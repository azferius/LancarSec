package proxy

import (
	"sync/atomic"
	"time"
)

const (
	ProxyVersion float64 = 1.5

	// OTPBucketLayout is the time layout for the rotation bucket the challenge
	// OTPs are derived from. It is formatted in UTC, so every instance behind a
	// load balancer agrees on the bucket regardless of local timezone, and it
	// is aligned to the wall-clock hour rather than to process start.
	OTPBucketLayout = "2006-01-02-15"
)

// OTP is one immutable, self-consistent set of per-hour challenge secrets.
//
// The three OTPs and the bucket string they were derived from belong together:
// a clearance token is Encrypt(ip+tlsFp+ua+Hour, Cookie|JS|Captcha). A reader
// that saw a new Hour next to an old Cookie — or vice versa — would derive a
// token neither the issuing nor the verifying side agrees with, and would
// re-challenge the visitor. Publishing all four fields as one value behind a
// single atomic pointer makes a torn read impossible: a request either sees the
// whole previous set or the whole next one.
//
// Never mutate an OTP after it has been passed to StoreOTP.
type OTP struct {
	// Hour is the aligned UTC bucket the set was derived from, in
	// OTPBucketLayout form. It is also the hour component of the access key.
	Hour string

	Cookie  string
	JS      string
	Captcha string
}

// otp holds the currently published set. It is never nil: init seeds it with a
// zero-valued set so LoadOTP is a single atomic load with no nil check on the
// request hot path.
var otp atomic.Pointer[OTP]

func init() {
	otp.Store(&OTP{})
}

// LoadOTP returns the currently published challenge secrets. The returned
// pointer is immutable and safe to read from any goroutine; it is one atomic
// load, which is what the request hot path can afford.
func LoadOTP() *OTP {
	return otp.Load()
}

// StoreOTP publishes a new set atomically. It copies its argument so the caller
// cannot mutate a published set.
func StoreOTP(next OTP) {
	published := next
	otp.Store(&published)
}

var (
	Fingerprint string

	WatchedDomain string
	TWidth        int
	THeight       int
	Cloudflare    bool
	MaxLogLength  int

	// CloudflareEnforceOrigin mirrors Proxy.CloudflareEnforceOrigin from the
	// published configuration, the same way Cloudflare above mirrors
	// Proxy.Cloudflare. Written only by core/config.publish. When it is true
	// AND Cloudflare is true, the request path rejects any socket peer that is
	// not inside the trusted-proxy set.
	//
	// It is false by default and stays false unless the operator opts in: see
	// the field comment in core/domains for why that default is not
	// negotiable.
	CloudflareEnforceOrigin bool

	// MaxBodySize mirrors Proxy.MaxBodySize - the process-wide default request
	// body ceiling in bytes, with -1 meaning unlimited. Per-domain limits are
	// resolved into domains.DomainSettings.MaxBodySize; this is the fallback
	// for a request that never resolves to a configured domain.
	MaxBodySize int64 = 10 << 20

	// CpuUsage/RamUsage moved to usage.go in wave 7. They were unsynchronised
	// string globals written by the TUI renderer and read from the cache
	// sweeper (under firewall.Mutex), the admin API handlers and the webhook
	// builder (under no lock at all) -- a data race. They are atomic pointers
	// now; readers call proxy.CpuUsage()/proxy.RamUsage().

	AdminSecret string
	APISecret   string

	CookieSecret string

	JSSecret string

	JSDifficulty = 5

	CaptchaSecret string

	// CookieOTP/JSOTP/CaptchaOTP/CurrHourStr used to be deprecated mirrors of
	// the LoadOTP fields; wave 7 deleted them. Readers call LoadOTP and take
	// the fields off the returned snapshot.

	IdleTimeout       = 5
	ReadTimeout       = 5
	WriteTimeout      = 7
	ReadHeaderTimeout = 5

	IdleTimeoutDuration       = time.Duration(IdleTimeout).Abs() * time.Second
	ReadTimeoutDuration       = time.Duration(ReadTimeout).Abs() * time.Second
	WriteTimeoutDuration      = time.Duration(WriteTimeout).Abs() * time.Second
	ReadHeaderTimeoutDuration = time.Duration(ReadHeaderTimeout).Abs() * time.Second

	RatelimitWindow = 120

	IPRatelimit            int
	FPRatelimit            int
	FailChallengeRatelimit int
	FailRequestRatelimit   int

	// The request-path clock moved to clock.go in wave 7. It is published by a
	// dedicated ticker goroutine rather than by the terminal renderer, so a
	// blocked stdout can no longer freeze the ratelimit window.

	// Initialised flips to true once the first prefill pass of
	// server.Monitor's evaluateRatelimit goroutine has published the window
	// buckets. It is written on the monitor goroutine and polled from main
	// before the listener starts, so it is an atomic.Bool (CONC-06) — a plain
	// bool shared across goroutines is a data race under the Go memory model.
	Initialised atomic.Bool
)
