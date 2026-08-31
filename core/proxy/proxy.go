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

	// DEPRECATED MIRRORS — see the CookieOTP/JSOTP/CaptchaOTP/CurrHourStr
	// declarations below. core/server/middleware.go still reads those four
	// package variables directly, and it is owned by another agent this wave,
	// so the mirrors are kept in step here until its four read sites move to
	// LoadOTP. Once they do, delete both these four lines and the variables.
	CurrHourStr = published.Hour
	CookieOTP = published.Cookie
	JSOTP = published.JS
	CaptchaOTP = published.Captcha
}

var (
	Fingerprint string

	WatchedDomain string
	TWidth        int
	THeight       int
	Cloudflare    bool
	MaxLogLength  int

	CpuUsage string
	RamUsage string

	AdminSecret string
	APISecret   string

	CookieSecret string

	JSSecret string

	JSDifficulty = 5

	CaptchaSecret string

	// CookieOTP, JSOTP, CaptchaOTP and CurrHourStr are DEPRECATED read-only
	// mirrors of the corresponding LoadOTP fields, written only by StoreOTP.
	//
	// They are not synchronised. A string is two machine words, so a reader
	// racing the hourly write can observe a pointer from one value next to a
	// length from another. Do not add new readers, and do not write them from
	// anywhere but StoreOTP. New code calls LoadOTP once and reads the fields
	// off the returned snapshot.
	CookieOTP   string
	JSOTP       string
	CaptchaOTP  string
	CurrHourStr string

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

	CurrHour               int
	LastSecondTime         time.Time
	LastSecondTimeFormated string
	LastSecondTimestamp    int
	Last10SecondTimestamp  int

	Initialised = false
)
