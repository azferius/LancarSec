package server

// Wave 3 tripwire tests for core/server/middleware.go.
//
// These tests pin the behaviour of Middleware AS IT EXISTS TODAY, bugs included.
// Anything marked "BUG (wave N flips this)" is a defect that is deliberately
// asserted as the current contract: when a later wave fixes it, the assertion
// below must visibly flip in the diff so a reviewer sees the behaviour change.
//
// Every helper and test in this file is prefixed mw/TestMiddleware to avoid
// symbol collisions with monitor_test.go, which lives in the same package.

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"image/png"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/azferius/lancarsec/core/domains"
	"github.com/azferius/lancarsec/core/firewall"
	"github.com/azferius/lancarsec/core/gofilter"
	"github.com/azferius/lancarsec/core/proxy"
	"github.com/azferius/lancarsec/core/transport"
	"github.com/azferius/lancarsec/core/trusted"
	"github.com/azferius/lancarsec/core/utils"
)

const (
	mwDomain      = "mw.test.local"
	mwIP          = "203.0.113.7"
	mwRemoteAddr  = mwIP + ":51000"
	mwUA          = "mw-test-agent"
	mwFP          = "0xdead,0xbeef,"
	mwHourStr     = "13"
	mwTimestamp   = 1700000000
	mwBackendBody = "MW-BACKEND-OK"

	mwCookieOTP   = "mw-cookie-otp"
	mwJSOTP       = "mw-js-otp"
	mwCaptchaOTP  = "mw-captcha-otp"
	mwAdminSecret = "mw-admin-secret"
	mwAPISecret   = "mw-api-secret"

	mwStage2Difficulty = 5
)

// mwAccessKey mirrors the accessKey built inside Middleware.
//
// FLIPPED BY WAVE 5: this used to be the bare concatenation
// ip + tlsFp + userAgent + proxy.CurrHourStr, with no delimiter, no domain and
// no suspicion level. It is now a length-prefixed encoding over
// (version, domain, ip, fingerprint, user agent, hour, suspicion level).
// mwLenPrefix keeps the helper an independent re-implementation of the
// encoding rather than a call into the production one, so a change to
// accessKeyFor has to be restated here to pass.
func mwLenPrefix(part string) string {
	return strconv.Itoa(len(part)) + ":" + part
}

func mwAccessKeyFor(domain, ip, fp, ua, hour string, susLv int) string {
	return mwLenPrefix("v1") +
		mwLenPrefix(domain) +
		mwLenPrefix(ip) +
		mwLenPrefix(fp) +
		mwLenPrefix(ua) +
		mwLenPrefix(hour) +
		mwLenPrefix(strconv.Itoa(susLv))
}

func mwAccessKey(susLv int) string {
	return mwAccessKeyFor(mwDomain, mwIP, mwFP, mwUA, mwHourStr, susLv)
}

func mwCookieToken() string  { return utils.Encrypt(mwAccessKey(1), mwCookieOTP) }
func mwJSToken() string      { return utils.Encrypt(mwAccessKey(2), mwJSOTP) }
func mwCaptchaToken() string { return utils.Encrypt(mwAccessKey(3), mwCaptchaOTP) }

// mwStage1Cookie / mwStage2Cookie / mwStage3Cookie are the cookie NAMES the
// proxy issues and now requires per stage. Wave 10 owns renaming the shared
// "__bProxy_v" token; until then these are the wire names.
const (
	mwStage1Cookie = "_1__bProxy_v"
	mwStage2Cookie = "_2__bProxy_v"
)

func mwStage3Cookie(ip string) string { return ip + "_3__bProxy_v" }

// ---------------------------------------------------------------------------
// harness
// ---------------------------------------------------------------------------

type mwEnv struct {
	tb      testing.TB
	backend *httptest.Server
	hits    atomic.Int64
}

// mwSaveGlobals snapshots every package-level global Middleware touches and
// restores it with t.Cleanup. This package is a swamp of mutable globals; no
// test may leak state into the next one.
func mwSaveGlobals(tb testing.TB) {
	tb.Helper()

	oldConfig := domains.Config
	oldDomainList := domains.Domains
	oldDomainsData := domains.DomainsData

	oldMutex := firewall.Mutex
	oldAccessIps := firewall.AccessIps
	oldAccessIpsCookie := firewall.AccessIpsCookie
	oldUnkFps := firewall.UnkFps
	oldWindowAccessIps := firewall.WindowAccessIps
	oldWindowAccessIpsCookie := firewall.WindowAccessIpsCookie
	oldWindowUnkFps := firewall.WindowUnkFps
	oldConnections := firewall.Connections
	oldKnown := firewall.KnownFingerprints
	oldBot := firewall.BotFingerprints
	oldForbidden := firewall.ForbiddenFingerprints

	oldCloudflare := proxy.Cloudflare
	oldAdminSecret := proxy.AdminSecret
	oldAPISecret := proxy.APISecret
	oldCookieOTP := proxy.CookieOTP
	oldJSOTP := proxy.JSOTP
	oldCaptchaOTP := proxy.CaptchaOTP
	oldIPRatelimit := proxy.IPRatelimit
	oldFPRatelimit := proxy.FPRatelimit
	oldFailChallenge := proxy.FailChallengeRatelimit
	oldCurrHour := proxy.CurrHour
	oldCurrHourStr := proxy.CurrHourStr
	oldLastSecondTimestamp := proxy.LastSecondTimestamp
	oldLast10 := proxy.Last10SecondTimestamp
	oldLastSecondFmt := proxy.LastSecondTimeFormated
	oldMaxLogLength := proxy.MaxLogLength
	oldFingerprint := proxy.Fingerprint
	oldWatched := proxy.WatchedDomain
	oldCPU := proxy.CpuUsage
	oldRAM := proxy.RamUsage

	oldMaxBody := MaxRequestBodyBytes.Load()

	tb.Cleanup(func() {
		MaxRequestBodyBytes.Store(oldMaxBody)

		domains.Config = oldConfig
		domains.Domains = oldDomainList
		domains.DomainsData = oldDomainsData
		domains.DomainsMap = sync.Map{}

		firewall.Mutex = oldMutex
		firewall.AccessIps = oldAccessIps
		firewall.AccessIpsCookie = oldAccessIpsCookie
		firewall.UnkFps = oldUnkFps
		firewall.WindowAccessIps = oldWindowAccessIps
		firewall.WindowAccessIpsCookie = oldWindowAccessIpsCookie
		firewall.WindowUnkFps = oldWindowUnkFps
		firewall.Connections = oldConnections
		firewall.KnownFingerprints = oldKnown
		firewall.BotFingerprints = oldBot
		firewall.ForbiddenFingerprints = oldForbidden
		firewall.CacheIps = sync.Map{}
		firewall.CacheImgs = sync.Map{}

		proxy.Cloudflare = oldCloudflare
		proxy.AdminSecret = oldAdminSecret
		proxy.APISecret = oldAPISecret
		proxy.CookieOTP = oldCookieOTP
		proxy.JSOTP = oldJSOTP
		proxy.CaptchaOTP = oldCaptchaOTP
		proxy.IPRatelimit = oldIPRatelimit
		proxy.FPRatelimit = oldFPRatelimit
		proxy.FailChallengeRatelimit = oldFailChallenge
		proxy.CurrHour = oldCurrHour
		proxy.CurrHourStr = oldCurrHourStr
		proxy.LastSecondTimestamp = oldLastSecondTimestamp
		proxy.Last10SecondTimestamp = oldLast10
		proxy.LastSecondTimeFormated = oldLastSecondFmt
		proxy.MaxLogLength = oldMaxLogLength
		proxy.Fingerprint = oldFingerprint
		proxy.WatchedDomain = oldWatched
		proxy.CpuUsage = oldCPU
		proxy.RamUsage = oldRAM

		// WAVE 6: the trusted-proxy set is process-global too. Default is
		// "trust nobody", which is what every test that does not explicitly
		// call mwTrustPeers expects.
		if _, err := trusted.Load(nil); err != nil {
			tb.Errorf("resetting the trusted set: %v", err)
		}

		transport.Reset()
	})
}

// mwTrustPeers publishes a trusted-proxy set for the duration of one test.
// Tests that want a forwarding header believed must call it; without it the
// default set is empty and realClientIP falls back to the socket peer.
// mwTrustPeers installs a trusted-proxy set for one test.
//
// trusted.Load always includes the 22 bundled Cloudflare prefixes on top of the
// operator entries passed here, so the count is checked as "bundled + extras"
// rather than "extras". Asserting the exact number is deliberate: it fails
// loudly if the bundled lists are ever refreshed, which is a moment somebody
// should look at these tests rather than have them silently keep passing
// against a different allowlist.
func mwTrustPeers(tb testing.TB, cidrs ...string) {
	tb.Helper()
	const bundled = 22
	n, err := trusted.Load(cidrs)
	if err != nil {
		tb.Fatalf("trusted.Load(%v): %v", cidrs, err)
	}
	if want := bundled + len(cidrs); n != want {
		tb.Fatalf("trusted.Load(%v) loaded %d prefixes, want %d (%d bundled + %d extras)",
			cidrs, n, want, bundled, len(cidrs))
	}
}

// mwNewEnv builds a fully initialised single-domain proxy state that mirrors
// what core/config.Load() produces, plus a stub backend.
func mwNewEnv(tb testing.TB) *mwEnv {
	tb.Helper()

	mwSaveGlobals(tb)

	env := &mwEnv{tb: tb}

	// --- firewall state (as evaluateRatelimit() would leave it) ---
	firewall.Mutex = &sync.RWMutex{}
	firewall.AccessIps = map[string]int{}
	firewall.AccessIpsCookie = map[string]int{}
	firewall.UnkFps = map[string]int{}
	firewall.WindowAccessIps = map[int]map[string]int{mwTimestamp: {}}
	firewall.WindowAccessIpsCookie = map[int]map[string]int{mwTimestamp: {}}
	firewall.WindowUnkFps = map[int]map[string]int{mwTimestamp: {}}
	firewall.Connections = map[string]string{mwRemoteAddr: mwFP}
	// Fresh (empty) fingerprint tables so tests control browser/bot/forbidden
	// classification instead of depending on the bundled upstream tables.
	firewall.KnownFingerprints = map[string]string{}
	firewall.BotFingerprints = map[string]string{}
	firewall.ForbiddenFingerprints = map[string]string{}
	firewall.CacheIps = sync.Map{}
	firewall.CacheImgs = sync.Map{}

	// --- proxy globals (as Monitor()/generateOTPSecrets() would leave them) ---
	proxy.Cloudflare = false
	proxy.AdminSecret = mwAdminSecret
	proxy.APISecret = mwAPISecret
	proxy.CookieOTP = mwCookieOTP
	proxy.JSOTP = mwJSOTP
	proxy.CaptchaOTP = mwCaptchaOTP
	proxy.IPRatelimit = 500
	proxy.FPRatelimit = 150
	proxy.FailChallengeRatelimit = 40
	proxy.CurrHour = 13
	proxy.CurrHourStr = mwHourStr
	proxy.LastSecondTimestamp = mwTimestamp + 3
	proxy.Last10SecondTimestamp = mwTimestamp
	proxy.LastSecondTimeFormated = "13:00:03"
	proxy.MaxLogLength = 20
	proxy.Fingerprint = "mw-proxy-fingerprint"
	proxy.WatchedDomain = mwDomain
	proxy.CpuUsage = ""
	proxy.RamUsage = ""

	// --- config ---
	domains.Config = &domains.Configuration{
		Proxy: domains.Proxy{
			Cloudflare:      false,
			AdminSecret:     mwAdminSecret,
			APISecret:       mwAPISecret,
			RatelimitWindow: 120,
			Ratelimits: map[string]int{
				"requests":           500,
				"unknownFingerprint": 150,
				"challengeFailures":  40,
				"noRequestsSent":     10,
			},
		},
		Domains: []domains.Domain{{Name: mwDomain}},
	}
	domains.Domains = []string{mwDomain}

	domains.DomainsMap = sync.Map{}
	domains.DomainsData = map[string]domains.DomainData{
		mwDomain: {
			Name:             mwDomain,
			Stage:            1,
			StageManuallySet: false,
			Stage2Difficulty: mwStage2Difficulty,
			RawAttack:        false,
			BypassAttack:     false,
			LastLogs:         []domains.DomainLog{},
			RequestLogger:    []domains.RequestLog{},
		},
	}

	env.backend = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		env.hits.Add(1)
		for _, h := range []string{"X-Real-Ip", "Proxy-Real-Ip", "Proxy-Tls-Fp", "Proxy-Tls-Name", "Cookie"} {
			w.Header().Set("X-Echo-"+h, strings.Join(r.Header.Values(h), "|"))
		}
		w.Header().Set("X-Echo-Path", r.URL.Path)
		w.Header().Set("X-Echo-Query", r.URL.RawQuery)
		_, _ = w.Write([]byte(mwBackendBody))
	}))
	tb.Cleanup(env.backend.Close)

	env.storeSettings(nil, nil)

	return env
}

// storeSettings (re)publishes DomainSettings for the test domain, mirroring
// config.buildDomain: reverse proxy to the stub backend through the production
// server.RoundTripper.
func (e *mwEnv) storeSettings(rules []domains.Rule, rt http.RoundTripper) {
	e.tb.Helper()

	target, err := url.Parse(e.backend.URL)
	if err != nil {
		e.tb.Fatalf("parse backend url: %v", err)
	}
	dProxy := httputil.NewSingleHostReverseProxy(target)
	if rt == nil {
		dProxy.Transport = &transport.RoundTripper{}
	} else {
		dProxy.Transport = rt
	}

	domains.DomainsMap.Store(mwDomain, domains.DomainSettings{
		Name:        mwDomain,
		CustomRules: rules,
		RawCustomRules: []domains.JsonRule{
			{Expression: "mw-test", Action: "0"},
		},
		DomainProxy: dProxy,
	})
}

// mwSetRules compiles expression/action pairs the way config.Load does.
func (e *mwEnv) mwSetRules(pairs ...[2]string) {
	e.tb.Helper()
	rules := make([]domains.Rule, 0, len(pairs))
	for _, p := range pairs {
		f, err := gofilter.NewFilter(p[0])
		if err != nil {
			e.tb.Fatalf("compile rule %q: %v", p[0], err)
		}
		rules = append(rules, domains.Rule{Filter: f, Action: p[1]})
	}
	e.storeSettings(rules, nil)
}

func (e *mwEnv) mwSetStage(stage int) {
	e.tb.Helper()
	firewall.Mutex.Lock()
	d := domains.DomainsData[mwDomain]
	d.Stage = stage
	domains.DomainsData[mwDomain] = d
	firewall.Mutex.Unlock()
}

func (e *mwEnv) mwDomainData() domains.DomainData {
	firewall.Mutex.RLock()
	defer firewall.Mutex.RUnlock()
	return domains.DomainsData[mwDomain]
}

func (e *mwEnv) mwBackendHits() int64 { return e.hits.Load() }

type mwReqOpt func(*http.Request)

func mwWithCookie(v string) mwReqOpt {
	return func(r *http.Request) { r.Header.Set("Cookie", v) }
}

func mwWithHeader(k, v string) mwReqOpt {
	return func(r *http.Request) { r.Header.Set(k, v) }
}

func mwWithHost(h string) mwReqOpt {
	return func(r *http.Request) { r.Host = h }
}

func mwWithRemoteAddr(a string) mwReqOpt {
	return func(r *http.Request) { r.RemoteAddr = a }
}

func mwWithMethod(m string) mwReqOpt {
	return func(r *http.Request) { r.Method = m }
}

// mwWithAPISecret authenticates a request to a gated /_bProxy/* endpoint.
// FLIPPED BY WAVE 5: /_bProxy/stats and /_bProxy/fingerprint used to be served
// to any client that cleared the challenge.
func mwWithAPISecret() mwReqOpt {
	return mwWithHeader("Proxy-Secret", mwAPISecret)
}

// mwAddDomain publishes a second fully configured domain pointing at the same
// stub backend, so cross-domain token reuse can be tested.
func (e *mwEnv) mwAddDomain(name string, stage int) {
	e.tb.Helper()

	firewall.Mutex.Lock()
	domains.DomainsData[name] = domains.DomainData{
		Name:             name,
		Stage:            stage,
		Stage2Difficulty: mwStage2Difficulty,
		LastLogs:         []domains.DomainLog{},
		RequestLogger:    []domains.RequestLog{},
	}
	firewall.Mutex.Unlock()
	domains.Domains = append(domains.Domains, name)

	target, err := url.Parse(e.backend.URL)
	if err != nil {
		e.tb.Fatalf("parse backend url: %v", err)
	}
	dProxy := httputil.NewSingleHostReverseProxy(target)
	dProxy.Transport = &transport.RoundTripper{}
	domains.DomainsMap.Store(name, domains.DomainSettings{
		Name:        name,
		DomainProxy: dProxy,
	})
}

// mwRequest builds a request that, by default, looks like a well-behaved
// client of the test domain.
func mwRequest(target string, opts ...mwReqOpt) *http.Request {
	req := httptest.NewRequest(http.MethodGet, target, nil)
	req.Host = mwDomain
	req.RemoteAddr = mwRemoteAddr
	req.Header.Set("User-Agent", mwUA)
	for _, o := range opts {
		o(req)
	}
	return req
}

func mwDo(req *http.Request) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	Middleware(rec, req)
	return rec
}

// mwRecover runs fn and returns the recovered panic value (nil if it did not
// panic).
func mwRecover(fn func()) (rec any) {
	defer func() { rec = recover() }()
	fn()
	return nil
}

func mwAssertStatus(t *testing.T, rec *httptest.ResponseRecorder, want int) {
	t.Helper()
	if got := rec.Result().StatusCode; got != want {
		t.Errorf("status = %d, want %d", got, want)
	}
}

func mwAssertBodyContains(t *testing.T, rec *httptest.ResponseRecorder, want string) {
	t.Helper()
	if body := rec.Body.String(); !strings.Contains(body, want) {
		t.Errorf("body does not contain %q\n--- body (first 400 bytes) ---\n%s", want, mwTrunc(body, 400))
	}
}

func mwAssertBodyNotContains(t *testing.T, rec *httptest.ResponseRecorder, notWant string) {
	t.Helper()
	if body := rec.Body.String(); strings.Contains(body, notWant) {
		t.Errorf("body unexpectedly contains %q", notWant)
	}
}

func mwTrunc(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + " ..."
}

// ---------------------------------------------------------------------------
// domain resolution
// ---------------------------------------------------------------------------

func TestMiddlewareUnknownDomain(t *testing.T) {
	env := mwNewEnv(t)

	cases := []struct {
		name string
		host string
	}{
		{name: "unconfigured host", host: "not-configured.example"},
		// BUG (a later wave may flip this): the Host header is matched verbatim,
		// so a client that sends an explicit port for a configured domain gets
		// "404 Not Found" instead of being served.
		{name: "configured host with explicit port", host: mwDomain + ":80"},
		{name: "empty host", host: ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			before := env.mwDomainData().TotalRequests
			rec := mwDo(mwRequest("/", mwWithHost(tc.host)))

			// BUG (wave 9 flips this): the "not found" path answers 200 OK with a
			// plain-text body that merely says 404. Wave 9 should send a real 404.
			mwAssertStatus(t, rec, http.StatusOK)
			mwAssertBodyContains(t, rec, "404 Not Found")

			if ct := rec.Result().Header.Get("Content-Type"); ct != "text/plain" {
				t.Errorf("Content-Type = %q, want text/plain", ct)
			}
			// The version header is set AFTER the domain lookup, so unknown-domain
			// responses carry no proxy header at all.
			if v := rec.Result().Header.Get("baloo-Proxy"); v != "" {
				t.Errorf("baloo-Proxy = %q, want empty on the unknown-domain path", v)
			}
			if env.mwBackendHits() != 0 {
				t.Errorf("backend was reached on the unknown-domain path")
			}
			if after := env.mwDomainData().TotalRequests; after != before {
				t.Errorf("TotalRequests changed (%d -> %d) for an unknown domain", before, after)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// counters / window maps
// ---------------------------------------------------------------------------

func TestMiddlewareCountersAndWindows(t *testing.T) {
	env := mwNewEnv(t)
	env.mwSetStage(1)

	// A stage-1 request with no cookie: counted as Total, challenged, not bypassed.
	rec := mwDo(mwRequest("/"))
	mwAssertStatus(t, rec, http.StatusFound)

	d := env.mwDomainData()
	if d.TotalRequests != 1 {
		t.Errorf("TotalRequests = %d, want 1", d.TotalRequests)
	}
	if d.BypassedRequests != 0 {
		t.Errorf("BypassedRequests = %d, want 0 (request was challenged)", d.BypassedRequests)
	}

	firewall.Mutex.RLock()
	accessCount := firewall.WindowAccessIps[mwTimestamp][mwIP]
	cookieCount := firewall.WindowAccessIpsCookie[mwTimestamp][mwIP]
	unkFpCount := firewall.WindowUnkFps[mwTimestamp][mwFP]
	firewall.Mutex.RUnlock()

	if accessCount != 1 {
		t.Errorf("WindowAccessIps[%d][%s] = %d, want 1", mwTimestamp, mwIP, accessCount)
	}
	if cookieCount != 1 {
		t.Errorf("WindowAccessIpsCookie[%d][%s] = %d, want 1", mwTimestamp, mwIP, cookieCount)
	}
	// The fingerprint is unknown (empty KnownFingerprints table), so the unknown
	// fingerprint window is incremented too.
	if unkFpCount != 1 {
		t.Errorf("WindowUnkFps[%d][%s] = %d, want 1", mwTimestamp, mwFP, unkFpCount)
	}

	// Now the same client with the correct cookie: bypassed, no challenge counter.
	// FLIPPED BY WAVE 5: the cookie must now be presented under the stage-1
	// NAME the proxy issued it as; the bare "__bProxy_v" name was only ever
	// accepted because the check was a substring test.
	rec = mwDo(mwRequest("/", mwWithCookie(mwStage1Cookie+"="+mwCookieToken())))
	mwAssertStatus(t, rec, http.StatusOK)
	mwAssertBodyContains(t, rec, mwBackendBody)

	d = env.mwDomainData()
	if d.TotalRequests != 2 {
		t.Errorf("TotalRequests = %d, want 2", d.TotalRequests)
	}
	if d.BypassedRequests != 1 {
		t.Errorf("BypassedRequests = %d, want 1", d.BypassedRequests)
	}
	if len(d.LastLogs) != 1 {
		t.Fatalf("LastLogs = %d entries, want 1 (only bypassed requests are logged)", len(d.LastLogs))
	}
	if d.LastLogs[0].IP != mwIP || d.LastLogs[0].TLSFP != mwFP || d.LastLogs[0].Useragent != mwUA {
		t.Errorf("log entry = %+v, want ip/fp/ua of the test client", d.LastLogs[0])
	}

	firewall.Mutex.RLock()
	cookieCount = firewall.WindowAccessIpsCookie[mwTimestamp][mwIP]
	firewall.Mutex.RUnlock()
	if cookieCount != 1 {
		t.Errorf("WindowAccessIpsCookie[%d][%s] = %d, want 1 (a passing request must not count as a challenge failure)", mwTimestamp, mwIP, cookieCount)
	}
}

// FLIPPED BY WAVE 6: a whitelisted (susLv 0) request never has a cookie to
// present, because the proxy never issued it one. It used to "fail" the cookie
// check anyway and increment the challenge-failure window that drives R1, so
// whitelisted traffic ratelimited ITSELF after FailChallengeRatelimit (40)
// requests per window - the exact opposite of what `action: 0` means. The
// increment is now gated on susLv > 0.
func TestMiddlewareWhitelistIsNotCountedAsAChallengeFailure(t *testing.T) {
	env := mwNewEnv(t)
	env.mwSetStage(0)

	// Enough requests to have blown past FailChallengeRatelimit under the old
	// behaviour. The point is not just that the counter is 0 but that a
	// whitelist cannot self-ratelimit however long it runs.
	const requests = 5
	for range requests {
		rec := mwDo(mwRequest("/"))
		mwAssertStatus(t, rec, http.StatusOK)
		mwAssertBodyContains(t, rec, mwBackendBody)
	}

	firewall.Mutex.RLock()
	cookieCount := firewall.WindowAccessIpsCookie[mwTimestamp][mwIP]
	accessCount := firewall.WindowAccessIps[mwTimestamp][mwIP]
	firewall.Mutex.RUnlock()

	if cookieCount != 0 {
		t.Errorf("WindowAccessIpsCookie[%d][%s] = %d, want 0 (a whitelisted request was never challenged, so it cannot have failed a challenge)", mwTimestamp, mwIP, cookieCount)
	}
	// The plain request counter is deliberately still incremented: it feeds
	// ip.http_requests and the attack detector, both of which want the real
	// volume. Only the CHECKS are skipped for whitelisted traffic.
	if accessCount != requests {
		t.Errorf("WindowAccessIps[%d][%s] = %d, want %d (whitelisted requests are still counted)", mwTimestamp, mwIP, accessCount, requests)
	}
	if env.mwBackendHits() != requests {
		t.Errorf("backend hits = %d, want %d", env.mwBackendHits(), requests)
	}
}

// The sliding-window maps are prefilled by the monitor goroutine
// (evaluateRatelimit). If that goroutine lags, Middleware writes to a nil map
// WHILE HOLDING firewall.Mutex and the deferred-free Unlock is skipped, so the
// panic wedges the mutex and freezes the whole proxy. The source comment at
// middleware.go:89 documents this; this test pins it.
//
// BUG (wave 7 flips this): the panic must become an ordinary lazily-created
// bucket (and the lock must be released with defer).
func TestMiddlewareMissingWindowBucketPanicsAndWedgesMutex(t *testing.T) {
	env := mwNewEnv(t)
	_ = env

	firewall.Mutex.Lock()
	delete(firewall.WindowAccessIps, mwTimestamp)
	firewall.Mutex.Unlock()

	rec := httptest.NewRecorder()
	got := mwRecover(func() { Middleware(rec, mwRequest("/")) })
	if got == nil {
		t.Fatal("expected a panic when the current window bucket is missing, got none")
	}
	if !strings.Contains(mwPanicString(got), "nil map") {
		t.Errorf("panic = %v, want an 'assignment to entry in nil map' panic", got)
	}

	// firewall.Mutex is still held by the panicked call. Replace it, otherwise
	// every later test in this package deadlocks. That this is necessary IS the
	// defect being pinned.
	if firewall.Mutex.TryLock() {
		firewall.Mutex.Unlock()
		t.Error("firewall.Mutex was released after the panic; the wedge documented in middleware.go:89 no longer reproduces")
	}
	firewall.Mutex = &sync.RWMutex{}
}

func mwPanicString(v any) string {
	if err, ok := v.(error); ok {
		return err.Error()
	}
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

// A domain present in DomainsData but absent from DomainsMap used to make the
// unchecked type assertion in middleware.go panic on a nil interface, and it
// was reachable whenever a reload populated one map before the other.
//
// FLIPPED BY WAVE 4: the assertion is comma-ok and the skew is answered with a
// real 404 instead of taking the handler down. Wave 4 also removed the way to
// reach the skew in the first place (the config pipeline publishes both tables
// inside one firewall.Mutex section, and converges them to config.json), but
// the guard stays: DomainsMap is a sync.Map written outside that lock, and a
// nil-interface panic is not an acceptable answer to a lookup miss that already
// has an "unknown domain" response.
//
// Note the status code: this path sends a real 404, while the sibling
// unknown-domain path a few lines above it still answers 200 with a body that
// merely says "404 Not Found". Wave 9 owns making that one honest too.
func TestMiddlewareDomainsMapMissingReturns404(t *testing.T) {
	env := mwNewEnv(t)

	domains.DomainsMap.Delete(mwDomain)

	rec := httptest.NewRecorder()
	if got := mwRecover(func() { Middleware(rec, mwRequest("/")) }); got != nil {
		t.Fatalf("Middleware panicked on a DomainsData/DomainsMap skew: %v", got)
	}

	mwAssertStatus(t, rec, http.StatusNotFound)
	mwAssertBodyContains(t, rec, "404 Not Found")
	if ct := rec.Result().Header.Get("Content-Type"); ct != "text/plain" {
		t.Errorf("Content-Type = %q, want text/plain", ct)
	}
	if env.mwBackendHits() != 0 {
		t.Errorf("backend was reached on the skewed-domain path")
	}
	// The guard sits AFTER the counter bump and the version header, unlike the
	// unknown-domain check at the top of Middleware. Pinning that here so a
	// later wave that hoists the settings lookup has to say so.
	if v := rec.Result().Header.Get("baloo-Proxy"); v != "1.5" {
		t.Errorf("baloo-Proxy = %q, want 1.5", v)
	}
	if got := env.mwDomainData().TotalRequests; got != 1 {
		t.Errorf("TotalRequests = %d, want 1", got)
	}
	if !firewall.Mutex.TryLock() {
		t.Error("firewall.Mutex was left locked by the skewed-domain path")
	} else {
		firewall.Mutex.Unlock()
	}
}

// ---------------------------------------------------------------------------
// ratelimits R1 / R2 / R3
// ---------------------------------------------------------------------------

func TestMiddlewareRatelimits(t *testing.T) {
	cases := []struct {
		name     string
		setup    func(t *testing.T, env *mwEnv)
		wantBody string
	}{
		{
			name: "R1 repeated challenge failures",
			setup: func(t *testing.T, env *mwEnv) {
				firewall.AccessIpsCookie[mwIP] = proxy.FailChallengeRatelimit + 1
			},
			wantBody: "You have been ratelimited. (R1)",
		},
		{
			name: "R2 request flood from one ip",
			setup: func(t *testing.T, env *mwEnv) {
				firewall.AccessIps[mwIP] = proxy.IPRatelimit + 1
			},
			wantBody: "You have been ratelimited. (R2)",
		},
		{
			name: "R3 unknown fingerprint flood",
			setup: func(t *testing.T, env *mwEnv) {
				firewall.UnkFps[mwFP] = proxy.FPRatelimit + 1
			},
			wantBody: "You have been ratelimited. (R3)",
		},
		{
			name: "R1 wins over R2 and R3",
			setup: func(t *testing.T, env *mwEnv) {
				firewall.AccessIpsCookie[mwIP] = proxy.FailChallengeRatelimit + 1
				firewall.AccessIps[mwIP] = proxy.IPRatelimit + 1
				firewall.UnkFps[mwFP] = proxy.FPRatelimit + 1
			},
			wantBody: "You have been ratelimited. (R1)",
		},
		{
			name: "R2 wins over R3",
			setup: func(t *testing.T, env *mwEnv) {
				firewall.AccessIps[mwIP] = proxy.IPRatelimit + 1
				firewall.UnkFps[mwFP] = proxy.FPRatelimit + 1
			},
			wantBody: "You have been ratelimited. (R2)",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := mwNewEnv(t)
			tc.setup(t, env)

			// Stage 1 is the default, so if a ratelimit branch ever failed to
			// return the request would fall through into the stage-1 challenge
			// and every assertion below would see the difference.
			rec := mwDo(mwRequest("/"))

			// BUG (wave 9 flips this): every ratelimit answers 200 OK, not 429.
			mwAssertStatus(t, rec, http.StatusOK)
			mwAssertBodyContains(t, rec, tc.wantBody)
			mwAssertBodyContains(t, rec, "Blocked by BalooProxy.")
			if ct := rec.Result().Header.Get("Content-Type"); ct != "text/plain" {
				t.Errorf("Content-Type = %q, want text/plain", ct)
			}
			if v := rec.Result().Header.Get("baloo-Proxy"); v != "1.5" {
				t.Errorf("baloo-Proxy = %q, want 1.5", v)
			}
			if env.mwBackendHits() != 0 {
				t.Error("backend was reached despite the ratelimit")
			}
			// Ratelimited requests still count towards TotalRequests.
			if got := env.mwDomainData().TotalRequests; got != 1 {
				t.Errorf("TotalRequests = %d, want 1", got)
			}

			// --- the ratelimit is an EARLY EXIT, not a prefix ---------------
			//
			// Everything below fails if the `return` after any of the three
			// SendResponse ratelimit calls is dropped: the response body would
			// gain the challenge/backend payload, a redirect Location and
			// Set-Cookie would appear, a lower-ranked limiter would append its
			// own message, and the challenge-failure window would be bumped.
			// That is the single most likely slip when these checks are moved
			// into a helper, and in production it means the proxy prints "you
			// have been ratelimited" and then serves the flood anyway.
			wantExact := "Blocked by BalooProxy.\n" + tc.wantBody
			if got := rec.Body.String(); got != wantExact {
				t.Errorf("body = %q, want exactly %q (the ratelimit branch must return immediately)", mwTrunc(got, 400), wantExact)
			}
			if loc := rec.Result().Header.Get("Location"); loc != "" {
				t.Errorf("Location = %q, want empty: a ratelimited request must not reach the stage-1 redirect", loc)
			}
			if sc := rec.Result().Header.Get("Set-Cookie"); sc != "" {
				t.Errorf("Set-Cookie = %q, want empty: a ratelimited request must not be handed a challenge token", sc)
			}

			firewall.Mutex.RLock()
			cookieWindow := firewall.WindowAccessIpsCookie[mwTimestamp][mwIP]
			firewall.Mutex.RUnlock()
			if cookieWindow != 0 {
				t.Errorf("WindowAccessIpsCookie[%d][%s] = %d, want 0: a ratelimited request must return before the cookie check", mwTimestamp, mwIP, cookieWindow)
			}
			if d := env.mwDomainData(); d.BypassedRequests != 0 || len(d.LastLogs) != 0 {
				t.Errorf("BypassedRequests = %d, LastLogs = %d entries; want 0/0 for a ratelimited request", d.BypassedRequests, len(d.LastLogs))
			}
		})
	}
}

// The thresholds are strict ">" comparisons: hitting the limit exactly is
// allowed, one over is blocked.
//
// FLIPPED BY WAVE 6 (setup, not expectations): this used to run at stage 0 and
// still expect the ratelimits to fire, which is precisely the defect wave 6
// removes - a whitelisted request is no longer subject to R1/R2/R3. The
// boundary behaviour itself is unchanged, so the cases below now run at stage 1
// with a valid clearance cookie: an allowed request still reaches the backend,
// a blocked one still says so.
func TestMiddlewareRatelimitBoundaries(t *testing.T) {
	cases := []struct {
		name    string
		set     func()
		blocked bool
	}{
		{name: "ip count equals limit", set: func() { firewall.AccessIps[mwIP] = 500 }, blocked: false},
		{name: "ip count one over limit", set: func() { firewall.AccessIps[mwIP] = 501 }, blocked: true},
		{name: "cookie count equals limit", set: func() { firewall.AccessIpsCookie[mwIP] = 40 }, blocked: false},
		{name: "cookie count one over limit", set: func() { firewall.AccessIpsCookie[mwIP] = 41 }, blocked: true},
		{name: "unknown fp equals limit", set: func() { firewall.UnkFps[mwFP] = 150 }, blocked: false},
		{name: "unknown fp one over limit", set: func() { firewall.UnkFps[mwFP] = 151 }, blocked: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := mwNewEnv(t)
			env.mwSetStage(1)
			tc.set()

			rec := mwDo(mwRequest("/", mwWithCookie(mwStage1Cookie+"="+mwCookieToken())))
			blocked := strings.Contains(rec.Body.String(), "ratelimited")
			if blocked != tc.blocked {
				t.Errorf("blocked = %v, want %v (body: %s)", blocked, tc.blocked, mwTrunc(rec.Body.String(), 120))
			}
			if !tc.blocked && env.mwBackendHits() != 1 {
				t.Errorf("backend hits = %d, want 1", env.mwBackendHits())
			}
		})

		// FLIPPED BY WAVE 6: the same over-limit state, whitelisted. Before
		// wave 6 the three ratelimits ran before rule evaluation, so an
		// operator's `action: 0` could not whitelist anything - the request had
		// already been counted and could already have been refused. Every case
		// above that blocks must now pass when susLv is 0.
		t.Run(tc.name+" is not enforced against a whitelisted request", func(t *testing.T) {
			env := mwNewEnv(t)
			env.mwSetStage(0)
			tc.set()

			rec := mwDo(mwRequest("/"))
			if strings.Contains(rec.Body.String(), "ratelimited") {
				t.Errorf("a whitelisted request was ratelimited: %s", mwTrunc(rec.Body.String(), 120))
			}
			if env.mwBackendHits() != 1 {
				t.Errorf("backend hits = %d, want 1", env.mwBackendHits())
			}
		})
	}
}

// The whitelist is reached through a RULE, not only through `stage 0`, and the
// rule is what the reorder exists for: an `action: 0` rule now runs before the
// ratelimits instead of after them. This is the operator-facing shape of the
// change - "allow my health check through however loud the flood is".
func TestMiddlewareWhitelistRuleBeatsTheRatelimits(t *testing.T) {
	env := mwNewEnv(t)
	env.mwSetStage(1)
	env.mwSetRules([2]string{`http.path eq "/health"`, "0"})

	// Every one of the three limiters is over its threshold for this client.
	firewall.AccessIps[mwIP] = proxy.IPRatelimit + 1000
	firewall.AccessIpsCookie[mwIP] = proxy.FailChallengeRatelimit + 1000
	firewall.UnkFps[mwFP] = proxy.FPRatelimit + 1000

	rec := mwDo(mwRequest("/health"))
	mwAssertStatus(t, rec, http.StatusOK)
	mwAssertBodyContains(t, rec, mwBackendBody)
	if env.mwBackendHits() != 1 {
		t.Fatalf("backend hits = %d, want 1: the whitelist rule did not beat the ratelimits", env.mwBackendHits())
	}

	// ...and a request the rule does NOT match is still refused, so the
	// whitelist is scoped to what it names rather than disabling the limiter.
	rec = mwDo(mwRequest("/not-health"))
	mwAssertBodyContains(t, rec, "You have been ratelimited. (R1)")
	if env.mwBackendHits() != 1 {
		t.Errorf("backend hits = %d, want 1: a non-whitelisted request got through", env.mwBackendHits())
	}
}

// R3 and the unknown-fingerprint window are skipped entirely when the TLS
// fingerprint maps to a known browser.
func TestMiddlewareKnownBrowserSkipsFingerprintRatelimit(t *testing.T) {
	env := mwNewEnv(t)
	env.mwSetStage(0)
	firewall.KnownFingerprints[mwFP] = "Chromium"
	firewall.UnkFps[mwFP] = proxy.FPRatelimit + 1000

	rec := mwDo(mwRequest("/"))
	mwAssertBodyContains(t, rec, mwBackendBody)
	mwAssertBodyNotContains(t, rec, "(R3)")

	firewall.Mutex.RLock()
	unk := firewall.WindowUnkFps[mwTimestamp][mwFP]
	firewall.Mutex.RUnlock()
	if unk != 0 {
		t.Errorf("WindowUnkFps[%d][%s] = %d, want 0 for a known browser", mwTimestamp, mwFP, unk)
	}
	if got := rec.Result().Header.Get("X-Echo-Proxy-Tls-Name"); got != "Chromium" {
		t.Errorf("proxy-tls-name forwarded = %q, want Chromium", got)
	}
}

// ---------------------------------------------------------------------------
// forbidden fingerprints
// ---------------------------------------------------------------------------

func TestMiddlewareForbiddenFingerprint(t *testing.T) {
	env := mwNewEnv(t)
	env.mwSetStage(0)
	firewall.ForbiddenFingerprints[mwFP] = "Http-Flood (1)"

	rec := mwDo(mwRequest("/"))

	// BUG (wave 9 flips this): a hard block answers 200 OK, not 403.
	mwAssertStatus(t, rec, http.StatusOK)
	mwAssertBodyContains(t, rec, "Your browser Http-Flood (1) is not allowed.")
	if env.mwBackendHits() != 0 {
		t.Error("backend was reached despite a forbidden fingerprint")
	}

	// FLIPPED BY WAVE 6: this request is whitelisted (stage 0), so the R3 block
	// - the threshold check AND the unknown-fingerprint window write that sits
	// with it - is skipped entirely. It used to be incremented for a
	// fingerprint the very next check rejects.
	//
	// The window write matters more than it looks: WindowUnkFps is keyed on the
	// TLS fingerprint, which is shared by every client running the same browser
	// build. Counting whitelisted traffic there let an operator's own
	// high-volume, single-fingerprint monitoring drive R3 against strangers.
	firewall.Mutex.RLock()
	unk := firewall.WindowUnkFps[mwTimestamp][mwFP]
	firewall.Mutex.RUnlock()
	if unk != 0 {
		t.Errorf("WindowUnkFps[%d][%s] = %d, want 0 for a whitelisted request", mwTimestamp, mwFP, unk)
	}
}

// The forbidden-fingerprint block is deliberately NOT gated on susLv: it is an
// explicit operator deny-list of attack tooling, and a whitelist rule that
// happens to cover the request must not unblock it. Deny beats allow.
func TestMiddlewareForbiddenFingerprintIgnoresTheWhitelist(t *testing.T) {
	for _, stage := range []int{0, 1} {
		t.Run("stage "+strconv.Itoa(stage), func(t *testing.T) {
			env := mwNewEnv(t)
			env.mwSetStage(stage)
			env.mwSetRules([2]string{`http.path eq "/"`, "0"})
			firewall.ForbiddenFingerprints[mwFP] = "Http-Flood (1)"

			rec := mwDo(mwRequest("/"))
			mwAssertBodyContains(t, rec, "Your browser Http-Flood (1) is not allowed.")
			if env.mwBackendHits() != 0 {
				t.Error("a whitelisted request with a forbidden fingerprint reached the backend")
			}
		})
	}
}

// At a stage that actually challenges, the unknown-fingerprint window is still
// written before the forbidden check - the sibling half of the flip above, so
// that "wave 6 skipped it" cannot be confused with "wave 6 deleted it".
func TestMiddlewareUnknownFingerprintWindowIsCountedWhenChallenged(t *testing.T) {
	env := mwNewEnv(t)
	env.mwSetStage(1)
	firewall.ForbiddenFingerprints[mwFP] = "Http-Flood (1)"

	mwDo(mwRequest("/"))

	firewall.Mutex.RLock()
	unk := firewall.WindowUnkFps[mwTimestamp][mwFP]
	firewall.Mutex.RUnlock()
	if unk != 1 {
		t.Errorf("WindowUnkFps[%d][%s] = %d, want 1", mwTimestamp, mwFP, unk)
	}
}

// KnownFingerprints and ForbiddenFingerprints are two independent JSON tables
// in global/fingerprints. A fingerprint can be in BOTH - which is exactly what
// a browser-impersonating flood tool produces - and the forbidden block must
// still fire. Skipping the forbidden lookup for recognised browsers looks like
// a harmless optimisation and would silently unblock every impersonator.
func TestMiddlewareForbiddenFingerprintBlocksRecognisedBrowsers(t *testing.T) {
	cases := []struct {
		name    string
		known   string
		botFp   string
		wantTls string
	}{
		{name: "known browser", known: "Chromium", wantTls: "Chromium"},
		{name: "known bot", botFp: "-crawler", wantTls: "-crawler"},
		{name: "known browser and bot", known: "Chromium", botFp: "-crawler", wantTls: "Chromium-crawler"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := mwNewEnv(t)
			env.mwSetStage(0) // whitelisted: only the forbidden table can block
			if tc.known != "" {
				firewall.KnownFingerprints[mwFP] = tc.known
			}
			if tc.botFp != "" {
				firewall.BotFingerprints[mwFP] = tc.botFp
			}
			firewall.ForbiddenFingerprints[mwFP] = "Http-Flood (1)"

			rec := mwDo(mwRequest("/"))

			mwAssertStatus(t, rec, http.StatusOK)
			mwAssertBodyContains(t, rec, "Your browser Http-Flood (1) is not allowed.")
			mwAssertBodyNotContains(t, rec, mwBackendBody)
			if env.mwBackendHits() != 0 {
				t.Errorf("backend hits = %d, want 0: a forbidden fingerprint is blocked even when it is also a known browser (%q)", env.mwBackendHits(), tc.wantTls)
			}
		})
	}
}

// The forbidden-fingerprint block outranks every challenge stage, including a
// client holding a valid cookie.
func TestMiddlewareForbiddenFingerprintBeatsValidCookie(t *testing.T) {
	env := mwNewEnv(t)
	env.mwSetStage(1)
	firewall.ForbiddenFingerprints[mwFP] = "Http-Flood (1)"

	rec := mwDo(mwRequest("/", mwWithCookie(mwStage1Cookie+"="+mwCookieToken())))
	mwAssertBodyContains(t, rec, "is not allowed.")
	if env.mwBackendHits() != 0 {
		t.Error("backend was reached despite a forbidden fingerprint")
	}
}

// ---------------------------------------------------------------------------
// challenge stages
// ---------------------------------------------------------------------------

func TestMiddlewareStage1Challenge(t *testing.T) {
	env := mwNewEnv(t)
	env.mwSetStage(1)

	rec := mwDo(mwRequest("/some/path?a=b"))

	mwAssertStatus(t, rec, http.StatusFound)
	if got, want := rec.Result().Header.Get("Location"), "/some/path?a=b"; got != want {
		t.Errorf("Location = %q, want %q", got, want)
	}
	wantCookie := mwStage1Cookie + "=" + mwCookieToken() + "; SameSite=Lax; path=/; Secure; HttpOnly"
	if got := rec.Result().Header.Get("Set-Cookie"); got != wantCookie {
		t.Errorf("Set-Cookie = %q, want %q", got, wantCookie)
	}
	// FLIPPED BY WAVE 5: the stage-1 cookie is now HttpOnly, so script on (or
	// injected into) the backend cannot read the proxy's clearance token.
	// Stages 2 and 3 are written by the challenge page's own JavaScript and
	// cannot carry the flag - see the comment on the stage-1 Set-Cookie in
	// middleware.go before "fixing" them to match.
	if !strings.Contains(strings.ToLower(rec.Result().Header.Get("Set-Cookie")), "httponly") {
		t.Error("Set-Cookie is not HttpOnly")
	}
	if env.mwBackendHits() != 0 {
		t.Error("backend was reached during a stage-1 challenge")
	}
}

func TestMiddlewareStage1CookieAcceptance(t *testing.T) {
	token := mwCookieToken()

	cases := []struct {
		name   string
		cookie string
		pass   bool
	}{
		{name: "stage1 cookie name as set by the proxy", cookie: mwStage1Cookie + "=" + token, pass: true},
		{name: "cookie among others", cookie: "a=1; " + mwStage1Cookie + "=" + token + "; b=2", pass: true},
		{name: "cookie among others, spaceless separator", cookie: "a=1;" + mwStage1Cookie + "=" + token + ";b=2", pass: true},
		{name: "wrong token", cookie: mwStage1Cookie + "=deadbeef", pass: false},
		{name: "no cookie", cookie: "", pass: false},

		// FLIPPED BY WAVE 5: the check is a lookup of the cookie NAMED for the
		// stage being enforced, compared in constant time over its whole value.
		// It used to be strings.Contains over the raw Cookie header, so the
		// three cases below all passed: the token embedded in an unrelated
		// cookie's value, the token under an attacker-chosen name, and the
		// token under the bare "__bProxy_v" name that the proxy never issues.
		{name: "bare __bProxy_v name the proxy never sets", cookie: "__bProxy_v=" + token, pass: false},
		{name: "token smuggled inside an unrelated cookie value", cookie: "junk=xx" + mwStage1Cookie + "=" + token, pass: false},
		{name: "token in a cookie name suffix", cookie: "evil" + mwStage1Cookie + "=" + token + "=1", pass: false},
		// A stage-2 or stage-3 cookie is not a stage-1 cookie, even carrying
		// the right bytes: the name identifies which challenge was solved.
		{name: "correct token under the stage-2 name", cookie: mwStage2Cookie + "=" + token, pass: false},
		{name: "correct token under the stage-3 name", cookie: mwStage3Cookie(mwIP) + "=" + token, pass: false},

		// --- the WHOLE token is compared, not a prefix of it ---------------
		//
		// The clearance token is 256 bits of blake3 rendered as 64 hex chars.
		// Comparing a truncated or otherwise derived prefix instead of the
		// full value - an easy slip when the check moves into a helper - would
		// cut the guessable material down to whatever is left. These cases
		// fail the moment any proper prefix of the token is accepted.
		{name: "first 8 chars of the token only", cookie: mwStage1Cookie + "=" + token[:8], pass: false},
		{name: "first 8 chars of the token then filler", cookie: mwStage1Cookie + "=" + token[:8] + strings.Repeat("z", len(token)-8), pass: false},
		{name: "first half of the token only", cookie: mwStage1Cookie + "=" + token[:len(token)/2], pass: false},
		{name: "token missing its last character", cookie: mwStage1Cookie + "=" + token[:len(token)-1], pass: false},
		{name: "token with one extra character", cookie: mwStage1Cookie + "=" + token + "z", pass: false},

		// --- the cookie NAME is part of the compared string ----------------
		//
		// A half-applied rename that loosens only the acceptance side (say
		// "_1__bProxy_v=" -> "bProxy_v=") is invisible unless a cookie carrying
		// the correct token under a shorter name is rejected.
		{name: "cookie name without the leading double underscore", cookie: "_1bProxy_v=" + token, pass: false},
		{name: "cookie name with a single leading underscore", cookie: "_1_bProxy_v=" + token, pass: false},
		{name: "cookie name without the trailing _v", cookie: "_1__bProxy=" + token, pass: false},
		{name: "cookie name without the stage prefix", cookie: "1__bProxy_v=" + token, pass: false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := mwNewEnv(t)
			env.mwSetStage(1)

			opts := []mwReqOpt{}
			if tc.cookie != "" {
				opts = append(opts, mwWithCookie(tc.cookie))
			}
			rec := mwDo(mwRequest("/", opts...))

			if tc.pass {
				mwAssertStatus(t, rec, http.StatusOK)
				mwAssertBodyContains(t, rec, mwBackendBody)
				if env.mwBackendHits() != 1 {
					t.Errorf("backend hits = %d, want 1", env.mwBackendHits())
				}
			} else {
				mwAssertStatus(t, rec, http.StatusFound)
				if env.mwBackendHits() != 0 {
					t.Errorf("backend hits = %d, want 0", env.mwBackendHits())
				}
			}
		})
	}
}

func TestMiddlewareStage2Challenge(t *testing.T) {
	env := mwNewEnv(t)
	env.mwSetStage(2)

	token := mwJSToken()
	publicSalt := token[:len(token)-mwStage2Difficulty]
	hashed := utils.EncryptSha(token, "")

	rec := mwDo(mwRequest("/"))

	mwAssertStatus(t, rec, http.StatusOK)
	if ct := rec.Result().Header.Get("Content-Type"); ct != "text/html" {
		t.Errorf("Content-Type = %q, want text/html", ct)
	}
	if cc := rec.Result().Header.Get("Cache-Control"); cc != "no-store, no-cache, must-revalidate, max-age=0" {
		t.Errorf("Cache-Control = %q", cc)
	}
	mwAssertBodyContains(t, rec, publicSalt)
	mwAssertBodyContains(t, rec, hashed)
	mwAssertBodyContains(t, rec, `document.cookie="_2__bProxy_v=`+publicSalt+`"`)
	mwAssertBodyContains(t, rec, `new BalooPow("`+publicSalt+`",`+strconv.Itoa(mwStage2Difficulty)+`,"`+hashed+`",!1)`)
	// Upstream loads the proof-of-work library from a third-party CDN.
	mwAssertBodyContains(t, rec, "https://cdn.jsdelivr.net/gh/41Baloo/balooPow@main/balooPow.min.js")
	if env.mwBackendHits() != 0 {
		t.Error("backend was reached during a stage-2 challenge")
	}

	// The hashed challenge answer is memoised under the encrypted token itself.
	cached, ok := firewall.CacheIps.Load(token)
	if !ok {
		t.Fatalf("CacheIps has no entry for the stage-2 token")
	}
	if cached.(string) != hashed {
		t.Errorf("cached hash = %q, want %q", cached, hashed)
	}

	// A second request takes the cache-hit branch, which reloads the hashed
	// answer from CacheIps rather than recomputing it. The page must be
	// byte-identical, otherwise the client's in-flight proof of work is void.
	second := mwDo(mwRequest("/"))
	if second.Body.String() != rec.Body.String() {
		t.Error("the cached second challenge page differs from the first")
	}
	mwAssertBodyContains(t, second, hashed)
}

func TestMiddlewareStage2SolvedCookiePasses(t *testing.T) {
	env := mwNewEnv(t)
	env.mwSetStage(2)

	rec := mwDo(mwRequest("/", mwWithCookie("_2__bProxy_v="+mwJSToken())))
	mwAssertStatus(t, rec, http.StatusOK)
	mwAssertBodyContains(t, rec, mwBackendBody)
	if env.mwBackendHits() != 1 {
		t.Errorf("backend hits = %d, want 1", env.mwBackendHits())
	}
}

func TestMiddlewareStage3CaptchaFromCache(t *testing.T) {
	env := mwNewEnv(t)
	env.mwSetStage(3)

	token := mwCaptchaToken()
	secretPart := token[:6]
	publicPart := token[6:]
	// Pre-seed the image cache so the response is fully deterministic (captcha
	// generation itself uses math/rand).
	firewall.CacheImgs.Store(secretPart, [2]string{"CAPTCHA_PNG_DATA", "MASK_PNG_DATA"})

	rec := mwDo(mwRequest("/"))

	mwAssertStatus(t, rec, http.StatusOK)
	if ct := rec.Result().Header.Get("Content-Type"); ct != "text/html" {
		t.Errorf("Content-Type = %q, want text/html", ct)
	}
	mwAssertBodyContains(t, rec, `captcha_image.src="data:image/png;base64,CAPTCHA_PNG_DATA"`)
	mwAssertBodyContains(t, rec, `mask_image.src="data:image/png;base64,MASK_PNG_DATA"`)
	mwAssertBodyContains(t, rec, `document.cookie="`+mwIP+`_3__bProxy_v="+a+"`+publicPart+`; SameSite=Lax; path=/; Secure"`)
	mwAssertBodyContains(t, rec, `fetch("https://"+location.hostname+"/_bProxy/verified")`)
	// BUG: the captcha answer is checked against the secret half of the token,
	// which is handed to the client inside the image; the public half is echoed
	// into the page. Pinned only as "this is the shape of the page today".
	mwAssertBodyContains(t, rec, "Drag the <b>slider</b>")
	if env.mwBackendHits() != 0 {
		t.Error("backend was reached during a stage-3 challenge")
	}
}

func TestMiddlewareStage3CaptchaGenerationCaches(t *testing.T) {
	env := mwNewEnv(t)
	env.mwSetStage(3)

	token := mwCaptchaToken()
	secretPart := token[:6]

	rec := mwDo(mwRequest("/"))
	mwAssertStatus(t, rec, http.StatusOK)
	mwAssertBodyContains(t, rec, `captcha_image.src="data:image/png;base64,iVBOR`)

	got, ok := firewall.CacheImgs.Load(secretPart)
	if !ok {
		t.Fatalf("CacheImgs has no entry for secret part %q after generating a captcha", secretPart)
	}
	pair, ok := got.([2]string)
	if !ok {
		t.Fatalf("CacheImgs entry has type %T, want [2]string", got)
	}
	if pair[0] == "" || pair[1] == "" {
		t.Errorf("cached captcha/mask pair is incomplete: %q / %q", mwTrunc(pair[0], 16), mwTrunc(pair[1], 16))
	}
	if env.mwBackendHits() != 0 {
		t.Error("backend was reached during a stage-3 challenge")
	}
}

// mwStage3InjectToken pre-seeds the encryption cache with a chosen stage-3
// token so the captcha's secret/public split is controlled by the test instead
// of by blake3. Middleware takes the cache-hit branch and uses this value
// verbatim as `encryptedIP`.
func mwStage3InjectToken(token string) {
	// FLIPPED BY WAVE 5: the cache key is the access key itself, which now
	// carries the suspicion level, instead of accessKey+StageToString(susLv).
	firewall.CacheIps.Store(mwAccessKey(3), token)
}

// mwCountOpaqueGreen counts the pixels of a base64 PNG that are exactly the
// colour utils.AddLabel is given for the captcha ANSWER: RGBA{61,140,64,255}.
// The other two labels on the captcha are drawn at alpha 20 and alpha 100, and
// neither WarpImg nor DrawTriangle invents a colour - they only copy, clear or
// displace existing pixels - so this colour appears if and only if the answer
// label was drawn with non-blank glyphs.
func mwCountOpaqueGreen(t *testing.T, b64 string) int {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		t.Fatalf("decode base64 png: %v", err)
	}
	img, err := png.Decode(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("decode png: %v", err)
	}
	n := 0
	b := img.Bounds()
	for y := b.Min.Y; y < b.Max.Y; y++ {
		for x := b.Min.X; x < b.Max.X; x++ {
			r, g, bl, a := img.At(x, y).RGBA()
			if r>>8 == 61 && g>>8 == 140 && bl>>8 == 64 && a>>8 == 255 {
				n++
			}
		}
	}
	return n
}

// mwExtractPNG pulls the base64 payload the captcha page assigns to
// captcha_image.src / mask_image.src.
func mwExtractPNG(t *testing.T, body, jsVar string) string {
	t.Helper()
	marker := jsVar + `.src="data:image/png;base64,`
	i := strings.Index(body, marker)
	if i < 0 {
		t.Fatalf("captcha page has no %s payload", jsVar)
	}
	rest := body[i+len(marker):]
	j := strings.Index(rest, `"`)
	if j < 0 {
		t.Fatalf("unterminated %s payload", jsVar)
	}
	return rest[:j]
}

// The stage-3 answer the proxy checks is encryptedIP[:6]; the string drawn in
// solid green is what the user is told to type. Those must be the same string.
// Swapping in any other same-typed piece of the token - publicPart[:6], say -
// makes every stage-3 captcha unsolvable, which hard-blocks all human traffic
// the moment the proxy escalates to stage 3.
//
// The captcha is generated with the global math/rand, so positions, warp and
// triangles are not reproducible. The test therefore controls the token
// instead: with a blank secret half there is no ink to draw in the answer
// colour, so ANY other string rendered there shows up as opaque-green pixels.
func TestMiddlewareStage3CaptchaDrawsTheSecretHalf(t *testing.T) {
	t.Run("a blank secret half leaves no answer-coloured ink", func(t *testing.T) {
		env := mwNewEnv(t)
		env.mwSetStage(3)
		// secretPart = "      ", publicPart[:6] = "WWWWWW" (very inky),
		// publicPart[6:] = "MMMMMM".
		mwStage3InjectToken("      " + "WWWWWW" + "MMMMMM")

		rec := mwDo(mwRequest("/"))
		mwAssertStatus(t, rec, http.StatusOK)
		body := rec.Body.String()

		got := mwCountOpaqueGreen(t, mwExtractPNG(t, body, "captcha_image")) +
			mwCountOpaqueGreen(t, mwExtractPNG(t, body, "mask_image"))
		if got != 0 {
			t.Errorf("captcha carries %d pixels in the answer colour, want 0: the answer label must render encryptedIP[:6], which is blank here", got)
		}
		if env.mwBackendHits() != 0 {
			t.Error("backend was reached during a stage-3 challenge")
		}
	})

	// Control: the same measurement finds plenty of ink when the secret half
	// is not blank, so the assertion above is not vacuously true.
	t.Run("an inky secret half does leave answer-coloured ink", func(t *testing.T) {
		env := mwNewEnv(t)
		env.mwSetStage(3)
		mwStage3InjectToken("WWWWWW" + "      " + "MMMMMM")

		rec := mwDo(mwRequest("/"))
		mwAssertStatus(t, rec, http.StatusOK)
		body := rec.Body.String()

		got := mwCountOpaqueGreen(t, mwExtractPNG(t, body, "captcha_image")) +
			mwCountOpaqueGreen(t, mwExtractPNG(t, body, "mask_image"))
		if got == 0 {
			t.Error("captcha carries no pixels in the answer colour even though the secret half is inky; the measurement is broken")
		}
		if env.mwBackendHits() != 0 {
			t.Error("backend was reached during a stage-3 challenge")
		}
	})
}

func TestMiddlewareStage3SolvedCookiePasses(t *testing.T) {
	env := mwNewEnv(t)
	env.mwSetStage(3)

	// The client sends "<ip>_3__bProxy_v=<answer><publicPart>", which for a
	// correct answer is the whole token.
	// FLIPPED BY WAVE 5: the name is now required to be the stage-3 name for
	// THIS client's ip; the old substring check took the token under any name.
	rec := mwDo(mwRequest("/", mwWithCookie(mwStage3Cookie(mwIP)+"="+mwCaptchaToken())))
	mwAssertStatus(t, rec, http.StatusOK)
	mwAssertBodyContains(t, rec, mwBackendBody)

	// The same token under another client's stage-3 cookie name does not clear
	// this client: the name is bound to the ip the captcha was issued to.
	before := env.mwBackendHits()
	rec = mwDo(mwRequest("/", mwWithCookie(mwStage3Cookie("198.51.100.9")+"="+mwCaptchaToken())))
	mwAssertStatus(t, rec, http.StatusOK)
	mwAssertBodyContains(t, rec, "Drag the <b>slider</b>")
	if env.mwBackendHits() != before {
		t.Errorf("backend hits = %d, want %d", env.mwBackendHits(), before)
	}
}

func TestMiddlewareSuspicionLevelBlocked(t *testing.T) {
	cases := []struct {
		name     string
		stage    int
		wantBody string
	}{
		{name: "stage 4", stage: 4, wantBody: "Suspicious request of level 4 (base 4)"},
		// StageToString maps anything outside 1..4 to "5+".
		{name: "stage 5", stage: 5, wantBody: "Suspicious request of level 5+ (base 5)"},
		{name: "stage 9", stage: 9, wantBody: "Suspicious request of level 5+ (base 9)"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := mwNewEnv(t)
			env.mwSetStage(tc.stage)

			// Even a client holding every valid token is blocked: the block is
			// evaluated before the cookie check.
			rec := mwDo(mwRequest("/", mwWithCookie(mwStage1Cookie+"="+mwCookieToken())))

			// BUG (wave 9 flips this): a suspicion block answers 200 OK.
			mwAssertStatus(t, rec, http.StatusOK)
			mwAssertBodyContains(t, rec, tc.wantBody)
			if env.mwBackendHits() != 0 {
				t.Error("backend was reached despite the suspicion block")
			}
			// The blocked branch returns before CacheIps.Store, so nothing is
			// memoised for a blocked suspicion level.
			if _, ok := firewall.CacheIps.Load(mwAccessKey(tc.stage)); ok {
				t.Error("CacheIps was populated for a blocked suspicion level")
			}
		})
	}
}

// FLIPPED BY WAVE 5. The token cache used to be keyed on
// "<accessKey>" + utils.StageToString(susLv), and StageToString collapses susLv
// 0 and susLv >= 5 into the same "5+" token, so a whitelisted request and a
// blocked request shared one cache entry. Once a whitelisted request had cached
// an empty token there, a later level-5 request from the same client reused it:
// the suspicion block was skipped (cache hit) and the cookie check degenerated
// to strings.Contains(cookieHeader, "__bProxy_v="), which ANY leftover proxy
// cookie satisfied, so the blocked client reached the backend.
//
// Two independent changes close it and this test checks both: the suspicion
// level is now a length-prefixed component of the access key (so levels 0 and 5
// cannot share an entry at all), and the cookie check is an exact per-stage
// name lookup with a constant-time full-value compare (so an empty expected
// token can never be "matched"). utils.StageToString is still lossy - fixing
// that is core/utils' job - and this test must keep passing when it is fixed.
func TestMiddlewareSuspicionLevelCacheKeysAreDistinct(t *testing.T) {
	env := mwNewEnv(t)

	// 1. a whitelisted request caches an empty token under ITS OWN key
	env.mwSetStage(0)
	rec := mwDo(mwRequest("/"))
	mwAssertBodyContains(t, rec, mwBackendBody)

	cached, ok := firewall.CacheIps.Load(mwAccessKey(0))
	if !ok {
		t.Fatal("whitelisted request did not populate CacheIps under the susLv-0 key")
	}
	if cached.(string) != "" {
		t.Fatalf("cached token = %q, want the empty string", cached)
	}
	if _, ok := firewall.CacheIps.Load(mwAccessKey(5)); ok {
		t.Error("the whitelisted request also populated the level-5 cache entry: the two levels still share a key")
	}

	// 2. the same client is now at suspicion level 5 (blocked)
	env.mwSetStage(5)

	t.Run("no cookie is blocked by the first switch", func(t *testing.T) {
		rec := mwDo(mwRequest("/"))
		mwAssertStatus(t, rec, http.StatusOK)
		// The "(base 5)" suffix says the block came from the FIRST switch: the
		// level-5 request missed the cache instead of hitting the whitelisted
		// request's entry.
		mwAssertBodyContains(t, rec, "Suspicious request of level 5+ (base 5)")
	})

	t.Run("a stale proxy cookie no longer bypasses the block", func(t *testing.T) {
		before := env.mwBackendHits()
		rec := mwDo(mwRequest("/", mwWithCookie(mwStage1Cookie+"=whatever-stale-value")))
		mwAssertStatus(t, rec, http.StatusOK)
		mwAssertBodyContains(t, rec, "Suspicious request of level 5+")
		mwAssertBodyNotContains(t, rec, mwBackendBody)
		if env.mwBackendHits() != before {
			t.Errorf("backend hits = %d, want %d: a level-5 request reached the backend", env.mwBackendHits(), before)
		}
	})

	t.Run("even a genuine stage-1 token does not clear level 5", func(t *testing.T) {
		before := env.mwBackendHits()
		rec := mwDo(mwRequest("/", mwWithCookie(mwStage1Cookie+"="+mwCookieToken())))
		mwAssertBodyContains(t, rec, "Suspicious request of level 5+")
		mwAssertBodyNotContains(t, rec, mwBackendBody)
		if env.mwBackendHits() != before {
			t.Errorf("backend hits = %d, want %d", env.mwBackendHits(), before)
		}
	})
}

// ---------------------------------------------------------------------------
// custom firewall rules
// ---------------------------------------------------------------------------

func TestMiddlewareCustomRules(t *testing.T) {
	cases := []struct {
		name       string
		rules      [][2]string
		path       string
		method     string
		wantBody   string
		wantStatus int
		wantHit    bool
	}{
		{
			name:       "static action raises to captcha",
			rules:      [][2]string{{`http.path eq "/captcha"`, "3"}},
			path:       "/captcha",
			wantStatus: http.StatusOK,
			wantBody:   "Drag the <b>slider</b>",
		},
		{
			name:       "static action raises to js challenge",
			rules:      [][2]string{{`http.path eq "/js"`, "2"}},
			path:       "/js",
			wantStatus: http.StatusOK,
			wantBody:   "BalooPow",
		},
		{
			name:       "relative action adds to the stage",
			rules:      [][2]string{{`http.method ne "GET" and http.method ne "POST"`, "+2"}},
			path:       "/",
			method:     http.MethodDelete,
			wantStatus: http.StatusOK,
			wantBody:   "Drag the <b>slider</b>", // stage 1 + 2 = 3
		},
		{
			name:       "relative action can lower the stage to whitelist",
			rules:      [][2]string{{`http.path eq "/health"`, "-1"}},
			path:       "/health",
			wantStatus: http.StatusOK,
			wantBody:   mwBackendBody,
			wantHit:    true,
		},
		{
			name:       "non matching rule leaves the stage alone",
			rules:      [][2]string{{`http.path eq "/other"`, "3"}},
			path:       "/",
			wantStatus: http.StatusFound, // stage 1 redirect
		},
		{
			name:       "additions can push past the block threshold",
			rules:      [][2]string{{`http.user_agent contains "mw-test"`, "+4"}},
			path:       "/",
			wantStatus: http.StatusOK,
			wantBody:   "Suspicious request of level 5+ (base 1)",
		},
		{
			name: "a static action wins and stops evaluation",
			rules: [][2]string{
				{`http.path eq "/stop"`, "0"},
				{`http.path eq "/stop"`, "+4"},
			},
			path:       "/stop",
			wantStatus: http.StatusOK,
			wantBody:   mwBackendBody,
			wantHit:    true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := mwNewEnv(t)
			env.mwSetStage(1)
			env.mwSetRules(tc.rules...)

			opts := []mwReqOpt{}
			if tc.method != "" {
				opts = append(opts, mwWithMethod(tc.method))
			}
			rec := mwDo(mwRequest(tc.path, opts...))

			mwAssertStatus(t, rec, tc.wantStatus)
			if tc.wantBody != "" {
				mwAssertBodyContains(t, rec, tc.wantBody)
			}
			if hit := env.mwBackendHits() > 0; hit != tc.wantHit {
				t.Errorf("backend reached = %v, want %v", hit, tc.wantHit)
			}
		})
	}
}

// BUG (wave 5 flips this): firewall.EvalFirewallRule slices rule.Action[:1]
// without a length check, so a config rule with an empty action panics the
// request goroutine. Reachable from a plain config.json.
func TestMiddlewareEmptyRuleActionPanics(t *testing.T) {
	env := mwNewEnv(t)
	env.mwSetRules([2]string{`http.method eq "GET"`, ""})

	rec := httptest.NewRecorder()
	got := mwRecover(func() { Middleware(rec, mwRequest("/")) })
	if got == nil {
		t.Fatal("expected a panic from an empty rule action, got none")
	}
	if !strings.Contains(mwPanicString(got), "out of range") {
		t.Errorf("panic = %v, want a slice bounds out of range panic", got)
	}
	if env.mwBackendHits() != 0 {
		t.Error("backend was reached")
	}
}

// ---------------------------------------------------------------------------
// reserved /_bProxy/* paths
// ---------------------------------------------------------------------------

func TestMiddlewareReservedPaths(t *testing.T) {
	t.Run("stats", func(t *testing.T) {
		env := mwNewEnv(t)
		env.mwSetStage(0)

		// FLIPPED BY WAVE 5: /_bProxy/stats now requires the API secret.
		rec := mwDo(mwRequest("/_bProxy/stats", mwWithAPISecret()))
		mwAssertStatus(t, rec, http.StatusOK)
		if ct := rec.Result().Header.Get("Content-Type"); ct != "text/plain" {
			t.Errorf("Content-Type = %q, want text/plain", ct)
		}
		// FLIPPED BY WAVE 5: StageToString used to render 0 as "5+", so a
		// whitelisted domain reported itself as the most hostile stage on its
		// own stats page. The same collision was a full bypass of the block
		// verdict through the token cache; see
		// TestMiddlewareSuspicionLevelCacheKeysAreDistinct.
		mwAssertBodyContains(t, rec, "Stage: 0")
		mwAssertBodyContains(t, rec, "Total Requests: 1")
		mwAssertBodyContains(t, rec, "Bypassed Requests: 1")
		mwAssertBodyContains(t, rec, "Proxy Fingerprint: mw-proxy-fingerprint")
		if env.mwBackendHits() != 0 {
			t.Error("backend was reached for a reserved path")
		}
	})

	t.Run("fingerprint", func(t *testing.T) {
		env := mwNewEnv(t)
		env.mwSetStage(0)
		firewall.AccessIps[mwIP] = 7
		firewall.AccessIpsCookie[mwIP] = 3
		firewall.KnownFingerprints[mwFP] = "Chromium"
		firewall.BotFingerprints[mwFP] = "-bot"

		// FLIPPED BY WAVE 5: /_bProxy/fingerprint now requires the API secret.
		rec := mwDo(mwRequest("/_bProxy/fingerprint", mwWithAPISecret()))
		mwAssertStatus(t, rec, http.StatusOK)
		mwAssertBodyContains(t, rec, "IP: "+mwIP)
		mwAssertBodyContains(t, rec, "IP Requests: 7")
		mwAssertBodyContains(t, rec, "IP Challenge Requests: 3")
		mwAssertBodyContains(t, rec, "SusLV: 0")
		mwAssertBodyContains(t, rec, "Fingerprint: "+mwFP)
		mwAssertBodyContains(t, rec, "Browser: Chromium-bot")
		if env.mwBackendHits() != 0 {
			t.Error("backend was reached for a reserved path")
		}
	})

	t.Run("verified", func(t *testing.T) {
		env := mwNewEnv(t)
		env.mwSetStage(0)

		rec := mwDo(mwRequest("/_bProxy/verified"))
		mwAssertStatus(t, rec, http.StatusOK)
		if body := rec.Body.String(); body != "verified" {
			t.Errorf("body = %q, want %q", body, "verified")
		}
		if env.mwBackendHits() != 0 {
			t.Error("backend was reached for a reserved path")
		}
	})

	t.Run("credits", func(t *testing.T) {
		env := mwNewEnv(t)
		env.mwSetStage(0)

		rec := mwDo(mwRequest("/_bProxy/credits"))
		mwAssertStatus(t, rec, http.StatusOK)
		// Required by the GPL. Flips in the wave that rebrands runtime strings.
		want := "BalooProxy; Lightweight http reverse-proxy https://github.com/41Baloo/balooProxy. Protected by GNU GENERAL PUBLIC LICENSE Version 2, June 1991"
		if body := rec.Body.String(); body != want {
			t.Errorf("credits body = %q, want %q", body, want)
		}
		if env.mwBackendHits() != 0 {
			t.Error("backend was reached for a reserved path")
		}
	})

	t.Run("reserved prefix that is not a reserved path is proxied", func(t *testing.T) {
		env := mwNewEnv(t)
		env.mwSetStage(0)

		rec := mwDo(mwRequest("/_bProxy/not-a-real-endpoint"))
		mwAssertStatus(t, rec, http.StatusOK)
		mwAssertBodyContains(t, rec, mwBackendBody)
		if got := rec.Result().Header.Get("X-Echo-Path"); got != "/_bProxy/not-a-real-endpoint" {
			t.Errorf("backend saw path %q", got)
		}
	})
}

// Reserved paths sit BEHIND the challenge: an unverified client at stage 1 is
// redirected instead of being served /_bProxy/stats.
func TestMiddlewareReservedPathsRequireChallenge(t *testing.T) {
	env := mwNewEnv(t)
	env.mwSetStage(1)

	rec := mwDo(mwRequest("/_bProxy/stats"))
	mwAssertStatus(t, rec, http.StatusFound)
	mwAssertBodyNotContains(t, rec, "Total Requests")
	if env.mwBackendHits() != 0 {
		t.Error("backend was reached")
	}
}

// The reserved-path dispatch keys off request.URL.Path, i.e. the path with the
// query string already stripped. Re-keying it off the raw request line
// (request.RequestURI) is a one-word slip that would silently proxy every
// reserved endpoint to the customer backend as soon as a query string is
// present - including the admin API path, which carries the admin secret.
func TestMiddlewareReservedPathsIgnoreTheQueryString(t *testing.T) {
	cases := []struct {
		name     string
		target   string
		wantBody string
		secret   bool
	}{
		{name: "stats", target: "/_bProxy/stats?x=1", wantBody: "Total Requests: 1", secret: true},
		{name: "fingerprint", target: "/_bProxy/fingerprint?x=1", wantBody: "IP: " + mwIP, secret: true},
		{name: "verified", target: "/_bProxy/verified?x=1", wantBody: "verified"},
		{name: "credits", target: "/_bProxy/credits?x=1", wantBody: "BalooProxy; Lightweight http reverse-proxy"},
		{name: "credits with a bare query marker", target: "/_bProxy/credits?", wantBody: "BalooProxy; Lightweight http reverse-proxy"},
		{name: "verified with a fragment-looking query", target: "/_bProxy/verified?a=b&c=d", wantBody: "verified"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := mwNewEnv(t)
			env.mwSetStage(0)

			opts := []mwReqOpt{}
			if tc.secret {
				opts = append(opts, mwWithAPISecret())
			}
			rec := mwDo(mwRequest(tc.target, opts...))

			mwAssertStatus(t, rec, http.StatusOK)
			mwAssertBodyContains(t, rec, tc.wantBody)
			mwAssertBodyNotContains(t, rec, mwBackendBody)
			if env.mwBackendHits() != 0 {
				t.Errorf("backend hits = %d, want 0: %q is a reserved path regardless of its query string", env.mwBackendHits(), tc.target)
			}
			if ct := rec.Result().Header.Get("Content-Type"); ct != "text/plain" {
				t.Errorf("Content-Type = %q, want text/plain", ct)
			}
		})
	}

	t.Run("admin api v1 with a query string", func(t *testing.T) {
		env := mwNewEnv(t)
		env.mwSetStage(0)
		proxy.CpuUsage = "12.5%"

		req := mwRequest("/_bProxy/"+mwAdminSecret+"/api/v1?x=1",
			mwWithMethod(http.MethodPost),
			mwWithHeader("proxy-secret", mwAPISecret),
		)
		req.Body = mwBody(`{"action":"GET_PROXY_STATS"}`)
		rec := mwDo(req)

		mwAssertBodyContains(t, rec, `"CPU_USAGE":"12.5%"`)
		mwAssertBodyNotContains(t, rec, mwBackendBody)
		if env.mwBackendHits() != 0 {
			t.Errorf("backend hits = %d, want 0: the admin path (and its secret) must never reach the backend", env.mwBackendHits())
		}
	})
}

// /_bProxy/stats reports two different counters. Swapping the two same-typed
// strconv.Itoa arguments would make a fully bypassed attack read as fully
// blocked, so the fixture below keeps Total and Bypassed deliberately unequal.
func TestMiddlewareStatsReportsTotalAndBypassedSeparately(t *testing.T) {
	env := mwNewEnv(t)

	// Three requests that are counted but never bypassed (stage 5 blocks
	// before the bypass bookkeeping).
	env.mwSetStage(5)
	for range 3 {
		rec := mwDo(mwRequest("/"))
		mwAssertBodyContains(t, rec, "Suspicious request of level 5+")
	}

	// One request that is both counted and bypassed, then the stats request
	// itself, which is counted and bypassed before the page is rendered.
	env.mwSetStage(0)
	mwDo(mwRequest("/"))

	rec := mwDo(mwRequest("/_bProxy/stats", mwWithAPISecret()))

	mwAssertStatus(t, rec, http.StatusOK)
	// 3 blocked + 1 allowed + this one = 5 total; 1 allowed + this one = 2
	// bypassed. The two numbers must not be interchangeable.
	mwAssertBodyContains(t, rec, "Total Requests: 5")
	mwAssertBodyContains(t, rec, "Bypassed Requests: 2")

	if d := env.mwDomainData(); d.TotalRequests != 5 || d.BypassedRequests != 2 {
		t.Fatalf("fixture drifted: TotalRequests = %d (want 5), BypassedRequests = %d (want 2)", d.TotalRequests, d.BypassedRequests)
	}
	if env.mwBackendHits() != 1 {
		t.Errorf("backend hits = %d, want 1", env.mwBackendHits())
	}
}

func TestMiddlewareAdminAPIv1(t *testing.T) {
	t.Run("correct proxy-secret is served by the api", func(t *testing.T) {
		env := mwNewEnv(t)
		env.mwSetStage(0)
		proxy.CpuUsage = "12.5%"
		proxy.RamUsage = "34.5%"

		req := mwRequest("/_bProxy/"+mwAdminSecret+"/api/v1",
			mwWithMethod(http.MethodPost),
			mwWithHeader("proxy-secret", mwAPISecret),
		)
		req.Body = mwBody(`{"action":"GET_PROXY_STATS"}`)
		rec := mwDo(req)

		mwAssertStatus(t, rec, http.StatusOK)
		if ct := rec.Result().Header.Get("Content-Type"); ct != "application/json" {
			t.Errorf("Content-Type = %q, want application/json", ct)
		}
		var resp struct {
			Success bool           `json:"success"`
			Results map[string]any `json:"results"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decode api response: %v (body %q)", err, rec.Body.String())
		}
		if !resp.Success {
			t.Errorf("success = false, want true (body %q)", rec.Body.String())
		}
		if resp.Results["CPU_USAGE"] != "12.5%" || resp.Results["RAM_USAGE"] != "34.5%" {
			t.Errorf("results = %v", resp.Results)
		}
		if env.mwBackendHits() != 0 {
			t.Error("backend was reached for an authenticated api call")
		}
	})

	t.Run("missing proxy-secret is a 404 and never reaches the backend", func(t *testing.T) {
		env := mwNewEnv(t)
		env.mwSetStage(0)

		rec := mwDo(mwRequest("/_bProxy/" + mwAdminSecret + "/api/v1"))

		// Wave 5 flipped this. api.Process used to return false on an auth
		// failure, and the switch case has no return, so an unauthenticated
		// admin request was forwarded upstream - handing proxy.AdminSecret to
		// the backend in the URL and in every backend access log, and making
		// the admin surface discoverable by diffing response codes. It now
		// answers 404 and reports the request as handled, so the middleware
		// returns without proxying.
		mwAssertStatus(t, rec, http.StatusNotFound)
		mwAssertBodyNotContains(t, rec, mwBackendBody)
		if got := rec.Result().Header.Get("X-Echo-Path"); got != "" {
			t.Errorf("backend saw path %q, want the admin path (and its secret) never to reach the backend", got)
		}
		if env.mwBackendHits() != 0 {
			t.Errorf("backend hits = %d, want 0", env.mwBackendHits())
		}
	})

	t.Run("wrong admin secret in the path is not an api call", func(t *testing.T) {
		env := mwNewEnv(t)
		env.mwSetStage(0)

		req := mwRequest("/_bProxy/wrong-secret/api/v1",
			mwWithMethod(http.MethodPost),
			mwWithHeader("proxy-secret", mwAPISecret),
		)
		req.Body = mwBody(`{"action":"GET_PROXY_STATS"}`)
		rec := mwDo(req)

		mwAssertBodyContains(t, rec, mwBackendBody)
		if env.mwBackendHits() != 1 {
			t.Errorf("backend hits = %d, want 1", env.mwBackendHits())
		}
	})
}

func TestMiddlewareAPIv2(t *testing.T) {
	t.Run("proxy action", func(t *testing.T) {
		env := mwNewEnv(t)
		env.mwSetStage(0)
		proxy.CpuUsage = "99%"

		rec := mwDo(mwRequest("/_bProxy/api/v2/GET_PROXY_STATS_CPU_USAGE",
			mwWithHeader("Proxy-Secret", mwAPISecret)))

		mwAssertStatus(t, rec, http.StatusOK)
		mwAssertBodyContains(t, rec, `"CPU_USAGE":"99%"`)
		if env.mwBackendHits() != 0 {
			t.Error("backend was reached for an authenticated api call")
		}
	})

	t.Run("domain action", func(t *testing.T) {
		env := mwNewEnv(t)
		env.mwSetStage(0)

		rec := mwDo(mwRequest("/_bProxy/api/v2/"+mwDomain+"/GET_TOTAL_REQUESTS",
			mwWithHeader("Proxy-Secret", mwAPISecret)))

		mwAssertStatus(t, rec, http.StatusOK)
		mwAssertBodyContains(t, rec, `"TOTAL_REQUESTS":1`)
	})

	t.Run("unknown domain", func(t *testing.T) {
		env := mwNewEnv(t)
		env.mwSetStage(0)

		rec := mwDo(mwRequest("/_bProxy/api/v2/nope.example/GET_TOTAL_REQUESTS",
			mwWithHeader("Proxy-Secret", mwAPISecret)))

		mwAssertBodyContains(t, rec, `"ERROR":"ERR_DOMAIN_NOT_FOUND"`)
		mwAssertBodyContains(t, rec, `"success":false`)
	})

	t.Run("missing secret is a 404 and never reaches the backend", func(t *testing.T) {
		env := mwNewEnv(t)
		env.mwSetStage(0)

		// Wave 5 flipped this, for the same reason as the v1 case above: an
		// unauthenticated admin request used to be proxied to the customer
		// backend, so the endpoint could be located by response-code
		// differencing without guessing the secret.
		rec := mwDo(mwRequest("/_bProxy/api/v2/GET_PROXY_STATS"))
		mwAssertStatus(t, rec, http.StatusNotFound)
		mwAssertBodyNotContains(t, rec, mwBackendBody)
		if env.mwBackendHits() != 0 {
			t.Errorf("backend hits = %d, want 0", env.mwBackendHits())
		}
	})

	// The marker is honoured as a PREFIX of the path only. Loosening that to a
	// substring test turns the admin API into a route reachable from any
	// backend path that merely embeds the marker.
	t.Run("the marker is only honoured at the start of the path", func(t *testing.T) {
		cases := []string{
			"/uploads/x/_bProxy/api/v2/GET_PROXY_STATS_CPU_USAGE",
			"/files/_bProxy/api/v2/" + mwDomain + "/GET_TOTAL_REQUESTS",
			"/a/_bProxy/api/v2",
			"/_bProxy/api/v3/_bProxy/api/v2/GET_PROXY_STATS_CPU_USAGE",
		}

		for _, target := range cases {
			t.Run(target, func(t *testing.T) {
				env := mwNewEnv(t)
				env.mwSetStage(0)
				proxy.CpuUsage = "99%"

				rec := mwDo(mwRequest(target, mwWithHeader("Proxy-Secret", mwAPISecret)))

				mwAssertBodyContains(t, rec, mwBackendBody)
				mwAssertBodyNotContains(t, rec, "CPU_USAGE")
				mwAssertBodyNotContains(t, rec, "ERR_DOMAIN_NOT_FOUND")
				if env.mwBackendHits() != 1 {
					t.Errorf("backend hits = %d, want 1: %q merely embeds the api marker, it does not start with it", env.mwBackendHits(), target)
				}
			})
		}
	})
}

// ---------------------------------------------------------------------------
// backend forwarding
// ---------------------------------------------------------------------------

func TestMiddlewareForwardsClientInfoHeaders(t *testing.T) {
	env := mwNewEnv(t)
	env.mwSetStage(0)
	firewall.KnownFingerprints[mwFP] = "Chromium"
	firewall.BotFingerprints[mwFP] = "-crawler"

	rec := mwDo(mwRequest("/app?x=1"))
	mwAssertStatus(t, rec, http.StatusOK)
	mwAssertBodyContains(t, rec, mwBackendBody)

	h := rec.Result().Header
	checks := map[string]string{
		"X-Echo-X-Real-Ip":      mwIP,
		"X-Echo-Proxy-Real-Ip":  mwIP,
		"X-Echo-Proxy-Tls-Fp":   mwFP,
		"X-Echo-Proxy-Tls-Name": "Chromium-crawler",
		"X-Echo-Path":           "/app",
		"X-Echo-Query":          "x=1",
	}
	for k, want := range checks {
		if got := h.Get(k); got != want {
			t.Errorf("%s = %q, want %q", k, got, want)
		}
	}
	if v := h.Get("baloo-Proxy"); v != "1.5" {
		t.Errorf("baloo-Proxy = %q, want 1.5", v)
	}
	if env.mwBackendHits() != 1 {
		t.Errorf("backend hits = %d, want 1", env.mwBackendHits())
	}
}

// FLIPPED BY WAVE 6: the client-info headers were ADDED, not SET, so a client
// that sent its own x-real-ip kept it and the backend saw "spoofed, real".
// Header.Get - how almost every backend reads a header - returns the FIRST
// value, so the attacker's won: every access-control decision, audit log and
// geo lookup behind this proxy was spoofable with one request header.
//
// They are now Del'd and Set. Del covers more than the four names written back:
// X-Forwarded-For and Forwarded say the same thing under other names, and a
// client can invent proxy-* headers himself.
func TestMiddlewareClientSuppliedIdentityHeadersAreReplaced(t *testing.T) {
	env := mwNewEnv(t)
	env.mwSetStage(0)
	firewall.KnownFingerprints[mwFP] = "Chromium"

	rec := mwDo(mwRequest("/",
		mwWithHeader("X-Real-Ip", "10.0.0.1"),
		mwWithHeader("Proxy-Tls-Name", "TotallyChrome"),
	))
	mwAssertStatus(t, rec, http.StatusOK)

	if got, want := rec.Result().Header.Get("X-Echo-X-Real-Ip"), mwIP; got != want {
		t.Errorf("backend saw x-real-ip = %q, want %q (exactly one value, the proxy's)", got, want)
	}
	if got, want := rec.Result().Header.Get("X-Echo-Proxy-Tls-Name"), "Chromium"; got != want {
		t.Errorf("backend saw proxy-tls-name = %q, want %q", got, want)
	}
	if env.mwBackendHits() != 1 {
		t.Errorf("backend hits = %d, want 1", env.mwBackendHits())
	}
}

// The wider sweep: every inbound header in the client-identity family is
// removed before the proxy's own values are set, so nothing a client sends
// under one of these names survives to the backend.
func TestMiddlewareInboundIdentityHeadersAreStripped(t *testing.T) {
	env := mwNewEnv(t)
	env.mwSetStage(0)
	env.storeSettings(nil, nil)

	// The stub backend only echoes a fixed list, so capture the whole forwarded
	// header set with a purpose-built one.
	var forwarded http.Header
	captured := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		forwarded = r.Header.Clone()
		_, _ = w.Write([]byte(mwBackendBody))
	}))
	t.Cleanup(captured.Close)

	target, err := url.Parse(captured.URL)
	if err != nil {
		t.Fatalf("parse backend url: %v", err)
	}
	rp := httputil.NewSingleHostReverseProxy(target)
	rp.Transport = &transport.RoundTripper{}
	domains.DomainsMap.Store(mwDomain, domains.DomainSettings{Name: mwDomain, DomainProxy: rp})

	rec := mwDo(mwRequest("/",
		mwWithHeader("X-Forwarded-For", "10.0.0.1, 10.0.0.2"),
		mwWithHeader("Forwarded", "for=10.0.0.3"),
		mwWithHeader("X-Real-Ip", "10.0.0.4"),
		mwWithHeader("Proxy-Real-Ip", "10.0.0.5"),
		mwWithHeader("Proxy-Tls-Fp", "forged-fingerprint"),
		mwWithHeader("Proxy-Secret", "guessed-admin-secret"),
	))
	mwAssertStatus(t, rec, http.StatusOK)
	if forwarded == nil {
		t.Fatal("backend was not reached")
	}

	// Nothing the client wrote survives.
	for _, forged := range []string{"10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4", "10.0.0.5", "forged-fingerprint", "guessed-admin-secret"} {
		for name, values := range forwarded {
			for _, v := range values {
				if strings.Contains(v, forged) {
					t.Errorf("client-supplied %q survived to the backend as %s: %q", forged, name, v)
				}
			}
		}
	}
	if got := forwarded.Get("Forwarded"); got != "" {
		t.Errorf("Forwarded = %q, want it removed", got)
	}
	// The admin API header must never reach a customer backend.
	if got := forwarded.Get("Proxy-Secret"); got != "" {
		t.Errorf("Proxy-Secret = %q, want it removed", got)
	}
	// X-Forwarded-For is deleted and left to httputil.ReverseProxy, which
	// appends the socket peer. That is the honest value for that header.
	if got, want := forwarded.Get("X-Forwarded-For"), mwIP; got != want {
		t.Errorf("X-Forwarded-For = %q, want %q (the socket peer, appended by ReverseProxy)", got, want)
	}
	if got, want := forwarded.Get("X-Real-Ip"), mwIP; got != want {
		t.Errorf("X-Real-Ip = %q, want %q", got, want)
	}
}

// FLIPPED BY WAVE 5: the challenge cookies used to be forwarded verbatim to the
// backend, so an XSS bug or a verbose access log on any customer backend handed
// out a working bypass for every domain the proxy fronts. They are now stripped
// from the request before it is proxied - every cookie whose NAME carries the
// "__bProxy_v" token, whatever prefix it wears - while unrelated cookies survive
// untouched.
func TestMiddlewareProxyCookiesAreStrippedBeforeForwarding(t *testing.T) {
	token := mwCookieToken()

	cases := []struct {
		name string
		sent string
		want string
	}{
		{
			name: "stage-1 cookie is removed, others survive",
			sent: mwStage1Cookie + "=" + token + "; other=1",
			want: "other=1",
		},
		{
			name: "order and spacing of the survivors is normalised, not lost",
			sent: "a=1;" + mwStage1Cookie + "=" + token + "; b=2",
			want: "a=1; b=2",
		},
		{
			name: "every stage prefix goes",
			sent: "keep=yes; " + mwStage1Cookie + "=" + token + "; " + mwStage2Cookie + "=x; " + mwStage3Cookie(mwIP) + "=y",
			want: "keep=yes",
		},
		{
			name: "an attacker-chosen prefix carrying the token goes too",
			sent: "evil" + mwStage1Cookie + "=" + token + "; keep=yes",
			want: "keep=yes",
		},
		{
			name: "the bare wire name goes",
			sent: "__bProxy_v=" + token + "; keep=yes",
			want: "keep=yes",
		},
		{
			name: "a header that is nothing but proxy cookies is dropped entirely",
			sent: mwStage1Cookie + "=" + token,
			want: "",
		},
		{
			name: "a header with no proxy cookie is passed through byte for byte",
			sent: "a=1; b=2",
			want: "a=1; b=2",
		},
		{
			name: "a cookie whose VALUE mentions the token is not a proxy cookie",
			sent: "note=see" + mwStage1Cookie + "=" + token,
			want: "note=see" + mwStage1Cookie + "=" + token,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := mwNewEnv(t)
			env.mwSetStage(0) // whitelisted: reach the backend regardless of cookies

			rec := mwDo(mwRequest("/", mwWithCookie(tc.sent)))
			mwAssertStatus(t, rec, http.StatusOK)
			mwAssertBodyContains(t, rec, mwBackendBody)

			if got := rec.Result().Header.Get("X-Echo-Cookie"); got != tc.want {
				t.Errorf("backend saw Cookie = %q, want %q", got, tc.want)
			}
			if strings.Contains(rec.Result().Header.Get("X-Echo-Cookie"), token) && !strings.Contains(tc.want, token) {
				t.Error("the clearance token reached the backend")
			}
			if env.mwBackendHits() != 1 {
				t.Errorf("backend hits = %d, want 1", env.mwBackendHits())
			}
		})
	}
}

// Stripping runs AFTER the cookie check, so a client that presents a valid
// token is still cleared - the backend just never sees it.
func TestMiddlewareStrippingDoesNotBreakVerification(t *testing.T) {
	env := mwNewEnv(t)
	env.mwSetStage(1)

	token := mwCookieToken()
	rec := mwDo(mwRequest("/", mwWithCookie(mwStage1Cookie+"="+token+"; other=1")))

	mwAssertStatus(t, rec, http.StatusOK)
	mwAssertBodyContains(t, rec, mwBackendBody)
	if got := rec.Result().Header.Get("X-Echo-Cookie"); got != "other=1" {
		t.Errorf("backend saw Cookie = %q, want %q", got, "other=1")
	}
	if env.mwBackendHits() != 1 {
		t.Errorf("backend hits = %d, want 1", env.mwBackendHits())
	}
}

// ---------------------------------------------------------------------------
// cloudflare mode
// ---------------------------------------------------------------------------

func TestMiddlewareCloudflareMode(t *testing.T) {
	t.Run("Cf-Connecting-Ip becomes the subject ip", func(t *testing.T) {
		env := mwNewEnv(t)
		domains.Config.Proxy.Cloudflare = true
		proxy.Cloudflare = true
		// FLIPPED BY WAVE 6: the header is believed only from a trusted peer.
		mwTrustPeers(t, mwIP+"/32")
		env.mwSetStage(0)

		rec := mwDo(mwRequest("/_bProxy/fingerprint", mwWithAPISecret(),
			mwWithHeader("Cf-Connecting-Ip", "198.51.100.44")))

		mwAssertBodyContains(t, rec, "IP: 198.51.100.44")
		// TLS fingerprinting is disabled behind Cloudflare: everything is
		// reported as the sentinel string "Cloudflare".
		mwAssertBodyContains(t, rec, "Fingerprint: Cloudflare")
		mwAssertBodyContains(t, rec, "Browser: Cloudflare")

		firewall.Mutex.RLock()
		unk := len(firewall.WindowUnkFps[mwTimestamp])
		access := firewall.WindowAccessIps[mwTimestamp]["198.51.100.44"]
		firewall.Mutex.RUnlock()
		if unk != 0 {
			t.Errorf("WindowUnkFps has %d entries, want 0 in cloudflare mode", unk)
		}
		if access != 1 {
			t.Errorf("WindowAccessIps[%d][198.51.100.44] = %d, want 1", mwTimestamp, access)
		}
		if env.mwBackendHits() != 0 {
			t.Error("backend was reached for a reserved path")
		}
	})

	// FLIPPED BY WAVE 6. The header used to be trusted unconditionally, so
	// anyone who found the origin address picked his own subject IP - and, by
	// sending a fresh one per request, his own ratelimit bucket, his own token
	// cache entry and his own log identity. One header defeated the whole
	// mitigation stack.
	//
	// The escape is the thing to test, not the header value: the peer is over
	// the R2 threshold and tries to walk out of its bucket by naming a
	// different client.
	t.Run("Cf-Connecting-Ip from an untrusted peer cannot escape the peer's ratelimit", func(t *testing.T) {
		env := mwNewEnv(t)
		domains.Config.Proxy.Cloudflare = true
		proxy.Cloudflare = true
		env.mwSetStage(1)
		firewall.AccessIps["192.0.2.99"] = proxy.IPRatelimit + 1 // the real peer is ratelimited

		rec := mwDo(mwRequest("/",
			mwWithRemoteAddr("192.0.2.99:1234"),
			mwWithHeader("Cf-Connecting-Ip", "1.1.1.1")))

		if got, want := rec.Body.String(), "Blocked by BalooProxy.\nYou have been ratelimited. (R2)"; got != want {
			t.Errorf("body = %q, want %q: the spoofed header bought a fresh bucket", mwTrunc(got, 200), want)
		}
		if env.mwBackendHits() != 0 {
			t.Errorf("backend hits = %d, want 0", env.mwBackendHits())
		}
	})

	// ...and the same request from a peer the operator DID configure as a
	// trusted proxy is believed, which is the whole point of the mode.
	t.Run("Cf-Connecting-Ip from a trusted peer is believed", func(t *testing.T) {
		env := mwNewEnv(t)
		domains.Config.Proxy.Cloudflare = true
		proxy.Cloudflare = true
		mwTrustPeers(t, "192.0.2.0/24")
		env.mwSetStage(0)

		rec := mwDo(mwRequest("/",
			mwWithRemoteAddr("192.0.2.99:1234"),
			mwWithHeader("Cf-Connecting-Ip", "1.1.1.1")))

		mwAssertBodyContains(t, rec, mwBackendBody)
		if got := rec.Result().Header.Get("X-Echo-X-Real-Ip"); got != "1.1.1.1" {
			t.Errorf("backend saw x-real-ip = %q, want 1.1.1.1", got)
		}
	})

	// Cloudflare mode wires up its OWN pair of counters. Both must be read for
	// the subject IP, not just the request counter: ipCountCookie is what R1
	// (the challenge-failure limiter that outranks everything else) consults,
	// and `cloudflare: true` is the documented production deployment mode.
	t.Run("both ratelimit counters are wired to the cloudflare subject ip", func(t *testing.T) {
		const cfIP = "198.51.100.44"

		t.Run("R1 fires on the subject ip's challenge failures", func(t *testing.T) {
			env := mwNewEnv(t)
			domains.Config.Proxy.Cloudflare = true
			proxy.Cloudflare = true
			mwTrustPeers(t, mwIP+"/32")
			// FLIPPED BY WAVE 6: stage 1, not stage 0. A whitelisted request is
			// no longer subject to the ratelimits at all, so a stage-0 setup
			// would prove nothing about which counter R1 reads.
			env.mwSetStage(1)
			firewall.AccessIpsCookie[cfIP] = proxy.FailChallengeRatelimit + 1

			rec := mwDo(mwRequest("/", mwWithHeader("Cf-Connecting-Ip", cfIP)))

			if got, want := rec.Body.String(), "Blocked by BalooProxy.\nYou have been ratelimited. (R1)"; got != want {
				t.Errorf("body = %q, want %q", mwTrunc(got, 200), want)
			}
			if env.mwBackendHits() != 0 {
				t.Errorf("backend hits = %d, want 0", env.mwBackendHits())
			}
		})

		t.Run("R2 fires on the subject ip's request count", func(t *testing.T) {
			env := mwNewEnv(t)
			domains.Config.Proxy.Cloudflare = true
			proxy.Cloudflare = true
			mwTrustPeers(t, mwIP+"/32")
			env.mwSetStage(1) // FLIPPED BY WAVE 6, as above
			firewall.AccessIps[cfIP] = proxy.IPRatelimit + 1

			rec := mwDo(mwRequest("/", mwWithHeader("Cf-Connecting-Ip", cfIP)))

			if got, want := rec.Body.String(), "Blocked by BalooProxy.\nYou have been ratelimited. (R2)"; got != want {
				t.Errorf("body = %q, want %q", mwTrunc(got, 200), want)
			}
			if env.mwBackendHits() != 0 {
				t.Errorf("backend hits = %d, want 0", env.mwBackendHits())
			}
		})

		t.Run("both counters are reported verbatim", func(t *testing.T) {
			env := mwNewEnv(t)
			domains.Config.Proxy.Cloudflare = true
			proxy.Cloudflare = true
			mwTrustPeers(t, mwIP+"/32")
			env.mwSetStage(0)
			firewall.AccessIps[cfIP] = 7
			firewall.AccessIpsCookie[cfIP] = 3

			rec := mwDo(mwRequest("/_bProxy/fingerprint", mwWithAPISecret(), mwWithHeader("Cf-Connecting-Ip", cfIP)))

			mwAssertBodyContains(t, rec, "IP Requests: 7")
			mwAssertBodyContains(t, rec, "IP Challenge Requests: 3")
			if env.mwBackendHits() != 0 {
				t.Error("backend was reached for a reserved path")
			}
		})
	})

	// FLIPPED BY WAVE 6: with no Cf-Connecting-Ip header the subject IP used to
	// be the empty string, so ALL such traffic shared one ratelimit bucket, one
	// encryption cache key and one log identity - and since the header was
	// never required, simply omitting it was a way into that shared bucket. The
	// answer is now the socket peer, which every request has.
	t.Run("missing Cf-Connecting-Ip falls back to the socket peer", func(t *testing.T) {
		env := mwNewEnv(t)
		domains.Config.Proxy.Cloudflare = true
		proxy.Cloudflare = true
		mwTrustPeers(t, mwIP+"/32")
		env.mwSetStage(0)

		rec := mwDo(mwRequest("/_bProxy/fingerprint", mwWithAPISecret()))
		mwAssertBodyContains(t, rec, "IP: "+mwIP+"\n")

		firewall.Mutex.RLock()
		empty := firewall.WindowAccessIps[mwTimestamp][""]
		peer := firewall.WindowAccessIps[mwTimestamp][mwIP]
		firewall.Mutex.RUnlock()
		if empty != 0 {
			t.Errorf(`WindowAccessIps[%d][""] = %d, want 0: nothing may be counted under the empty key`, mwTimestamp, empty)
		}
		if peer != 1 {
			t.Errorf("WindowAccessIps[%d][%s] = %d, want 1", mwTimestamp, mwIP, peer)
		}
		if env.mwBackendHits() != 0 {
			t.Error("backend was reached for a reserved path")
		}
	})
}

// FLIPPED BY WAVE 6. The subject IP used to be
// strings.Split(RemoteAddr, ":")[0], which mangled every IPv6 peer down to the
// literal string "[2001" - so 2001:db8::1, 2001:db8:ffff::2 and every other
// address whose first hextet was 2001 shared one ratelimit bucket, one
// encryption cache key and one log identity. It is now net.SplitHostPort plus
// netip.ParseAddr, and the counter is keyed on the /64.
func TestMiddlewareIPv6IsParsedAndKeyedOnTheSlash64(t *testing.T) {
	env := mwNewEnv(t)
	env.mwSetStage(0)

	cases := []struct {
		remote  string
		wantIP  string
		wantKey string
	}{
		// Two addresses one hop apart inside the SAME /64: one bucket, because
		// rotating inside an allocation is free for the attacker.
		{"[2001:db8:1:2::1]:51000", "2001:db8:1:2::1", "2001:db8:1:2::/64"},
		{"[2001:db8:1:2::dead:beef]:51001", "2001:db8:1:2::dead:beef", "2001:db8:1:2::/64"},
		// A different /64 is a different bucket.
		{"[2001:db8:1:3::1]:51002", "2001:db8:1:3::1", "2001:db8:1:3::/64"},
		// A v4 client is still keyed on the whole address.
		{"198.51.100.9:51003", "198.51.100.9", "198.51.100.9"},
		// A 4-in-6 mapped peer is unmapped, so a dual-stack listener does not
		// hand the same client a second bucket.
		{"[::ffff:198.51.100.9]:51004", "198.51.100.9", "198.51.100.9"},
	}

	for _, tc := range cases {
		rec := mwDo(mwRequest("/_bProxy/fingerprint", mwWithAPISecret(), mwWithRemoteAddr(tc.remote)))
		// The reported identity is the EXACT address, never the bucket: a log
		// row or an abuse report naming a /64 is useless.
		mwAssertBodyContains(t, rec, "IP: "+tc.wantIP+"\n")
		mwAssertBodyContains(t, rec, "Ratelimit Key: "+tc.wantKey+"\n")
	}

	firewall.Mutex.RLock()
	sameSlash64 := firewall.WindowAccessIps[mwTimestamp]["2001:db8:1:2::/64"]
	otherSlash64 := firewall.WindowAccessIps[mwTimestamp]["2001:db8:1:3::/64"]
	v4 := firewall.WindowAccessIps[mwTimestamp]["198.51.100.9"]
	mangled := firewall.WindowAccessIps[mwTimestamp]["[2001"]
	firewall.Mutex.RUnlock()

	if sameSlash64 != 2 {
		t.Errorf(`WindowAccessIps[%d]["2001:db8:1:2::/64"] = %d, want 2 (both addresses in one allocation count together)`, mwTimestamp, sameSlash64)
	}
	if otherSlash64 != 1 {
		t.Errorf(`WindowAccessIps[%d]["2001:db8:1:3::/64"] = %d, want 1 (a different allocation is a different bucket)`, mwTimestamp, otherSlash64)
	}
	if v4 != 2 {
		t.Errorf(`WindowAccessIps[%d]["198.51.100.9"] = %d, want 2 (the mapped and unmapped forms are one client)`, mwTimestamp, v4)
	}
	if mangled != 0 {
		t.Errorf(`WindowAccessIps[%d]["[2001"] = %d, want 0: the split-on-colon key is gone`, mwTimestamp, mangled)
	}
	if env.mwBackendHits() != 0 {
		t.Error("backend was reached for a reserved path")
	}
}

// An IPv6 client's clearance token is bound to its exact address, not to the
// /64 it is counted under. Binding a token to the bucket would let one host in
// a residential allocation solve one challenge and hand the cookie to every
// other address in it.
func TestMiddlewareIPv6TokensAreBoundToTheAddressNotTheBucket(t *testing.T) {
	env := mwNewEnv(t)
	env.mwSetStage(1)

	first := mwDo(mwRequest("/", mwWithRemoteAddr("[2001:db8:1:2::1]:51000")))
	second := mwDo(mwRequest("/", mwWithRemoteAddr("[2001:db8:1:2::2]:51001")))

	firstToken := mwTokenFromSetCookie(t, first)
	secondToken := mwTokenFromSetCookie(t, second)
	if firstToken == secondToken {
		t.Error("two addresses in one /64 were issued the same clearance token; the token is keyed on the ratelimit bucket, not the address")
	}

	// The neighbour's token must not clear this address.
	replayed := mwDo(mwRequest("/",
		mwWithRemoteAddr("[2001:db8:1:2::2]:51002"),
		mwWithCookie(mwStage1Cookie+"="+firstToken)))
	mwAssertStatus(t, replayed, http.StatusFound)
	if env.mwBackendHits() != 0 {
		t.Errorf("backend hits = %d, want 0: a neighbour's token cleared the challenge", env.mwBackendHits())
	}
}

// The encryption cache is keyed on ip+fingerprint+useragent+hour, so two
// different clients get different tokens and one client's token is reused.
func TestMiddlewareEncryptionCacheReuse(t *testing.T) {
	env := mwNewEnv(t)
	env.mwSetStage(1)

	first := mwDo(mwRequest("/")).Result().Header.Get("Set-Cookie")
	second := mwDo(mwRequest("/")).Result().Header.Get("Set-Cookie")
	if first != second {
		t.Errorf("token changed between requests from the same client:\n%s\n%s", first, second)
	}

	// A different user agent is a different cache key and a different token.
	other := mwDo(mwRequest("/", mwWithHeader("User-Agent", "another-agent"))).Result().Header.Get("Set-Cookie")
	if other == first {
		t.Error("a different user agent produced the same challenge token")
	}
	if env.mwBackendHits() != 0 {
		t.Error("backend was reached during stage-1 challenges")
	}
}

// ---------------------------------------------------------------------------
// shared counter state under concurrency
// ---------------------------------------------------------------------------

// Middleware's two counter bumps are read-modify-writes against the shared
// domains.DomainsData map:
//
//	firewall.Mutex.Lock()
//	...
//	domainData = domains.DomainsData[domainName]   // re-read UNDER the write lock
//	domainData.TotalRequests++
//	domains.DomainsData[domainName] = domainData
//	firewall.Mutex.Unlock()
//
// and the same shape again for BypassedRequests around utils.AddLogs. Two
// separate mistakes are cheap to make here and invisible to any single-threaded
// test:
//
//  1. reusing the copy already read under the earlier RLock instead of
//     re-reading under the write lock ("we already have that value"), which
//     reintroduces lost updates on the very counter checkAttack uses to decide
//     whether an attack is happening; and
//  2. dropping or mis-scoping one of the two critical sections, which is a
//     concurrent map write on domains.DomainsData and on the per-domain log
//     slice - a hard `fatal error: concurrent map writes` under load.
//
// Every request below targets /_bProxy/verified, which is served without a
// backend round trip: the counter bookkeeping is then a large share of each
// request, so an unsynchronised read-modify-write loses updates immediately
// rather than occasionally.
func TestMiddlewareConcurrentCountersAreExact(t *testing.T) {
	const (
		workers   = 16
		perWorker = 400
		total     = workers * perWorker
	)

	env := mwNewEnv(t)
	env.mwSetStage(0) // whitelisted: every request is counted AND bypassed

	// AddLogs appends without bound; ReadLogs (the TUI) is what trims. Raise
	// the cap so nothing in this test depends on log trimming.
	proxy.MaxLogLength = total + 1

	var wg sync.WaitGroup
	for w := range workers {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := range perWorker {
				// Distinct source ports, one shared source IP: every request
				// contends for the same DomainsData entry and the same window
				// buckets.
				addr := mwIP + ":" + strconv.Itoa(20000+w*perWorker+i)
				rec := httptest.NewRecorder()
				Middleware(rec, mwRequest("/_bProxy/verified", mwWithRemoteAddr(addr)))
				if body := rec.Body.String(); body != "verified" {
					t.Errorf("body = %q, want %q", mwTrunc(body, 80), "verified")
					return
				}
			}
		}(w)
	}
	wg.Wait()

	d := env.mwDomainData()
	if d.TotalRequests != total {
		t.Errorf("TotalRequests = %d, want %d: %d increments were lost, so the counter bump is not a read-modify-write against current shared state", d.TotalRequests, total, total-d.TotalRequests)
	}
	if d.BypassedRequests != total {
		t.Errorf("BypassedRequests = %d, want %d: %d increments were lost", d.BypassedRequests, total, total-d.BypassedRequests)
	}
	if len(d.LastLogs) != total {
		t.Errorf("LastLogs = %d entries, want %d: appends to the shared log slice were lost", len(d.LastLogs), total)
	}

	firewall.Mutex.RLock()
	access := firewall.WindowAccessIps[mwTimestamp][mwIP]
	cookie := firewall.WindowAccessIpsCookie[mwTimestamp][mwIP]
	firewall.Mutex.RUnlock()
	if access != total {
		t.Errorf("WindowAccessIps[%d][%s] = %d, want %d", mwTimestamp, mwIP, access, total)
	}
	// FLIPPED BY WAVE 6: stage 0 has no cookie to present, and a request that
	// was never challenged is no longer counted as having failed a challenge
	// (see TestMiddlewareWhitelistIsNotCountedAsAChallengeFailure). The write
	// is skipped entirely, so this is 0 rather than `total`.
	if cookie != 0 {
		t.Errorf("WindowAccessIpsCookie[%d][%s] = %d, want 0", mwTimestamp, mwIP, cookie)
	}
	if env.mwBackendHits() != 0 {
		t.Errorf("backend hits = %d, want 0 (/_bProxy/verified is served by the proxy)", env.mwBackendHits())
	}
}

// ---------------------------------------------------------------------------
// access-key construction (wave 5)
// ---------------------------------------------------------------------------

// mwTokenFromSetCookie pulls the clearance token out of a stage-1 challenge
// response.
func mwTokenFromSetCookie(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	raw := rec.Result().Header.Get("Set-Cookie")
	_, rest, found := strings.Cut(raw, "=")
	if !found {
		t.Fatalf("no Set-Cookie on the challenge response (got %q)", raw)
	}
	token, _, _ := strings.Cut(rest, ";")
	if token == "" {
		t.Fatalf("empty token in Set-Cookie %q", raw)
	}
	return token
}

// The access key used to be the bare concatenation
// ip + tlsFp + reqUa + proxy.CurrHourStr. With no delimiter, bytes move freely
// across the component boundaries, and proxy.CurrHourStr is a bare decimal
// hour: a client sending the user agent "<ua>1" during hour 3 is issued exactly
// the token that a client sending "<ua>" is issued during hour 13. The user
// agent is free for the attacker to choose, so he can mint clearance ten hours
// ahead and walk through the hourly OTP rotation that is meant to expire it.
//
// FIXED BY WAVE 5: every component is length-prefixed, so the boundaries are
// unambiguous.
func TestMiddlewareAccessKeyDoesNotMergeUserAgentIntoTheHour(t *testing.T) {
	env := mwNewEnv(t)
	env.mwSetStage(1)

	// Sanity: this pair really does collide under the old concatenation, so
	// the assertions below are not vacuous.
	if mwIP+mwFP+mwUA+"1"+"3" != mwIP+mwFP+mwUA+"13" {
		t.Fatal("fixture drifted: the two identities no longer collide under the old concatenation")
	}

	proxy.CurrHourStr = "3"
	premint := mwTokenFromSetCookie(t, mwDo(mwRequest("/", mwWithHeader("User-Agent", mwUA+"1"))))

	// Ten hours pass and the OTP bucket rotates.
	proxy.CurrHourStr = "13"
	current := mwTokenFromSetCookie(t, mwDo(mwRequest("/")))

	if premint == current {
		t.Fatal("a user agent ending in a digit pre-minted the next hour's token: the hour is still concatenated onto the user agent without a delimiter")
	}

	rec := mwDo(mwRequest("/", mwWithCookie(mwStage1Cookie+"="+premint)))
	mwAssertStatus(t, rec, http.StatusFound)
	if env.mwBackendHits() != 0 {
		t.Errorf("backend hits = %d, want 0: a pre-minted token cleared the challenge", env.mwBackendHits())
	}
}

// The proxy fronts many domains from one set of OTP secrets. Without the domain
// in the access key, a token minted against an idle endpoint - a domain nobody
// is attacking, which hands out stage-1 clearance to anyone who asks - is
// equally valid on a domain that has escalated under a flood.
//
// FIXED BY WAVE 5: the domain is a component of the access key.
func TestMiddlewareAccessKeyIsBoundToTheDomain(t *testing.T) {
	const idleDomain = "idle.test.local"

	env := mwNewEnv(t)
	env.mwSetStage(1)
	env.mwAddDomain(idleDomain, 1)

	minted := mwTokenFromSetCookie(t, mwDo(mwRequest("/", mwWithHost(idleDomain))))

	// Control: the token does clear the domain it was minted for.
	rec := mwDo(mwRequest("/", mwWithHost(idleDomain), mwWithCookie(mwStage1Cookie+"="+minted)))
	mwAssertStatus(t, rec, http.StatusOK)
	mwAssertBodyContains(t, rec, mwBackendBody)
	if env.mwBackendHits() != 1 {
		t.Fatalf("backend hits = %d, want 1: the token does not even clear its own domain", env.mwBackendHits())
	}

	// The attack: the same token against the domain under a flood.
	rec = mwDo(mwRequest("/", mwWithCookie(mwStage1Cookie+"="+minted)))
	mwAssertStatus(t, rec, http.StatusFound)
	mwAssertBodyNotContains(t, rec, mwBackendBody)
	if env.mwBackendHits() != 1 {
		t.Errorf("backend hits = %d, want 1: a token minted on %q cleared %q", env.mwBackendHits(), idleDomain, mwDomain)
	}
}

// accessKeyFor is an injective encoding of its arguments. mwAccessKeyFor is an
// independent re-implementation, so this pins the layout as well as the
// property: any pair of distinct component tuples must render to distinct keys,
// including the pairs the old concatenation collapsed.
func TestMiddlewareAccessKeyEncodingIsInjective(t *testing.T) {
	type identity struct {
		domain, ip, fp, ua, hour string
		susLv                    int
	}
	base := identity{mwDomain, mwIP, mwFP, mwUA, mwHourStr, 1}

	// Every pair below collided under the old key, either because bytes moved
	// across an undelimited component boundary or because the component was
	// not in the key at all.
	cases := []struct {
		name  string
		other identity
	}{
		{
			name:  "a digit moves from the user agent into the hour",
			other: identity{mwDomain, mwIP, mwFP, mwUA + "1", "3", 1},
		},
		{
			name:  "a byte moves from the fingerprint into the ip",
			other: identity{mwDomain, mwIP + mwFP[:1], mwFP[1:], mwUA, mwHourStr, 1},
		},
		{
			name:  "a byte moves from the user agent into the fingerprint",
			other: identity{mwDomain, mwIP, mwFP + mwUA[:1], mwUA[1:], mwHourStr, 1},
		},
		{
			name:  "a different domain, which the old key ignored entirely",
			other: identity{"other.test.local", mwIP, mwFP, mwUA, mwHourStr, 1},
		},
		{
			name:  "a different suspicion level, which the old key ignored entirely",
			other: identity{mwDomain, mwIP, mwFP, mwUA, mwHourStr, 3},
		},
		{
			name:  "whitelisted versus hard-blocked, which StageToString still renders identically",
			other: identity{mwDomain, mwIP, mwFP, mwUA, mwHourStr, 5},
		},
	}

	build := func(id identity) string {
		return accessKeyFor(id.domain, id.ip, id.fp, id.ua, id.hour, id.susLv)
	}
	oldBuild := func(id identity) string { return id.ip + id.fp + id.ua + id.hour }

	if got, want := build(base), mwAccessKey(1); got != want {
		t.Fatalf("accessKeyFor = %q, want %q", got, want)
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if oldBuild(base) != oldBuild(tc.other) {
				t.Error("the old concatenation did not collide on this pair: the fixture no longer demonstrates what it claims")
			}
			if build(base) == build(tc.other) {
				t.Errorf("accessKeyFor collapsed two distinct identities onto %q", build(base))
			}
		})
	}
}

// ---------------------------------------------------------------------------
// gated mitigation-state endpoints (wave 5)
// ---------------------------------------------------------------------------

// FIXED BY WAVE 5: /_bProxy/stats and /_bProxy/fingerprint were served to any
// client that cleared the challenge. stats reports live bypassed-r/s, which
// tells an attacker in real time whether his flood is getting through, plus the
// build fingerprint; fingerprint reports his own ratelimit counters and the
// proxy's view of his TLS fingerprint, which is a free oracle for tuning an
// evasion. Both now require the API secret, compared in constant time, and
// answer a plain 404 - not 401 or 403 - so the endpoints cannot be discovered
// by probing.
func TestMiddlewareMitigationStateEndpointsAreGated(t *testing.T) {
	leaks := map[string][]string{
		"/_bProxy/stats":       {"Bypassed R/s", "Total Requests", "Proxy Fingerprint", "mw-proxy-fingerprint"},
		"/_bProxy/fingerprint": {"IP Requests", "SusLV", "Fingerprint: "},
	}

	cases := []struct {
		name    string
		secret  string // configured proxy.APISecret, "" means leave the fixture's
		header  string
		allowed bool
	}{
		{name: "no header at all", allowed: false},
		{name: "wrong secret", header: "not-the-secret", allowed: false},
		{name: "a prefix of the secret", header: mwAPISecret[:len(mwAPISecret)-1], allowed: false},
		{name: "the secret with one byte appended", header: mwAPISecret + "x", allowed: false},
		{name: "the admin secret is not the api secret", header: mwAdminSecret, allowed: false},
		{name: "empty secret configured, empty header sent", secret: "-empty-", header: "", allowed: false},
		{name: "correct secret", header: mwAPISecret, allowed: true},
	}

	for path, leaked := range leaks {
		t.Run(path, func(t *testing.T) {
			for _, tc := range cases {
				t.Run(tc.name, func(t *testing.T) {
					env := mwNewEnv(t)
					env.mwSetStage(0)
					if tc.secret == "-empty-" {
						proxy.APISecret = ""
					}

					opts := []mwReqOpt{}
					if tc.header != "" {
						opts = append(opts, mwWithHeader("Proxy-Secret", tc.header))
					}
					rec := mwDo(mwRequest(path, opts...))

					if tc.allowed {
						mwAssertStatus(t, rec, http.StatusOK)
						mwAssertBodyContains(t, rec, leaked[0])
						return
					}

					mwAssertStatus(t, rec, http.StatusNotFound)
					if body := rec.Body.String(); body != "404 Not Found" {
						t.Errorf("body = %q, want exactly %q: an unauthorised probe must be indistinguishable from a missing endpoint", mwTrunc(body, 200), "404 Not Found")
					}
					if ct := rec.Result().Header.Get("Content-Type"); ct != "text/plain" {
						t.Errorf("Content-Type = %q, want text/plain", ct)
					}
					for _, secretish := range leaked {
						mwAssertBodyNotContains(t, rec, secretish)
					}
					if env.mwBackendHits() != 0 {
						t.Errorf("backend hits = %d, want 0: an unauthorised probe must not be proxied either", env.mwBackendHits())
					}
				})
			}
		})
	}
}

// The gate is the API secret, not the challenge: clearing the challenge is not
// enough, and the two other reserved endpoints stay open because the captcha
// page fetches /_bProxy/verified and the GPL requires /_bProxy/credits.
func TestMiddlewareUngatedReservedPathsStayOpen(t *testing.T) {
	for _, path := range []string{"/_bProxy/verified", "/_bProxy/credits"} {
		t.Run(path, func(t *testing.T) {
			env := mwNewEnv(t)
			env.mwSetStage(0)

			rec := mwDo(mwRequest(path))
			mwAssertStatus(t, rec, http.StatusOK)
			if env.mwBackendHits() != 0 {
				t.Errorf("backend hits = %d, want 0", env.mwBackendHits())
			}
		})
	}
}

// mwBody wraps a string as a request body.
func mwBody(s string) mwStringBody {
	return mwStringBody{Reader: strings.NewReader(s)}
}

type mwStringBody struct{ *strings.Reader }

func (mwStringBody) Close() error { return nil }

// ---------------------------------------------------------------------------
// client identity (wave 6)
// ---------------------------------------------------------------------------

// realClientIP is the single source of truth for the subject IP. These are unit
// tests of the resolution rule itself; the tests above pin what the rest of
// Middleware does with the answer.
func TestRealClientIP(t *testing.T) {
	cases := []struct {
		name    string
		trust   []string
		remote  string
		headers map[string]string
		// xff, when set, is sent as SEPARATE X-Forwarded-For header lines.
		xff  []string
		want string
	}{
		{
			name:   "no trusted proxies: the peer wins",
			remote: "203.0.113.7:51000",
			headers: map[string]string{
				"Cf-Connecting-Ip": "1.1.1.1",
				"X-Real-Ip":        "2.2.2.2",
				"X-Forwarded-For":  "3.3.3.3",
			},
			want: "203.0.113.7",
		},
		{
			name:    "an untrusted peer's Cf-Connecting-Ip is ignored",
			trust:   []string{"192.0.2.0/24"},
			remote:  "203.0.113.7:51000",
			headers: map[string]string{"Cf-Connecting-Ip": "1.1.1.1"},
			want:    "203.0.113.7",
		},
		{
			name:    "a trusted peer's Cf-Connecting-Ip is honoured",
			trust:   []string{"192.0.2.0/24"},
			remote:  "192.0.2.9:51000",
			headers: map[string]string{"Cf-Connecting-Ip": "1.1.1.1"},
			want:    "1.1.1.1",
		},
		{
			name:   "Cf-Connecting-Ip outranks X-Real-Ip and X-Forwarded-For",
			trust:  []string{"192.0.2.0/24"},
			remote: "192.0.2.9:51000",
			headers: map[string]string{
				"Cf-Connecting-Ip": "1.1.1.1",
				"X-Real-Ip":        "2.2.2.2",
			},
			xff:  []string{"3.3.3.3"},
			want: "1.1.1.1",
		},
		{
			name:    "X-Real-Ip is used when Cf-Connecting-Ip is absent",
			trust:   []string{"192.0.2.0/24"},
			remote:  "192.0.2.9:51000",
			headers: map[string]string{"X-Real-Ip": "2.2.2.2"},
			xff:     []string{"3.3.3.3"},
			want:    "2.2.2.2",
		},
		{
			name:   "a garbage Cf-Connecting-Ip falls through to the next source",
			trust:  []string{"192.0.2.0/24"},
			remote: "192.0.2.9:51000",
			headers: map[string]string{
				"Cf-Connecting-Ip": "not-an-address",
				"X-Real-Ip":        "2.2.2.2",
			},
			want: "2.2.2.2",
		},
		{
			name:   "a trusted peer that forwarded nothing falls back to itself",
			trust:  []string{"192.0.2.0/24"},
			remote: "192.0.2.9:51000",
			want:   "192.0.2.9",
		},

		// --- X-Forwarded-For element selection -------------------------------
		//
		// THE ELEMENT CHOICE IS THE WHOLE POINT. XFF reads left to right as
		// "client, first proxy, second proxy", and the leftmost element is
		// whatever the original client wrote - it is appended to by every hop
		// and verified by none. Taking the leftmost hands the attacker his own
		// ratelimit bucket, which is the bug this wave exists to remove. The
		// rightmost element that is not itself a trusted proxy is the last
		// value written by something we put there.
		{
			name:   "a single-element chain from a trusted peer is the client",
			trust:  []string{"192.0.2.0/24"},
			remote: "192.0.2.9:51000",
			xff:    []string{"1.1.1.1"},
			want:   "1.1.1.1",
		},
		{
			name:   "the client-forged leftmost element is NOT taken",
			trust:  []string{"192.0.2.0/24"},
			remote: "192.0.2.9:51000",
			// 9.9.9.9 is what the attacker wrote himself; 1.1.1.1 is what our
			// own edge observed and appended.
			xff:  []string{"9.9.9.9, 1.1.1.1"},
			want: "1.1.1.1",
		},
		{
			name:   "trailing trusted hops are skipped",
			trust:  []string{"192.0.2.0/24", "198.51.100.0/24"},
			remote: "192.0.2.9:51000",
			xff:    []string{"9.9.9.9, 1.1.1.1, 198.51.100.5, 198.51.100.6"},
			want:   "1.1.1.1",
		},
		{
			name:   "the chain may arrive as several header lines",
			trust:  []string{"192.0.2.0/24", "198.51.100.0/24"},
			remote: "192.0.2.9:51000",
			xff:    []string{"9.9.9.9, 1.1.1.1", "198.51.100.5"},
			want:   "1.1.1.1",
		},
		{
			name:   "an all-trusted chain falls back to the leftmost",
			trust:  []string{"192.0.2.0/24", "198.51.100.0/24"},
			remote: "192.0.2.9:51000",
			xff:    []string{"198.51.100.5, 198.51.100.6"},
			want:   "198.51.100.5",
		},
		{
			name:   "junk elements are skipped, not fatal",
			trust:  []string{"192.0.2.0/24"},
			remote: "192.0.2.9:51000",
			xff:    []string{"unknown, 1.1.1.1, _obfuscated"},
			want:   "1.1.1.1",
		},
		{
			name:   "bracketed and port-suffixed elements parse",
			trust:  []string{"192.0.2.0/24"},
			remote: "192.0.2.9:51000",
			xff:    []string{"9.9.9.9, [2001:db8::1]:4444"},
			want:   "2001:db8::1",
		},

		// --- canonicalisation ------------------------------------------------
		{
			name:   "an IPv6 peer is parsed, not split on the first colon",
			remote: "[2001:db8::1]:51000",
			want:   "2001:db8::1",
		},
		{
			name:   "a 4-in-6 mapped peer is unmapped",
			remote: "[::ffff:203.0.113.7]:51000",
			want:   "203.0.113.7",
		},
		{
			name:   "a zone is not part of the identity",
			remote: "[fe80::1%eth0]:51000",
			want:   "fe80::1",
		},
		{
			name:   "a RemoteAddr with no port still parses",
			remote: "203.0.113.7",
			want:   "203.0.113.7",
		},
		{
			name:   "an unparseable RemoteAddr yields the zero address",
			remote: "not-an-address",
			want:   "",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mwSaveGlobals(t)
			mwTrustPeers(t, tc.trust...)

			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.RemoteAddr = tc.remote
			for k, v := range tc.headers {
				req.Header.Set(k, v)
			}
			for _, v := range tc.xff {
				req.Header.Add("X-Forwarded-For", v)
			}

			if got := ipString(realClientIP(req)); got != tc.want {
				t.Errorf("realClientIP = %q, want %q", got, tc.want)
			}
		})
	}
}

// A trusted peer that is itself IPv4-mapped must still match a v4 trusted
// prefix, or a dual-stack listener would stop believing its own edge.
func TestRealClientIPTrustsAMappedPeer(t *testing.T) {
	mwSaveGlobals(t)
	mwTrustPeers(t, "192.0.2.0/24")

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "[::ffff:192.0.2.9]:51000"
	req.Header.Set("Cf-Connecting-Ip", "1.1.1.1")

	if got := ipString(realClientIP(req)); got != "1.1.1.1" {
		t.Errorf("realClientIP = %q, want 1.1.1.1: a 4-in-6 mapped trusted peer was not recognised", got)
	}
}

func TestRatelimitKey(t *testing.T) {
	cases := []struct{ in, want string }{
		{"203.0.113.7", "203.0.113.7"},
		{"2001:db8:1:2::1", "2001:db8:1:2::/64"},
		{"2001:db8:1:2:ffff:ffff:ffff:ffff", "2001:db8:1:2::/64"},
		{"2001:db8:1:3::1", "2001:db8:1:3::/64"},
		{"::1", "::/64"},
	}
	for _, tc := range cases {
		addr, err := netip.ParseAddr(tc.in)
		if err != nil {
			t.Fatalf("ParseAddr(%q): %v", tc.in, err)
		}
		if got := ratelimitKey(addr); got != tc.want {
			t.Errorf("ratelimitKey(%s) = %q, want %q", tc.in, got, tc.want)
		}
	}
	if got := ratelimitKey(netip.Addr{}); got != "" {
		t.Errorf("ratelimitKey(zero) = %q, want %q", got, "")
	}
}

// ---------------------------------------------------------------------------
// hard limits at the top of Middleware (wave 6)
// ---------------------------------------------------------------------------

// CONNECT asks a proxy to splice a socket to an arbitrary host:port.
// httputil.ReverseProxy forwards the method verbatim, so without this the
// mitigation front end can be driven as an open tunnel - traffic leaving from
// the proxy's address, with the proxy's reputation.
func TestMiddlewareRejectsConnect(t *testing.T) {
	env := mwNewEnv(t)
	env.mwSetStage(0) // whitelisted: nothing but the CONNECT guard can refuse it

	req := httptest.NewRequest(http.MethodConnect, "/", nil)
	req.Host = mwDomain
	req.RemoteAddr = mwRemoteAddr
	rec := mwDo(req)

	mwAssertStatus(t, rec, http.StatusMethodNotAllowed)
	mwAssertBodyContains(t, rec, "405 Method Not Allowed")
	if env.mwBackendHits() != 0 {
		t.Error("a CONNECT request was proxied to the backend")
	}

	// The guard sits above ALL bookkeeping: a refused CONNECT must not move a
	// counter, take the window lock or issue a token.
	if got := env.mwDomainData().TotalRequests; got != 0 {
		t.Errorf("TotalRequests = %d, want 0: CONNECT was counted before it was refused", got)
	}
	firewall.Mutex.RLock()
	access := len(firewall.WindowAccessIps[mwTimestamp])
	firewall.Mutex.RUnlock()
	if access != 0 {
		t.Errorf("WindowAccessIps has %d entries, want 0", access)
	}
	if sc := rec.Result().Header.Get("Set-Cookie"); sc != "" {
		t.Errorf("Set-Cookie = %q, want empty", sc)
	}
}

// The body cap. A client that sends more than it is allowed gets its read
// truncated, which the reverse proxy surfaces as a failed upstream request
// rather than streaming an unbounded body at the customer origin.
func TestMiddlewareCapsTheRequestBody(t *testing.T) {
	mwPost := func(size int) *http.Request {
		req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(strings.Repeat("a", size)))
		req.Host = mwDomain
		req.RemoteAddr = mwRemoteAddr
		req.Header.Set("User-Agent", mwUA)
		return req
	}

	t.Run("a body under the limit is proxied", func(t *testing.T) {
		env := mwNewEnv(t)
		env.mwSetStage(0)
		MaxRequestBodyBytes.Store(64)

		rec := mwDo(mwPost(32))

		mwAssertStatus(t, rec, http.StatusOK)
		mwAssertBodyContains(t, rec, mwBackendBody)
		if env.mwBackendHits() != 1 {
			t.Errorf("backend hits = %d, want 1", env.mwBackendHits())
		}
	})

	t.Run("a body over the limit does not reach the backend intact", func(t *testing.T) {
		env := mwNewEnv(t)
		env.mwSetStage(0)
		MaxRequestBodyBytes.Store(16)

		rec := mwDo(mwPost(4096))

		// The upstream request is aborted mid-body, which core/transport turns
		// into its error page. Asserted on the body rather than the status
		// because that error page is served with 200 - a separate defect, owned
		// by the wave that makes error responses honest.
		mwAssertBodyContains(t, rec, "request body too large")
		if env.mwBackendHits() != 0 {
			t.Errorf("backend hits = %d, want 0: the oversized body was delivered", env.mwBackendHits())
		}
	})

	t.Run("a zero limit disables the cap", func(t *testing.T) {
		env := mwNewEnv(t)
		env.mwSetStage(0)
		MaxRequestBodyBytes.Store(0)

		rec := mwDo(mwPost(4096))

		mwAssertStatus(t, rec, http.StatusOK)
		if env.mwBackendHits() != 1 {
			t.Errorf("backend hits = %d, want 1", env.mwBackendHits())
		}
	})
}
