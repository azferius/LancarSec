package api

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/azferius/lancarsec/core/domains"
	"github.com/azferius/lancarsec/core/firewall"
	"github.com/azferius/lancarsec/core/proxy"
)

// ---------------------------------------------------------------------------
// fixtures
//
// Everything this package reads is process-global (proxy.APISecret, the
// domains tables, the firewall counters), so no test here may run in parallel
// and every test restores what it touched.
// ---------------------------------------------------------------------------

const (
	apiSecret = "test-api-secret-0123456789"
	apiDomain = "example.com"
	// A token of the shape firewall.CacheIps actually stores. No response body
	// may ever contain it.
	apiCacheToken = "CACHED-CLEARANCE-TOKEN-MUST-NEVER-LEAK"
	apiCacheKey   = "1.2.3.4|fp|ua|09|3"
	apiClientIP   = "203.0.113.77"
)

// apiEnv installs a known secret, one domain, and a populated firewall state,
// and restores the previous globals when the test ends.
func apiEnv(t *testing.T) {
	t.Helper()

	oldSecret := proxy.APISecret
	oldCPU, oldRAM := proxy.CpuUsage(), proxy.RamUsage()
	oldDelay, oldLimit := authFailDelay, authFailDelayLimit

	proxy.APISecret = apiSecret
	proxy.SetCpuUsage("12.5%")
	proxy.SetRamUsage("34.5%")
	// The delay is exercised by its own tests; everywhere else it would only
	// add wall-clock time.
	authFailDelay = 0

	domains.DomainsMap.Store(apiDomain, domains.DomainSettings{
		Name: apiDomain,
		RawCustomRules: []domains.JsonRule{
			{Expression: "ip.src eq 1.1.1.1", Action: "3"},
		},
	})
	domains.DomainsData[apiDomain] = domains.DomainData{
		Name:                      apiDomain,
		TotalRequests:             41,
		BypassedRequests:          17,
		RequestsPerSecond:         7,
		RequestsBypassedPerSecond: 3,
		LastLogs:                  []domains.DomainLog{{IP: apiClientIP, Path: "/login"}},
	}

	firewall.Mutex.Lock()
	oldAccess, oldCookie, oldFps := firewall.AccessIps, firewall.AccessIpsCookie, firewall.UnkFps
	firewall.AccessIps = map[string]int{apiClientIP: 12, "198.51.100.9": 5}
	firewall.AccessIpsCookie = map[string]int{apiClientIP: 4}
	firewall.UnkFps = map[string]int{"unknown-fingerprint": 9}
	firewall.Mutex.Unlock()

	firewall.CacheIps.Store(apiCacheKey, apiCacheToken)

	t.Cleanup(func() {
		proxy.APISecret = oldSecret
		proxy.SetCpuUsage(oldCPU)
		proxy.SetRamUsage(oldRAM)
		authFailDelay, authFailDelayLimit = oldDelay, oldLimit

		domains.DomainsMap.Delete(apiDomain)
		delete(domains.DomainsData, apiDomain)

		firewall.Mutex.Lock()
		firewall.AccessIps, firewall.AccessIpsCookie, firewall.UnkFps = oldAccess, oldCookie, oldFps
		firewall.Mutex.Unlock()

		firewall.CacheIps.Range(func(key, _ any) bool {
			firewall.CacheIps.Delete(key)
			return true
		})
	})
}

// apiV1 drives the v1 entry point. body is sent verbatim.
func apiV1(t *testing.T, secret, body string) (*httptest.ResponseRecorder, bool) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/_lancarsec/api/v1", strings.NewReader(body))
	if secret != "" {
		req.Header.Set("proxy-secret", secret)
	}
	rec := httptest.NewRecorder()
	handled := Process(rec, req, domains.DomainData{Name: "other.example", TotalRequests: 999999})
	return rec, handled
}

// apiV2 drives the v2 entry point at the given path suffix.
func apiV2(t *testing.T, secret, path string) (*httptest.ResponseRecorder, bool) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	if secret != "" {
		req.Header.Set("Proxy-Secret", secret)
	}
	rec := httptest.NewRecorder()
	handled := ProcessV2(rec, req)
	return rec, handled
}

type apiResult struct {
	Success bool           `json:"success"`
	Results map[string]any `json:"results"`
}

func apiDecode(t *testing.T, rec *httptest.ResponseRecorder) apiResult {
	t.Helper()
	var out apiResult
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode response: %v (body %q)", err, rec.Body.String())
	}
	return out
}

func apiAssertError(t *testing.T, rec *httptest.ResponseRecorder, want string) {
	t.Helper()
	res := apiDecode(t, rec)
	if res.Success {
		t.Errorf("success = true, want false (body %q)", rec.Body.String())
	}
	if got := res.Results["ERROR"]; got != want {
		t.Errorf("ERROR = %v, want %q (body %q)", got, want, rec.Body.String())
	}
}

// errReader models a body that dies mid-read: the client announced more bytes
// than it delivered and then went away.
type errReader struct {
	prefix string
	read   bool
}

func (e *errReader) Read(p []byte) (int, error) {
	if !e.read {
		e.read = true
		n := copy(p, e.prefix)
		return n, nil
	}
	return 0, io.ErrUnexpectedEOF
}

// ---------------------------------------------------------------------------
// authentication
// ---------------------------------------------------------------------------

func TestAuthAcceptsTheConfiguredSecret(t *testing.T) {
	apiEnv(t)

	t.Run("v1", func(t *testing.T) {
		rec, handled := apiV1(t, apiSecret, `{"action":"GET_PROXY_STATS"}`)
		if !handled {
			t.Fatal("Process returned false for an authenticated request")
		}
		if rec.Code != http.StatusOK {
			t.Errorf("status = %d, want 200", rec.Code)
		}
		res := apiDecode(t, rec)
		if !res.Success || res.Results["CPU_USAGE"] != "12.5%" {
			t.Errorf("results = %v", res.Results)
		}
	})

	t.Run("v2", func(t *testing.T) {
		rec, handled := apiV2(t, apiSecret, apiV2Prefix+"/GET_PROXY_STATS")
		if !handled {
			t.Fatal("ProcessV2 returned false for an authenticated request")
		}
		res := apiDecode(t, rec)
		if !res.Success || res.Results["RAM_USAGE"] != "34.5%" {
			t.Errorf("results = %v", res.Results)
		}
	})
}

// A wrong secret must produce a 404 and must NOT be reported back to the
// caller as unhandled. Returning false let core/server proxy the request to the
// customer backend, which (a) handed proxy.AdminSecret - it is in the v1 URL -
// to the backend and every log behind it, and (b) made the admin surface
// discoverable by response-code differencing without guessing anything.
func TestAuthRejectionIs404AndIsHandled(t *testing.T) {
	apiEnv(t)

	cases := []struct {
		name   string
		secret string
	}{
		{"no header at all", ""},
		{"wrong secret", "not-the-secret"},
		{"correct prefix", apiSecret[:len(apiSecret)-1]},
		{"correct secret plus one byte", apiSecret + "x"},
		{"differs in the first byte only", "Xest-api-secret-0123456789"},
		{"differs in the last byte only", "test-api-secret-012345678X"},
		{"case flipped", strings.ToUpper(apiSecret)},
		{"padded with whitespace", " " + apiSecret + " "},
		{"very long", strings.Repeat("a", 4096)},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for _, entry := range []struct {
				name string
				run  func() (*httptest.ResponseRecorder, bool)
			}{
				{"v1", func() (*httptest.ResponseRecorder, bool) {
					return apiV1(t, tc.secret, `{"action":"GET_PROXY_STATS"}`)
				}},
				{"v2", func() (*httptest.ResponseRecorder, bool) {
					return apiV2(t, tc.secret, apiV2Prefix+"/GET_PROXY_STATS")
				}},
			} {
				t.Run(entry.name, func(t *testing.T) {
					rec, handled := entry.run()

					if !handled {
						t.Fatal("returned false: an auth failure must be handled here, not proxied to the backend")
					}
					if rec.Code != http.StatusNotFound {
						t.Errorf("status = %d, want 404", rec.Code)
					}
					if ct := rec.Result().Header.Get("Content-Type"); strings.Contains(ct, "application/json") {
						t.Errorf("Content-Type = %q: a rejection must not look like an api response", ct)
					}
					body := rec.Body.String()
					if strings.Contains(body, "CPU_USAGE") || strings.Contains(body, "ERR_") {
						t.Errorf("rejection body leaks api detail: %q", body)
					}
				})
			}
		})
	}
}

// Rejections must be indistinguishable from each other. A near-miss secret and
// a random one produce byte-identical answers, so the response carries no
// signal about how close a guess was.
func TestAuthRejectionsAreIndistinguishable(t *testing.T) {
	apiEnv(t)

	reference, _ := apiV2(t, "completely-wrong", apiV2Prefix+"/GET_PROXY_STATS")
	wantCode, wantBody := reference.Code, reference.Body.String()

	for _, secret := range []string{
		"",
		apiSecret[:1],
		apiSecret[:len(apiSecret)-1],
		apiSecret + "!",
		strings.Repeat("z", len(apiSecret)),
	} {
		rec, _ := apiV2(t, secret, apiV2Prefix+"/GET_PROXY_STATS")
		if rec.Code != wantCode || rec.Body.String() != wantBody {
			t.Errorf("rejection for %q = %d/%q, want %d/%q: rejections must not be distinguishable",
				secret, rec.Code, rec.Body.String(), wantCode, wantBody)
		}
	}
}

// authenticate is the constant-time comparison itself. The timing property is
// not observable from a test - crypto/subtle over two fixed-size SHA-256
// digests is what provides it, and there is no black-box assertion that can
// prove a comparison did not short-circuit. What is observable, and what this
// pins, is that acceptance depends on the WHOLE secret: no prefix, suffix,
// substring, length or case-insensitive match is ever accepted. That is what
// kills the mutations a plain string comparison would let through
// (strings.HasPrefix, strings.Contains, EqualFold, a length-only check).
func TestAuthenticateMatchesTheWholeSecretOnly(t *testing.T) {
	apiEnv(t)

	accept := func(secret string) bool {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		if secret != "" {
			req.Header.Set("Proxy-Secret", secret)
		}
		return authenticate(req)
	}

	if !accept(apiSecret) {
		t.Fatal("the exact secret was rejected")
	}
	for _, bad := range []string{
		"",
		apiSecret[:len(apiSecret)-1],        // prefix
		apiSecret[1:],                       // suffix
		apiSecret[2 : len(apiSecret)-2],     // substring
		apiSecret + apiSecret,               // superstring
		strings.ToUpper(apiSecret),          // case
		strings.Repeat("x", len(apiSecret)), // same length, no shared bytes
	} {
		if accept(bad) {
			t.Errorf("accepted %q, want rejected", bad)
		}
	}
}

// An absent apisecret key used to leave the admin API wide open: Header.Get
// returns "" for a missing header, so `"" != ""` was false and the guard let
// every request through. Config validation rejects a CHANGE_ME secret but does
// not require the key to exist, so an omitted key must not be the softer
// failure.
func TestAuthEmptySecretDeniesEveryone(t *testing.T) {
	apiEnv(t)
	proxy.APISecret = ""

	for _, secret := range []string{"", "anything", apiSecret} {
		t.Run("v1 "+secret, func(t *testing.T) {
			rec, handled := apiV1(t, secret, `{"action":"GET_PROXY_STATS"}`)
			if !handled || rec.Code != http.StatusNotFound {
				t.Errorf("handled = %v, status = %d, want true/404 with no api secret configured", handled, rec.Code)
			}
			if strings.Contains(rec.Body.String(), "CPU_USAGE") {
				t.Errorf("an unconfigured api secret served an admin action: %q", rec.Body.String())
			}
		})
		t.Run("v2 "+secret, func(t *testing.T) {
			rec, handled := apiV2(t, secret, apiV2Prefix+"/GET_PROXY_STATS")
			if !handled || rec.Code != http.StatusNotFound {
				t.Errorf("handled = %v, status = %d, want true/404 with no api secret configured", handled, rec.Code)
			}
		})
	}

	// The whitespace-only case: a config with `"apisecret": " "` is a real
	// secret as far as this package is concerned - it is not our job to guess
	// intent - but it must still not match an absent header.
	proxy.APISecret = " "
	if rec, _ := apiV2(t, "", apiV2Prefix+"/GET_PROXY_STATS"); rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404: an absent header must not match a non-empty secret", rec.Code)
	}
}

// ---------------------------------------------------------------------------
// the auth-failure penalty
// ---------------------------------------------------------------------------

func TestAuthFailureIsDelayed(t *testing.T) {
	apiEnv(t)
	authFailDelay = 80 * time.Millisecond

	start := time.Now()
	rec, _ := apiV2(t, "wrong", apiV2Prefix+"/GET_PROXY_STATS")
	elapsed := time.Since(start)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
	if elapsed < authFailDelay {
		t.Errorf("rejection took %v, want at least %v: failed auth must be slowed down", elapsed, authFailDelay)
	}
}

func TestAuthSuccessIsNotDelayed(t *testing.T) {
	apiEnv(t)
	authFailDelay = 2 * time.Second

	start := time.Now()
	rec, _ := apiV2(t, apiSecret, apiV2Prefix+"/GET_PROXY_STATS")
	elapsed := time.Since(start)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if elapsed > time.Second {
		t.Errorf("an authenticated call took %v: the penalty must only apply to failures", elapsed)
	}
}

// The penalty must never become the amplification vector. Beyond
// authFailDelayLimit concurrent rejections the delay is skipped entirely, so a
// flood of bad secrets cannot park an unbounded number of goroutines on a proxy
// whose whole job is absorbing floods.
func TestAuthFailureDelayIsBounded(t *testing.T) {
	apiEnv(t)
	authFailDelay = 750 * time.Millisecond
	authFailDelayLimit = 1

	// Occupy the single slot, then confirm the next rejection is not delayed at
	// all. Without the cap every rejection sleeps, so an attacker parks one
	// goroutine and one socket per bad guess for as long as he likes.
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		apiV2(t, "wrong", apiV2Prefix+"/GET_PROXY_STATS")
	}()

	deadline := time.Now().Add(2 * time.Second)
	for authFailDelayInFlight.Load() < authFailDelayLimit {
		if time.Now().After(deadline) {
			t.Fatal("the first rejection never entered the penalty")
		}
		time.Sleep(time.Millisecond)
	}

	start := time.Now()
	rec, _ := apiV2(t, "wrong", apiV2Prefix+"/GET_PROXY_STATS")
	overflow := time.Since(start)

	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404: the rejection itself must not change under load", rec.Code)
	}
	if overflow > authFailDelay/3 {
		t.Errorf("a rejection past the in-flight cap took %v (delay is %v): beyond the cap the penalty must be skipped entirely, or it becomes the amplification vector",
			overflow, authFailDelay)
	}
	if got := authFailDelayInFlight.Load(); got > authFailDelayLimit {
		t.Errorf("in-flight penalty counter = %d, want at most %d", got, authFailDelayLimit)
	}

	wg.Wait()
	if got := authFailDelayInFlight.Load(); got != 0 {
		t.Errorf("in-flight penalty counter = %d after all callers returned, want 0", got)
	}
}

// A flood of rejections must not queue behind each other either: the penalty
// is a fixed cost paid concurrently, never a serial one.
func TestAuthFailureDelayDoesNotSerialise(t *testing.T) {
	apiEnv(t)
	authFailDelay = 300 * time.Millisecond
	authFailDelayLimit = 16

	const callers = 8
	var wg sync.WaitGroup
	wg.Add(callers)

	start := time.Now()
	for range callers {
		go func() {
			defer wg.Done()
			apiV2(t, "wrong", apiV2Prefix+"/GET_PROXY_STATS")
		}()
	}
	wg.Wait()

	// A queueing implementation would take callers*delay = 2.4s.
	if elapsed := time.Since(start); elapsed > 3*authFailDelay {
		t.Errorf("%d concurrent rejections took %v, want about %v", callers, elapsed, authFailDelay)
	}
}

// A client that hangs up must not keep a goroutine parked for the full penalty.
func TestAuthFailureDelayStopsWhenTheClientGoesAway(t *testing.T) {
	apiEnv(t)
	authFailDelay = 5 * time.Second

	req := httptest.NewRequest(http.MethodGet, apiV2Prefix+"/GET_PROXY_STATS", nil)
	req.Header.Set("Proxy-Secret", "wrong")
	ctx, cancel := context.WithCancel(req.Context())
	cancel()
	req = req.WithContext(ctx)

	start := time.Now()
	ProcessV2(httptest.NewRecorder(), req)
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("rejection of a cancelled request took %v, want immediate", elapsed)
	}
}

// ---------------------------------------------------------------------------
// deleted actions
// ---------------------------------------------------------------------------

// GET_IP_CACHE dumped firewall.CacheIps, whose values are the live challenge
// tokens every visitor is presenting. FILL_IP_CACHE held the global firewall
// write lock across 19980 random-string builds, freezing every request on every
// domain. RELOAD locked and immediately unlocked and reloaded nothing.
func TestDeletedActionsAreGone(t *testing.T) {
	apiEnv(t)

	for _, action := range []string{"GET_IP_CACHE", "FILL_IP_CACHE", "RELOAD"} {
		t.Run(action, func(t *testing.T) {
			rec, handled := apiV2(t, apiSecret, apiV2Prefix+"/"+action)
			if !handled {
				t.Fatal("returned false")
			}
			apiAssertError(t, rec, ERR_ACTION_NOT_FOUND)

			rec, _ = apiV1(t, apiSecret, `{"action":"`+action+`"}`)
			apiAssertError(t, rec, ERR_ACTION_NOT_FOUND)
		})
	}
}

// No action, present or future, may put a cached clearance token in a response
// body. This sweeps every action name the package knows about rather than only
// the deleted one, so reintroducing the dump under a new name fails here too.
func TestNoActionLeaksACachedClearanceToken(t *testing.T) {
	apiEnv(t)

	actions := []string{
		"GET_PROXY_STATS", "GET_PROXY_STATS_CPU_USAGE", "GET_PROXY_STATS_RAM_USAGE",
		"GET_IP_REQUESTS", "GET_FINGERPRINT_REQUESTS",
		"GET_IP_CACHE", "FILL_IP_CACHE", "RELOAD",
		"GET_TOTAL_REQUESTS", "GET_BYPASSED_REQUESTS", "GET_FIREWALL_RULES", "GET_LOGS",
	}

	for _, action := range actions {
		for _, path := range []string{apiV2Prefix + "/" + action, apiV2Prefix + "/" + apiDomain + "/" + action} {
			rec, _ := apiV2(t, apiSecret, path)
			if body := rec.Body.String(); strings.Contains(body, apiCacheToken) || strings.Contains(body, apiCacheKey) {
				t.Errorf("%s leaked cache material: %q", path, body)
			}
		}
	}
}

// FILL_IP_CACHE must not merely be renamed away: nothing may write to the
// cache from the API at all.
func TestFillIPCacheNoLongerWritesToTheCache(t *testing.T) {
	apiEnv(t)

	before := 0
	firewall.CacheIps.Range(func(_, _ any) bool { before++; return true })

	start := time.Now()
	apiV2(t, apiSecret, apiV2Prefix+"/FILL_IP_CACHE")
	elapsed := time.Since(start)

	after := 0
	firewall.CacheIps.Range(func(_, _ any) bool { after++; return true })

	if after != before {
		t.Errorf("cache size %d -> %d: the api must not write to firewall.CacheIps", before, after)
	}
	if elapsed > time.Second {
		t.Errorf("FILL_IP_CACHE took %v: it must not be doing work under the global lock", elapsed)
	}
}

// ---------------------------------------------------------------------------
// surviving proxy actions
// ---------------------------------------------------------------------------

func TestProxyActions(t *testing.T) {
	apiEnv(t)

	t.Run("GET_PROXY_STATS", func(t *testing.T) {
		rec, _ := apiV2(t, apiSecret, apiV2Prefix+"/GET_PROXY_STATS")
		res := apiDecode(t, rec)
		if !res.Success || res.Results["CPU_USAGE"] != "12.5%" || res.Results["RAM_USAGE"] != "34.5%" {
			t.Errorf("results = %v", res.Results)
		}
	})

	t.Run("GET_PROXY_STATS_CPU_USAGE", func(t *testing.T) {
		rec, _ := apiV2(t, apiSecret, apiV2Prefix+"/GET_PROXY_STATS_CPU_USAGE")
		res := apiDecode(t, rec)
		if res.Results["CPU_USAGE"] != "12.5%" {
			t.Errorf("results = %v", res.Results)
		}
		if _, ok := res.Results["RAM_USAGE"]; ok {
			t.Errorf("cpu-only action returned RAM_USAGE: %v", res.Results)
		}
	})

	t.Run("GET_PROXY_STATS_RAM_USAGE", func(t *testing.T) {
		rec, _ := apiV2(t, apiSecret, apiV2Prefix+"/GET_PROXY_STATS_RAM_USAGE")
		res := apiDecode(t, rec)
		if res.Results["RAM_USAGE"] != "34.5%" {
			t.Errorf("results = %v", res.Results)
		}
		if _, ok := res.Results["CPU_USAGE"]; ok {
			t.Errorf("ram-only action returned CPU_USAGE: %v", res.Results)
		}
	})
}

// GET_IP_REQUESTS returns aggregates. It used to return the AccessIps and
// AccessIpsCookie maps verbatim - a roster of every client IP on the proxy with
// its request count - and it marshalled those live maps after releasing the
// lock.
func TestGetIPRequestsReturnsCountsNotAddresses(t *testing.T) {
	apiEnv(t)

	rec, _ := apiV2(t, apiSecret, apiV2Prefix+"/GET_IP_REQUESTS")
	res := apiDecode(t, rec)
	if !res.Success {
		t.Fatalf("success = false: %q", rec.Body.String())
	}

	// 2 addresses, 12+5 requests; 1 challenged address, 4 requests.
	for key, want := range map[string]float64{
		"TOTAL_IPS":             2,
		"TOTAL_IP_REQUESTS":     17,
		"CHALLENGE_IPS":         1,
		"CHALLENGE_IP_REQUESTS": 4,
	} {
		if got := res.Results[key]; got != want {
			t.Errorf("%s = %v, want %v (body %q)", key, got, want, rec.Body.String())
		}
	}

	for _, ip := range []string{apiClientIP, "198.51.100.9"} {
		if strings.Contains(rec.Body.String(), ip) {
			t.Errorf("response contains client address %q: %q", ip, rec.Body.String())
		}
	}
}

// The two counters must not be interchangeable: swapping them would make a
// fully challenged population read as a fully bypassing one.
func TestGetIPRequestsKeepsTotalAndChallengeSeparate(t *testing.T) {
	apiEnv(t)

	rec, _ := apiV2(t, apiSecret, apiV2Prefix+"/GET_IP_REQUESTS")
	res := apiDecode(t, rec)
	if res.Results["TOTAL_IP_REQUESTS"] == res.Results["CHALLENGE_IP_REQUESTS"] {
		t.Fatalf("fixture drifted: the two counters must be unequal, got %v", res.Results)
	}
	if res.Results["TOTAL_IP_REQUESTS"].(float64) < res.Results["CHALLENGE_IP_REQUESTS"].(float64) {
		t.Errorf("total (%v) < challenge (%v): the counters are swapped",
			res.Results["TOTAL_IP_REQUESTS"], res.Results["CHALLENGE_IP_REQUESTS"])
	}
}

// GET_FINGERPRINT_REQUESTS keeps its map - a TLS fingerprint identifies client
// software, not a client - unlike GET_IP_REQUESTS, which is now aggregates only.
func TestGetFingerprintRequestsReturnsTheCounts(t *testing.T) {
	apiEnv(t)

	rec, _ := apiV2(t, apiSecret, apiV2Prefix+"/GET_FINGERPRINT_REQUESTS")
	res := apiDecode(t, rec)
	fps, ok := res.Results["TOTAL_FINGERPRINT_REQUESTS"].(map[string]any)
	if !ok {
		t.Fatalf("TOTAL_FINGERPRINT_REQUESTS = %v, want a map", res.Results["TOTAL_FINGERPRINT_REQUESTS"])
	}
	if fps["unknown-fingerprint"] != float64(9) {
		t.Errorf("fingerprint counts = %v", fps)
	}
}

// The counter maps must be snapshotted or aggregated while the lock is held,
// never marshalled live. The old code copied the map HEADER under RLock,
// released the lock, and let encoding/json walk the live map - which is only
// safe because evaluateRatelimit happens to replace these maps wholesale rather
// than mutate them, a property this package must not depend on. The moment
// anything writes in place, that is a concurrent map iteration and write:
// a fatal error net/http's handler recover cannot catch.
//
// There is no way to assert "the lock was held" directly, so this drives the
// actions against a live writer and lets -race adjudicate. Reverting either
// handler to publish the live map makes this fail under -race.
func TestCounterActionsDoNotMarshalLiveMaps(t *testing.T) {
	apiEnv(t)

	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-stop:
				return
			default:
			}
			firewall.Mutex.Lock()
			firewall.UnkFps["churn"]++
			firewall.AccessIps["churn"]++
			firewall.AccessIpsCookie["churn"]++
			firewall.Mutex.Unlock()
		}
	}()

	for range 200 {
		apiV2(t, apiSecret, apiV2Prefix+"/GET_FINGERPRINT_REQUESTS")
		apiV2(t, apiSecret, apiV2Prefix+"/GET_IP_REQUESTS")
	}

	close(stop)
	<-done
}

// ---------------------------------------------------------------------------
// domain actions
// ---------------------------------------------------------------------------

func TestDomainActionsV2(t *testing.T) {
	apiEnv(t)

	cases := []struct {
		action string
		key    string
		want   any
	}{
		{"GET_TOTAL_REQUESTS", "TOTAL_REQUESTS", float64(41)},
		{"GET_BYPASSED_REQUESTS", "BYPASSED_REQUESTS", float64(17)},
		{"GET_TOTAL_REQUESTS_PER_SECOND", "TOTAL_REQUESTS_REQUESTS_PER_SECOND", float64(7)},
		{"GET_BYPASSED_REQUESTS_PER_SECOND", "BYPASSED_REQUESTS_REQUESTS_PER_SECOND", float64(3)},
	}

	for _, tc := range cases {
		t.Run(tc.action, func(t *testing.T) {
			rec, handled := apiV2(t, apiSecret, apiV2Prefix+"/"+apiDomain+"/"+tc.action)
			if !handled {
				t.Fatal("returned false")
			}
			res := apiDecode(t, rec)
			if !res.Success {
				t.Fatalf("success = false: %q", rec.Body.String())
			}
			if got := res.Results[tc.key]; got != tc.want {
				t.Errorf("%s = %v, want %v", tc.key, got, tc.want)
			}
		})
	}

	t.Run("GET_FIREWALL_RULES", func(t *testing.T) {
		rec, _ := apiV2(t, apiSecret, apiV2Prefix+"/"+apiDomain+"/GET_FIREWALL_RULES")
		if !strings.Contains(rec.Body.String(), "ip.src eq 1.1.1.1") {
			t.Errorf("body = %q, want the configured rule", rec.Body.String())
		}
	})

	t.Run("GET_LOGS", func(t *testing.T) {
		rec, _ := apiV2(t, apiSecret, apiV2Prefix+"/"+apiDomain+"/GET_LOGS")
		if !strings.Contains(rec.Body.String(), "/login") {
			t.Errorf("body = %q, want the logged request", rec.Body.String())
		}
	})

	t.Run("unknown domain", func(t *testing.T) {
		rec, handled := apiV2(t, apiSecret, apiV2Prefix+"/nope.invalid/GET_TOTAL_REQUESTS")
		if !handled {
			t.Fatal("returned false")
		}
		apiAssertError(t, rec, ERR_DOMAIN_NOT_FOUND)
	})

	t.Run("unknown action on a known domain", func(t *testing.T) {
		rec, _ := apiV2(t, apiSecret, apiV2Prefix+"/"+apiDomain+"/NOT_AN_ACTION")
		apiAssertError(t, rec, ERR_ACTION_NOT_FOUND)
	})
}

// v1 used to answer domain queries with the counters of whatever domain the
// request happened to ARRIVE on, ignoring the domain the caller named. The
// fixture's caller-domain snapshot carries a deliberately absurd request count
// so the confusion cannot pass unnoticed.
func TestV1DomainActionsUseTheRequestedDomain(t *testing.T) {
	apiEnv(t)

	rec, handled := apiV1(t, apiSecret, `{"domain":"`+apiDomain+`","action":"GET_TOTAL_REQUESTS"}`)
	if !handled {
		t.Fatal("returned false")
	}
	res := apiDecode(t, rec)
	if got := res.Results["TOTAL_REQUESTS"]; got != float64(41) {
		t.Errorf("TOTAL_REQUESTS = %v, want 41 (the requested domain's count, not the calling domain's)", got)
	}

	t.Run("unknown domain", func(t *testing.T) {
		rec, _ := apiV1(t, apiSecret, `{"domain":"nope.invalid","action":"GET_TOTAL_REQUESTS"}`)
		apiAssertError(t, rec, ERR_DOMAIN_NOT_FOUND)
	})
}

// ---------------------------------------------------------------------------
// malformed input
// ---------------------------------------------------------------------------

func TestMalformedJSON(t *testing.T) {
	apiEnv(t)

	for _, body := range []string{
		`{"action":`,
		`not json at all`,
		`[1,2,3]`,
		`{"action":123}`,
		``,
	} {
		t.Run(body, func(t *testing.T) {
			rec, handled := apiV1(t, apiSecret, body)
			if !handled {
				t.Fatal("returned false: a malformed body must still be handled, not proxied upstream")
			}
			apiAssertError(t, rec, ERR_JSON_READ_FAILED)
		})
	}
}

// A body that dies mid-read must be reported once and the request must be
// treated as handled. Returning false after having already written the error
// response let core/server proxy the same request upstream and write a second,
// conflicting response into the same writer.
func TestTruncatedBody(t *testing.T) {
	apiEnv(t)

	req := httptest.NewRequest(http.MethodPost, "/_lancarsec/api/v1", &errReader{prefix: `{"action":"GET_PRO`})
	req.Header.Set("proxy-secret", apiSecret)
	req.ContentLength = 512
	rec := httptest.NewRecorder()

	if handled := Process(rec, req, domains.DomainData{}); !handled {
		t.Fatal("returned false after writing a response: the caller would proxy the request and write a second one")
	}
	apiAssertError(t, rec, ERR_BODY_READ_FAILED)
	if strings.Count(rec.Body.String(), `"success"`) != 1 {
		t.Errorf("body contains more than one response: %q", rec.Body.String())
	}
}

// An API_REQUEST is two short strings. An authenticated caller must not be able
// to make the proxy buffer an unbounded body on its behalf.
//
// The bound is asserted separately from the rejection, and the test body is a
// fixed 1 MiB rather than maxBodyBytes+1: deriving the fixture from the
// constant under test means raising the constant silently grows the fixture
// instead of failing, which is how a cap of 1 TiB would sail through.
func TestOversizedBodyIsRejected(t *testing.T) {
	apiEnv(t)

	if maxBodyBytes > 1<<20 {
		t.Fatalf("maxBodyBytes = %d, want at most 1 MiB: an API_REQUEST is two short strings, and a larger cap is a memory budget handed to whoever holds the secret", maxBodyBytes)
	}

	body := `{"action":"GET_PROXY_STATS","domain":"` + strings.Repeat("a", 1<<20) + `"}`
	rec, handled := apiV1(t, apiSecret, body)
	if !handled {
		t.Fatal("returned false")
	}
	apiAssertError(t, rec, ERR_BODY_READ_FAILED)

	// A body comfortably under the cap still works.
	rec, _ = apiV1(t, apiSecret, `{"action":"GET_PROXY_STATS"}`)
	if res := apiDecode(t, rec); !res.Success {
		t.Errorf("a normal-sized body was rejected: %q", rec.Body.String())
	}
}

func TestUnknownAction(t *testing.T) {
	apiEnv(t)

	t.Run("v1", func(t *testing.T) {
		rec, handled := apiV1(t, apiSecret, `{"action":"DEFINITELY_NOT_AN_ACTION"}`)
		if !handled {
			t.Fatal("returned false")
		}
		apiAssertError(t, rec, ERR_ACTION_NOT_FOUND)
	})

	t.Run("v1 empty action", func(t *testing.T) {
		rec, _ := apiV1(t, apiSecret, `{}`)
		apiAssertError(t, rec, ERR_ACTION_NOT_FOUND)
	})

	t.Run("v2", func(t *testing.T) {
		rec, handled := apiV2(t, apiSecret, apiV2Prefix+"/DEFINITELY_NOT_AN_ACTION")
		if !handled {
			t.Fatal("returned false")
		}
		apiAssertError(t, rec, ERR_ACTION_NOT_FOUND)
	})
}

// Everything past the routing marker is handled here. These paths used to
// return false and be proxied to the customer backend even though the caller
// had already authenticated.
func TestV2DegenerateePathsAreHandled(t *testing.T) {
	apiEnv(t)

	for _, path := range []string{
		apiV2Prefix,
		apiV2Prefix + "/",
		apiV2Prefix + "extra",
	} {
		t.Run(path, func(t *testing.T) {
			rec, handled := apiV2(t, apiSecret, path)
			if !handled {
				t.Fatal("returned false: an authenticated request must never fall through to the backend")
			}
			apiAssertError(t, rec, ERR_ACTION_NOT_FOUND)
		})
	}

	// A trailing empty segment names an empty domain, which cannot exist.
	t.Run("empty domain segment", func(t *testing.T) {
		rec, handled := apiV2(t, apiSecret, apiV2Prefix+"//GET_TOTAL_REQUESTS")
		if !handled {
			t.Fatal("returned false")
		}
		apiAssertError(t, rec, ERR_DOMAIN_NOT_FOUND)
	})
}

// ---------------------------------------------------------------------------
// response envelope
// ---------------------------------------------------------------------------

func TestAPIResponseEnvelope(t *testing.T) {
	rec := httptest.NewRecorder()
	if err := APIResponse(rec, true, map[string]any{"K": "V"}); err != nil {
		t.Fatalf("APIResponse: %v", err)
	}
	if ct := rec.Result().Header.Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
	if got := rec.Body.String(); got != `{"success":true,"results":{"K":"V"}}` {
		t.Errorf("body = %q", got)
	}

	// An unmarshalable value is reported rather than written as garbage.
	rec = httptest.NewRecorder()
	if err := APIResponse(rec, true, map[string]any{"K": make(chan int)}); err == nil {
		t.Error("APIResponse returned nil for an unmarshalable response")
	}
}
