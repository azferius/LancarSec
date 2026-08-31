package server

// Wave 3 benchmark baseline for core/server/middleware.go.
//
// The point of these benchmarks is wave 7 (hot-path concurrency rewrite). The
// audit recorded the request path getting SLOWER as cores are added - 43.7 ns/op
// at GOMAXPROCS=1 degrading to 90.9 ns/op at 16 - because firewall.Mutex, one
// process-wide RWMutex, is taken three to four times per request, twice for
// writing. The serial/parallel pairs below are what makes that inversion visible.
//
// Measured numbers, the machine they came from and the raw output are committed
// in core/server/BENCHMARK_BASELINE.md. Re-run with:
//
//	go test ./core/server/ -run '^$' -bench BenchmarkMiddleware -benchmem -count 5 -cpu 1,16
//
// What is and is not measured:
//   - The upstream backend is an in-process stub RoundTripper, not a socket, so
//     the hot-path number is middleware + httputil.ReverseProxy, not TCP latency.
//   - Each goroutine builds ONE *http.Request outside the timed loop and resets
//     the four identity headers Middleware adds. Building a request per
//     iteration costs ~1.2 us and swamps everything else;
//     BenchmarkMiddlewareHarnessBaseline measures what is left (the reset).
//   - The response writer discards output, so response serialisation is out.
//   - -cpu changes GOMAXPROCS for the serial benchmarks too, which changes GC
//     parallelism. Compare serial-to-serial and parallel-to-parallel, never a
//     serial number against a parallel one.

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/azferius/lancarsec/core/domains"
	"github.com/azferius/lancarsec/core/firewall"
	"github.com/azferius/lancarsec/core/proxy"
)

// mwNullWriter is a http.ResponseWriter that throws everything away, so the
// benchmark measures Middleware rather than response encoding.
type mwNullWriter struct {
	header http.Header
	n      int
}

func mwNewNullWriter() *mwNullWriter {
	return &mwNullWriter{header: make(http.Header, 8)}
}

func (w *mwNullWriter) Header() http.Header { return w.header }

func (w *mwNullWriter) Write(b []byte) (int, error) {
	w.n += len(b)
	return len(b), nil
}

func (w *mwNullWriter) WriteHeader(int) {}

func (w *mwNullWriter) Flush() {}

// mwStubTransport answers every upstream request in-process.
type mwStubTransport struct{}

func (mwStubTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	return &http.Response{
		Status:        "200 OK",
		StatusCode:    http.StatusOK,
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        make(http.Header, 2),
		Body:          io.NopCloser(strings.NewReader(mwBackendBody)),
		ContentLength: int64(len(mwBackendBody)),
		Request:       r,
	}, nil
}

// mwNewBenchEnv builds the standard test domain but routes the reverse proxy at
// an in-process transport.
func mwNewBenchEnv(b *testing.B) *mwEnv {
	b.Helper()
	env := mwNewEnv(b)
	env.storeSettings(nil, mwStubTransport{})
	return env
}

// mwResetIdentityHeaders undoes the four identity-header writes at the end of
// Middleware so one request value can be reused across iterations.
//
// Since wave 6 those writes are Set, not Add, so the header map no longer grows
// by four values per iteration and this is strictly no longer required for
// correctness. It is kept so the per-iteration harness cost stays comparable
// with the numbers in BENCHMARK_BASELINE.md - removing it would silently make
// every benchmark below look faster than the recorded "before" for a reason
// that has nothing to do with Middleware.
func mwResetIdentityHeaders(r *http.Request) {
	h := r.Header
	delete(h, "X-Real-Ip")
	delete(h, "Proxy-Real-Ip")
	delete(h, "Proxy-Tls-Fp")
	delete(h, "Proxy-Tls-Name")
}

// mwResetCookie puts the challenge cookie back. Since wave 5 Middleware strips
// every challenge cookie from the request before forwarding it upstream, so a
// reused *http.Request loses its clearance after the first iteration and every
// later iteration would silently measure the stage-1 challenge path instead of
// the hot path. Its cost is included in BenchmarkMiddlewareHarnessBaseline.
func mwResetCookie(r *http.Request, cookie string) {
	r.Header.Set("Cookie", cookie)
}

// mwTrimBenchLogs keeps domains.DomainsData[mwDomain].LastLogs from growing
// without bound over millions of iterations. utils.AddLogs appends on every
// bypassed request and nothing trims it inside a benchmark run (the monitor
// goroutine is not running). Capacity is retained, so this is not a realloc.
func mwTrimBenchLogs() {
	firewall.Mutex.Lock()
	d := domains.DomainsData[mwDomain]
	d.LastLogs = d.LastLogs[:0]
	domains.DomainsData[mwDomain] = d
	firewall.Mutex.Unlock()
}

const mwBenchTrimEvery = 4096

// BenchmarkMiddlewareHotPath measures a request that passes every check -
// domain found, under every ratelimit, fingerprint not forbidden, no custom
// rules, correct challenge cookie - and is forwarded to the backend.
//
// The ~40 KB/op is not the middleware: httputil.ReverseProxy allocates a fresh
// 32 KiB copy buffer per response because no BufferPool is configured
// (core/config/init.go:126-130). Wave 8 owns that number.
func BenchmarkMiddlewareHotPath(b *testing.B) {
	env := mwNewBenchEnv(b)
	env.mwSetStage(1)

	cookie := mwStage1Cookie + "=" + mwCookieToken()
	req := mwRequest("/", mwWithCookie(cookie))
	w := mwNewNullWriter()

	// Warm the encryption cache exactly as a live proxy would be warm.
	Middleware(w, req)
	mwResetIdentityHeaders(req)
	mwResetCookie(req, cookie)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Middleware(w, req)
		mwResetIdentityHeaders(req)
		mwResetCookie(req, cookie)
		if i%mwBenchTrimEvery == mwBenchTrimEvery-1 {
			mwTrimBenchLogs()
		}
	}
	b.StopTimer()
	mwTrimBenchLogs()
}

// BenchmarkMiddlewareHotPathParallel is the same work under contention. This is
// the number that must improve in wave 7: every request takes the single global
// firewall.Mutex twice for writing (the sliding-window increment and the
// access-log append), so throughput is capped by one lock no matter how many
// cores the box has.
func BenchmarkMiddlewareHotPathParallel(b *testing.B) {
	env := mwNewBenchEnv(b)
	env.mwSetStage(1)

	cookie := mwStage1Cookie + "=" + mwCookieToken()
	Middleware(mwNewNullWriter(), mwRequest("/", mwWithCookie(cookie)))

	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		w := mwNewNullWriter()
		req := mwRequest("/", mwWithCookie(cookie))
		n := 0
		for pb.Next() {
			Middleware(w, req)
			mwResetIdentityHeaders(req)
			mwResetCookie(req, cookie)
			n++
			if n%mwBenchTrimEvery == 0 {
				mwTrimBenchLogs()
			}
		}
	})
	b.StopTimer()
	mwTrimBenchLogs()
}

// BenchmarkMiddlewareDecisionPath measures the cheapest terminating path: the R2
// ip ratelimit, which returns before the firewall rules, the encryption cache
// and the backend. No reverse proxy is involved, so this is the closest thing to
// a pure measurement of the middleware's own bookkeeping - three firewall.Mutex
// acquisitions (two read, one write) plus two map lookups.
func BenchmarkMiddlewareDecisionPath(b *testing.B) {
	env := mwNewBenchEnv(b)
	env.mwSetStage(1)
	firewall.AccessIps[mwIP] = proxy.IPRatelimit + 1

	req := mwRequest("/")
	w := mwNewNullWriter()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Middleware(w, req)
	}
}

// BenchmarkMiddlewareDecisionPathParallel is the contended twin of
// BenchmarkMiddlewareDecisionPath. Serial-vs-parallel on this pair is the
// clearest signal of the global-mutex bottleneck, because nothing else in the
// measurement scales.
func BenchmarkMiddlewareDecisionPathParallel(b *testing.B) {
	env := mwNewBenchEnv(b)
	env.mwSetStage(1)
	firewall.AccessIps[mwIP] = proxy.IPRatelimit + 1

	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		w := mwNewNullWriter()
		req := mwRequest("/")
		for pb.Next() {
			Middleware(w, req)
		}
	})
}

// BenchmarkMiddlewareChallengeStage1 measures issuing a stage-1 challenge: what
// every unverified client costs during an attack. The encryption cache is warm,
// so this excludes the BLAKE3 hash and includes the CacheIps lookup, the
// challenge-failure window write and the redirect.
func BenchmarkMiddlewareChallengeStage1(b *testing.B) {
	env := mwNewBenchEnv(b)
	env.mwSetStage(1)

	req := mwRequest("/")
	w := mwNewNullWriter()
	Middleware(w, req) // warm CacheIps

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Middleware(w, req)
	}
}

// BenchmarkMiddlewareChallengeStage1Parallel is its contended twin.
func BenchmarkMiddlewareChallengeStage1Parallel(b *testing.B) {
	env := mwNewBenchEnv(b)
	env.mwSetStage(1)

	Middleware(mwNewNullWriter(), mwRequest("/")) // warm CacheIps

	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		w := mwNewNullWriter()
		req := mwRequest("/")
		for pb.Next() {
			Middleware(w, req)
		}
	})
}

// BenchmarkMiddlewareClientIP isolates the wave-6 identity resolution, which is
// new work on every single request. It is the piece to watch if wave 7 shards
// these keys: realClientIP must stay allocation-free, and ipString's single
// string is the only allocation the pair is allowed.
func BenchmarkMiddlewareClientIP(b *testing.B) {
	cases := []struct {
		name    string
		trust   []string
		remote  string
		headers [][2]string
	}{
		{
			name:   "origin ipv4 peer",
			remote: "203.0.113.7:51000",
		},
		{
			name:   "origin ipv6 peer",
			remote: "[2001:db8:1:2::1]:51000",
		},
		{
			// The untrusted-peer path is the one an attacker hitting the origin
			// directly takes, and it must not be more expensive than the
			// trusted one or the spoof attempt is itself an amplifier.
			name:    "untrusted peer sending a forged header",
			trust:   []string{"192.0.2.0/24"},
			remote:  "203.0.113.7:51000",
			headers: [][2]string{{"Cf-Connecting-Ip", "1.1.1.1"}},
		},
		{
			name:    "trusted peer, Cf-Connecting-Ip",
			trust:   []string{"192.0.2.0/24"},
			remote:  "192.0.2.9:51000",
			headers: [][2]string{{"Cf-Connecting-Ip", "1.1.1.1"}},
		},
		{
			name:    "trusted peer, four-element X-Forwarded-For",
			trust:   []string{"192.0.2.0/24", "198.51.100.0/24"},
			remote:  "192.0.2.9:51000",
			headers: [][2]string{{"X-Forwarded-For", "9.9.9.9, 1.1.1.1, 198.51.100.5, 198.51.100.6"}},
		},
	}

	for _, tc := range cases {
		b.Run(tc.name, func(b *testing.B) {
			mwSaveGlobals(b)
			mwTrustPeers(b, tc.trust...)

			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.RemoteAddr = tc.remote
			for _, h := range tc.headers {
				req.Header.Set(h[0], h[1])
			}

			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				addr := realClientIP(req)
				mwSinkString = ratelimitKeyFor(addr, ipString(addr))
			}
		})
	}
}

// mwSinkString keeps the compiler from eliminating the benchmarked work.
var mwSinkString string

// BenchmarkMiddlewareHarnessBaseline measures the per-iteration cost the
// harness itself adds to the benchmarks above (the identity-header reset), so
// it can be subtracted.
func BenchmarkMiddlewareHarnessBaseline(b *testing.B) {
	cookie := mwStage1Cookie + "=" + mwCookieToken()
	req := mwRequest("/")
	req.Header.Add("x-real-ip", mwIP)
	req.Header.Add("proxy-real-ip", mwIP)
	req.Header.Add("proxy-tls-fp", mwFP)
	req.Header.Add("proxy-tls-name", "")

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		mwResetIdentityHeaders(req)
		mwResetCookie(req, cookie)
	}
}
