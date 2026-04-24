package server

import (
	"crypto/subtle"
	"fmt"
	"net"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"lancarsec/core/domains"
	"lancarsec/core/firewall"
	"lancarsec/core/proxy"
)

// Metrics counters that sit on the hot path. All atomic so they don't add
// lock pressure to the middleware. Prometheus scrapes them via
// /_lancarsec/metrics.
//
// The metric names follow the loose Prometheus convention: lowercase,
// underscores, unit suffix where applicable (_total, _seconds, _bytes).
var (
	mReqTotal      atomic.Int64 // all requests reaching the middleware
	mReqForwarded  atomic.Int64 // forwarded to backend
	mReqBlocked    atomic.Int64 // outright blocked
	mReqBlocklist  atomic.Int64 // blocklist short-circuit
	mReqPathLimit  atomic.Int64 // path-scoped limit hit
	mReqRateLimit  atomic.Int64 // global per-IP ratelimit block
	mReqConnect    atomic.Int64 // CONNECT rejected
	mChallengeJS   atomic.Int64 // Stage 2 challenges shown
	mChallengeCAP  atomic.Int64 // Stage 3 captchas shown
	mTLSHandshakes atomic.Int64 // TLS client hellos seen
	startedAt      = time.Now()
)

// RecordRequest / RecordForwarded / … are called from middleware.go via the
// Incr* wrappers below so metric names don't leak into the hot path.
func IncrRequest()       { mReqTotal.Add(1) }
func IncrForwarded()     { mReqForwarded.Add(1) }
func IncrBlocked()       { mReqBlocked.Add(1) }
func IncrBlocklistHit()  { mReqBlocklist.Add(1) }
func IncrPathLimitHit()  { mReqPathLimit.Add(1) }
func IncrRateLimitHit()  { mReqRateLimit.Add(1) }
func IncrConnectReject() { mReqConnect.Add(1) }
func IncrChallengeJS()   { mChallengeJS.Add(1) }
func IncrChallengeCAP()  { mChallengeCAP.Add(1) }
func IncrTLSHandshake()  { mTLSHandshakes.Add(1) }

// ServeMetrics renders Prometheus text format. Authentication is via an
// optional METRICS_TOKEN env-gated bearer, not an operator session, because
// Prometheus scrapers shouldn't be juggling cookies. If the token env var is
// unset, only loopback peers may scrape.
func ServeMetrics(w http.ResponseWriter, r *http.Request) {
	if required := metricsToken(); required != "" {
		got := bearerFromHeader(r)
		if subtle.ConstantTimeCompare([]byte(got), []byte(required)) != 1 {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
	} else if !requestFromLoopback(r) {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")

	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)
	uptime := time.Since(startedAt).Seconds()

	write := func(format string, args ...any) { fmt.Fprintf(w, format, args...) }

	write("# HELP lancarsec_uptime_seconds Seconds since the proxy started.\n")
	write("# TYPE lancarsec_uptime_seconds gauge\n")
	write("lancarsec_uptime_seconds %f\n", uptime)

	write("# HELP lancarsec_requests_total Total HTTP requests that reached the middleware.\n")
	write("# TYPE lancarsec_requests_total counter\n")
	write("lancarsec_requests_total %d\n", mReqTotal.Load())

	write("# HELP lancarsec_requests_forwarded_total Requests successfully forwarded to the backend.\n")
	write("# TYPE lancarsec_requests_forwarded_total counter\n")
	write("lancarsec_requests_forwarded_total %d\n", mReqForwarded.Load())

	write("# HELP lancarsec_requests_blocked_total Requests denied instead of forwarded.\n")
	write("# TYPE lancarsec_requests_blocked_total counter\n")
	write("lancarsec_requests_blocked_total %d\n", mReqBlocked.Load())

	write("# HELP lancarsec_blocklist_hits_total Requests short-circuited by the deny list.\n")
	write("# TYPE lancarsec_blocklist_hits_total counter\n")
	write("lancarsec_blocklist_hits_total %d\n", mReqBlocklist.Load())

	write("# HELP lancarsec_pathlimit_hits_total Requests exceeding a path-scoped rate limit.\n")
	write("# TYPE lancarsec_pathlimit_hits_total counter\n")
	write("lancarsec_pathlimit_hits_total %d\n", mReqPathLimit.Load())

	write("# HELP lancarsec_ratelimit_hits_total Requests rejected by the global per-IP rate limit.\n")
	write("# TYPE lancarsec_ratelimit_hits_total counter\n")
	write("lancarsec_ratelimit_hits_total %d\n", mReqRateLimit.Load())

	write("# HELP lancarsec_connect_rejects_total CONNECT-method requests rejected.\n")
	write("# TYPE lancarsec_connect_rejects_total counter\n")
	write("lancarsec_connect_rejects_total %d\n", mReqConnect.Load())

	write("# HELP lancarsec_challenges_total Challenges rendered, by stage.\n")
	write("# TYPE lancarsec_challenges_total counter\n")
	write("lancarsec_challenges_total{stage=\"js_pow\"} %d\n", mChallengeJS.Load())
	write("lancarsec_challenges_total{stage=\"captcha\"} %d\n", mChallengeCAP.Load())

	write("# HELP lancarsec_tls_handshakes_total TLS ClientHellos seen.\n")
	write("# TYPE lancarsec_tls_handshakes_total counter\n")
	write("lancarsec_tls_handshakes_total %d\n", firewall.HandshakeCount())

	// Per-domain stage gauge so Grafana can render a state-timeline.
	write("# HELP lancarsec_domain_stage The protection stage currently applied per domain (1 cookie, 2 JS PoW, 3 captcha).\n")
	write("# TYPE lancarsec_domain_stage gauge\n")
	firewall.DataMu.RLock()
	for name, d := range domains.DomainsData {
		if name == "debug" {
			continue
		}
		locked := 0
		if d.StageManuallySet {
			locked = 1
		}
		write("lancarsec_domain_stage{domain=\"%s\",locked=\"%d\"} %d\n", prometheusLabel(name), locked, d.Stage)
	}
	firewall.DataMu.RUnlock()

	// Per-domain request totals (atomic, no lock).
	write("# HELP lancarsec_domain_requests_total Total requests seen per-domain.\n")
	write("# TYPE lancarsec_domain_requests_total counter\n")
	cfg := domains.LoadConfig()
	if cfg != nil {
		for _, d := range cfg.Domains {
			ctr := domains.CountersFor(d.Name)
			domainLabel := prometheusLabel(d.Name)
			write("lancarsec_domain_requests_total{domain=\"%s\"} %d\n", domainLabel, ctr.Total.Load())
			write("# HELP lancarsec_domain_bypassed_total Total forwarded requests per-domain.\n")
			write("# TYPE lancarsec_domain_bypassed_total counter\n")
			write("lancarsec_domain_bypassed_total{domain=\"%s\"} %d\n", domainLabel, ctr.Bypassed.Load())
		}
	}

	// Host process metrics. CPU is captured by printStats every second.
	write("# HELP lancarsec_process_memory_alloc_bytes Currently allocated Go heap.\n")
	write("# TYPE lancarsec_process_memory_alloc_bytes gauge\n")
	write("lancarsec_process_memory_alloc_bytes %d\n", mem.Alloc)

	write("# HELP lancarsec_process_memory_sys_bytes Total memory obtained from the OS.\n")
	write("# TYPE lancarsec_process_memory_sys_bytes gauge\n")
	write("lancarsec_process_memory_sys_bytes %d\n", mem.Sys)

	write("# HELP lancarsec_process_goroutines Number of live goroutines.\n")
	write("# TYPE lancarsec_process_goroutines gauge\n")
	write("lancarsec_process_goroutines %d\n", runtime.NumGoroutine())

	write("# HELP lancarsec_process_cpu_percent Last-observed CPU percentage reported by the monitor.\n")
	write("# TYPE lancarsec_process_cpu_percent gauge\n")
	write("lancarsec_process_cpu_percent %s\n", safeNumber(proxy.GetCPUUsage()))
}

// metricsToken returns the LANCARSEC_METRICS_TOKEN env value or "" when unset.
func metricsToken() string { return os.Getenv("LANCARSEC_METRICS_TOKEN") }

func requestFromLoopback(r *http.Request) bool {
	host := r.RemoteAddr
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func prometheusLabel(s string) string {
	return strings.NewReplacer("\\", "\\\\", "\n", "\\n", "\"", "\\\"").Replace(s)
}

// safeNumber returns s if it parses as a Go float, or "0" otherwise. We use
// it to emit proxy CPU usage (a string) into Prometheus format without risking
// a parse error if the monitor goroutine wrote an "ERR" sentinel.
func safeNumber(s string) string {
	if _, err := strconv.ParseFloat(s, 64); err == nil {
		return s
	}
	return "0"
}

func bearerFromHeader(r *http.Request) string {
	h := r.Header.Get("Authorization")
	const p = "Bearer "
	if len(h) <= len(p) || h[:len(p)] != p {
		return ""
	}
	return h[len(p):]
}
