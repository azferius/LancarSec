package api

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/azferius/lancarsec/core/domains"
	"github.com/azferius/lancarsec/core/firewall"
	"github.com/azferius/lancarsec/core/proxy"
)

const (
	// apiV2Prefix is the path marker core/server routes to ProcessV2. It is
	// duplicated rather than shared because the middleware owns the routing
	// decision and this package owns the parsing of what is left. WAVE 10: the
	// middleware rewrites the legacy /_bProxy/api/v2 spelling onto this prefix
	// inside its v2 branch, so this stays the only spelling parsed here.
	apiV2Prefix = "/_lancarsec/api/v2"

	// maxBodyBytes caps the admin API request body. An API_REQUEST is two short
	// strings; anything larger is either a mistake or an attempt to make the
	// proxy buffer an unbounded body in memory on our behalf.
	maxBodyBytes = 64 << 10
)

// Authentication failures are deliberately slowed down so the shared static
// secret cannot be ground at line rate, but the delay is itself an attack
// surface: this process exists to absorb floods, and a naive unconditional
// sleep converts every rejected request into a goroutine plus a socket held
// open for the duration - an attacker-controlled memory amplifier that costs
// him nothing and costs us everything.
//
// So the delay is bounded on both axes:
//
//   - authFailDelay is 250ms. Long enough that an online guessing campaign
//     against the 30-character secret is hopeless at any rate the delay
//     actually gates, short enough to stay well inside the proxy's own
//     write timeout so we never hold a connection the server has given up on.
//   - authFailDelayLimit caps how many rejected requests may be sleeping at
//     once. Beyond it, rejection is immediate. Under a flood the delay
//     degrades to zero rather than accumulating goroutines, so the worst case
//     is 32 parked goroutines regardless of offered load. That still throttles
//     a *serial* guesser (the only kind that learns anything) to ~4 attempts
//     per second, while a parallel flood - which learns nothing extra, because
//     the comparison below is constant time - simply gets fast 404s.
//
// The sleep also aborts as soon as the client's context is cancelled, so a
// caller who hangs up does not keep a goroutine parked for the full delay.
var (
	authFailDelay      = 250 * time.Millisecond
	authFailDelayLimit = int32(32)

	authFailDelayInFlight atomic.Int32
)

// authenticate compares the caller's Proxy-Secret against the configured API
// secret in constant time.
//
// The values are hashed first so the comparison does not branch on length
// either: subtle.ConstantTimeCompare returns early when the two slices differ
// in size, which would leak the secret's length to a caller who can time us.
//
// An empty configured secret denies everything. Header.Get returns "" for an
// absent header, so a plain string comparison against an unset apisecret made
// `"" == ""` true and left the entire admin API open to anyone on the internet.
// Config validation rejects a secret containing CHANGE_ME, but it does not
// require the key to be present at all, and an omitted key must not be a softer
// failure than a placeholder one.
func authenticate(r *http.Request) bool {
	secret := proxy.APISecret
	if secret == "" {
		return false
	}

	got := sha256.Sum256([]byte(r.Header.Get("Proxy-Secret")))
	want := sha256.Sum256([]byte(secret))

	return subtle.ConstantTimeCompare(got[:], want[:]) == 1
}

// denyAuth answers a failed authentication with a 404.
//
// It used to return false and let the middleware fall through to the customer
// backend, which meant an unauthenticated request to the v1 admin path was
// proxied upstream - handing proxy.AdminSecret, which sits in that URL, to the
// backend and to every access log behind it. It also made the endpoint
// trivially discoverable: a wrong secret produced the backend's response while
// a right one produced JSON, so the admin surface could be located by diffing
// response codes without ever guessing the secret.
func denyAuth(w http.ResponseWriter, r *http.Request) {
	delayAuthFailure(r.Context())
	http.NotFound(w, r)
}

func delayAuthFailure(ctx context.Context) {
	if authFailDelay <= 0 {
		return
	}
	if authFailDelayInFlight.Add(1) > authFailDelayLimit {
		// Too many rejections already parked: fail fast rather than let the
		// penalty become the amplification vector.
		authFailDelayInFlight.Add(-1)
		return
	}
	defer authFailDelayInFlight.Add(-1)

	timer := time.NewTimer(authFailDelay)
	defer timer.Stop()

	select {
	case <-timer.C:
	case <-ctx.Done():
	}
}

// Process handles the v1 admin API, reached at the fixed /_lancarsec/api/v1
// path with the admin secret in the Admin-Secret header (WAVE 10: the core
// server gate checks that; this re-checks the API secret below).
//
// It reports whether the request was handled. Every path below now handles the
// request, including authentication failure; returning false after having
// already written a response let the middleware proxy the same request
// upstream and write a second, conflicting response into the same writer.
func Process(writer http.ResponseWriter, request *http.Request, domainData domains.DomainData) bool {

	if !authenticate(request) {
		denyAuth(writer, request)
		return true
	}

	reqBody, err := io.ReadAll(http.MaxBytesReader(writer, request.Body, maxBodyBytes))
	if err != nil {
		APIResponse(writer, false, map[string]any{
			"ERROR": ERR_BODY_READ_FAILED,
		})
		return true
	}

	var apiRequest API_REQUEST
	if err := json.Unmarshal(reqBody, &apiRequest); err != nil {
		APIResponse(writer, false, map[string]any{
			"ERROR": ERR_JSON_READ_FAILED,
		})
		return true
	}

	if apiRequest.Domain == "" {
		handleProxyActions(apiRequest.Action, writer)
		return true
	}

	uncastedDomainSettings, ok := domains.DomainsMap.Load(apiRequest.Domain)
	if !ok {
		APIResponse(writer, false, map[string]any{
			"ERROR": ERR_DOMAIN_NOT_FOUND,
		})
		return true
	}
	domainSettings, _ := uncastedDomainSettings.(domains.DomainSettings)

	// The counters must come from the domain the caller asked about. The
	// domainData argument is the snapshot of the domain the request happened to
	// arrive on, so answering with it made GET_TOTAL_REQUESTS for domain A
	// return domain B's numbers whenever the operator queried through a
	// different vhost. It is kept in the signature because core/server owns the
	// call site.
	_ = domainData

	firewall.Mutex.RLock()
	requestedData := domains.DomainsData[apiRequest.Domain]
	firewall.Mutex.RUnlock()

	handleDomainActions(apiRequest.Action, writer, &requestedData, &domainSettings)
	return true
}

func handleProxyActions(action string, writer http.ResponseWriter) {
	switch action {
	case "GET_PROXY_STATS":
		APIResponse(writer, true, map[string]any{
			"CPU_USAGE": proxy.CpuUsage(),
			"RAM_USAGE": proxy.RamUsage(),
		})
	case "GET_PROXY_STATS_CPU_USAGE":
		APIResponse(writer, true, map[string]any{
			"CPU_USAGE": proxy.CpuUsage(),
		})
	case "GET_PROXY_STATS_RAM_USAGE":
		APIResponse(writer, true, map[string]any{
			"RAM_USAGE": proxy.RamUsage(),
		})

	// Aggregates only. This used to return the AccessIps / AccessIpsCookie maps
	// verbatim: a roster of every client IP currently talking to the proxy,
	// with its request count. That is a privacy dump with no operational
	// payoff - what an operator watches is the shape of the traffic, not the
	// individual addresses, and the addresses are already in GET_LOGS for the
	// cases that genuinely need them.
	//
	// The maps are also summarised while the lock is held. The old code copied
	// the map header under RLock, released it, and then let encoding/json walk
	// the live map; that is only safe because evaluateRatelimit happens to
	// replace these maps wholesale instead of mutating them, which is not a
	// property this package should be depending on.
	case "GET_IP_REQUESTS":
		firewall.Mutex.RLock()
		ips, ipRequests := len(firewall.AccessIps), sumCounts(firewall.AccessIps)
		cookieIps, cookieRequests := len(firewall.AccessIpsCookie), sumCounts(firewall.AccessIpsCookie)
		firewall.Mutex.RUnlock()

		APIResponse(writer, true, map[string]any{
			"TOTAL_IPS":             ips,
			"TOTAL_IP_REQUESTS":     ipRequests,
			"CHALLENGE_IPS":         cookieIps,
			"CHALLENGE_IP_REQUESTS": cookieRequests,
		})

	// Only returns UNK fingerprints. Kept in full, unlike GET_IP_REQUESTS: a
	// TLS fingerprint is a property of client software, not of a client, and
	// the per-fingerprint counts are what an operator writes firewall rules
	// against. Snapshotted under the lock rather than marshalled live.
	case "GET_FINGERPRINT_REQUESTS":
		firewall.Mutex.RLock()
		fingerprints := copyCounts(firewall.UnkFps)
		firewall.Mutex.RUnlock()

		APIResponse(writer, true, map[string]any{
			"TOTAL_FINGERPRINT_REQUESTS": fingerprints,
		})

	// GET_IP_CACHE, FILL_IP_CACHE and RELOAD used to live here.
	//
	// GET_IP_CACHE ranged firewall.CacheIps into the response. The values in
	// that map are the live challenge tokens clients are presenting, keyed by
	// ip+fingerprint+user-agent+hour, so a single call returned a ready-to-
	// replay stage-3 cookie for every visitor on the proxy plus their IP, TLS
	// fingerprint and User-Agent. It is deleted rather than reduced to counts:
	// nothing operational reads it, the cache's size is not a number anyone
	// tunes against, and a counts-only version would be a live occupancy oracle
	// kept alive purely to preserve an action name. GET_PROXY_STATS already
	// covers the "is this box healthy" question it was nominally there for.
	//
	// FILL_IP_CACHE was a load-test that took the global firewall write lock
	// and held it across 19980 iterations of two crypto-random string builds
	// and a sync.Map store. Every request on every domain blocks behind that
	// lock, so one authenticated call was a self-inflicted outage, and a loop
	// of them was an unbounded memory-growth primitive on a map that holds
	// secrets. Debug affordances do not belong in the production request path.
	//
	// RELOAD took the global write lock, released it immediately, and returned
	// a 200 with an empty body. It never reloaded anything. An advertised
	// action that silently does nothing is worse than no action at all, so it
	// now falls through to ERR_ACTION_NOT_FOUND. Wiring it to the real reload
	// routine is a control-plane change that belongs with the reload owner, not
	// here.

	default:
		APIResponse(writer, false, map[string]any{
			"ERROR": ERR_ACTION_NOT_FOUND,
		})
	}
}

func handleDomainActions(action string, writer http.ResponseWriter, domainData *domains.DomainData, domainSettings *domains.DomainSettings) {
	switch action {
	case "GET_TOTAL_REQUESTS":
		APIResponse(writer, true, map[string]any{
			"TOTAL_REQUESTS": domainData.TotalRequests,
		})
	case "GET_BYPASSED_REQUESTS":
		APIResponse(writer, true, map[string]any{
			"BYPASSED_REQUESTS": domainData.BypassedRequests,
		})
	case "GET_TOTAL_REQUESTS_PER_SECOND":
		APIResponse(writer, true, map[string]any{
			"TOTAL_REQUESTS_REQUESTS_PER_SECOND": domainData.RequestsPerSecond,
		})
	case "GET_BYPASSED_REQUESTS_PER_SECOND":
		APIResponse(writer, true, map[string]any{
			"BYPASSED_REQUESTS_REQUESTS_PER_SECOND": domainData.RequestsBypassedPerSecond,
		})
	case "GET_FIREWALL_RULES":
		APIResponse(writer, true, map[string]any{
			"FIREWALL_RULES": domainSettings.RawCustomRules,
		})
	case "GET_LOGS":
		APIResponse(writer, true, map[string]any{
			"LOGS": domainData.LastLogs,
		})
	default:
		APIResponse(writer, false, map[string]any{
			"ERROR": ERR_ACTION_NOT_FOUND,
		})
	}
}

// ProcessV2 handles the path-addressed admin API, /_lancarsec/api/v2/[:domain/]:action.
//
// It reports whether the request was handled. As with Process, everything past
// the routing marker is now handled here rather than falling through to the
// customer backend.
func ProcessV2(w http.ResponseWriter, r *http.Request) bool {

	if !authenticate(r) {
		denyAuth(w, r)
		return true
	}

	path := strings.TrimPrefix(r.URL.Path, apiV2Prefix+"/")
	if path == "" || path == r.URL.Path {
		// Either nothing followed the marker, or the marker was not a whole
		// path segment. Both used to return false and be proxied upstream.
		APIResponse(w, false, map[string]any{
			"ERROR": ERR_ACTION_NOT_FOUND,
		})
		return true
	}

	parts := strings.Split(path, "/")

	if len(parts) == 1 {

		// /:action

		handleProxyActions(parts[0], w)
		return true
	}

	//  /:domain/:action

	uncastedDomainSettings, ok := domains.DomainsMap.Load(parts[0])
	if !ok {
		APIResponse(w, false, map[string]any{
			"ERROR": ERR_DOMAIN_NOT_FOUND,
		})
		return true
	}
	domainSettings, _ := uncastedDomainSettings.(domains.DomainSettings)

	firewall.Mutex.RLock()
	domainData := domains.DomainsData[parts[0]]
	firewall.Mutex.RUnlock()

	handleDomainActions(parts[1], w, &domainData, &domainSettings)
	return true
}

func APIResponse(writer http.ResponseWriter, success bool, response map[string]any) error {

	writer.Header().Set("Content-Type", "application/json")

	apiResponse := API_RESPONSE{
		Success:  success,
		Response: response,
	}

	jsonResponse, err := json.Marshal(apiResponse)
	if err != nil {
		return err
	}

	fmt.Fprint(writer, string(jsonResponse))
	return nil
}

func sumCounts(counts map[string]int) int {
	total := 0
	for _, count := range counts {
		total += count
	}
	return total
}

func copyCounts(counts map[string]int) map[string]int {
	out := make(map[string]int, len(counts))
	for key, count := range counts {
		out[key] = count
	}
	return out
}
