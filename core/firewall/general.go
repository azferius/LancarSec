package firewall

import (
	"net"
	"net/http"
	"sync"
	"sync/atomic"
)

// The firewall state is guarded by three independent synchronization
// primitives so hot paths don't all queue behind one giant lock:
//
//   - DataMu      protects DomainsData (heavy struct-copy writes per request)
//   - CountersMu  protects the sliding-window ratelimit maps
//   - Connections is a sync.Map (write on TLS handshake, read every request)
var (
	DataMu     = &sync.RWMutex{}
	CountersMu = &sync.RWMutex{}

	// Sliding-window counters. Hot path: every request writes WindowAccessIps,
	// potentially WindowAccessIpsCookie and WindowUnkFps.
	UnkFps                = map[string]int{}
	WindowUnkFps          = map[int]map[string]int{}
	AccessIps             = map[string]int{}
	WindowAccessIps       = map[int]map[string]int{}
	AccessIpsCookie       = map[string]int{}
	WindowAccessIpsCookie = map[int]map[string]int{}

	// WindowPathLimits is the dedicated window for path-scoped rate limits.
	// Keys are composite (ip + "|" + rule_id) so different rules stay
	// separate. Kept off WindowAccessIps so the global per-IP 200k bucket
	// cap doesn't get consumed by per-path bookkeeping — under heavy
	// path-rule coverage with IP rotation that pollution would silently
	// drop legitimate IPs from the global ratelimit view.
	WindowPathLimits = map[int]map[string]int{}

	// Encryption/captcha caches — sync.Map was already the right structure;
	// each key is written once and read many times before eviction.
	CacheIps  = sync.Map{}
	CacheImgs = sync.Map{}

	// Connections maps "host:port" remote addresses to the TLS fingerprint
	// captured during the ClientHello. Populated in fingerprint.go, cleared in
	// OnStateChange. sync.Map fits: write-rarely, read-often, never contended
	// with counter or domain-data locks.
	Connections = sync.Map{}

	// ClientHellos stores the raw-parsed ClientHello (*tlsparse.ClientHello)
	// captured by the peek listener before tls.Server consumes the bytes.
	// Used by ja4.go to compute a spec-compliant JA4. Keyed by RemoteAddr.
	ClientHellos = sync.Map{}

	// JA4s stores the computed JA4 TLS fingerprint per connection, keyed by
	// RemoteAddr. Read in middleware to expose as ip.ja4 in firewall rules
	// and as the proxy-tls-ja4 header to backends.
	JA4s = sync.Map{}

	// JA3s, JA4Rs, JA4Os carry the additional TLS fingerprint variants
	// computed alongside JA4 at handshake time. JA3 is the legacy Salesforce
	// MD5 used by most threat-intel feeds; JA4_R is raw, original-order,
	// harder to spoof; JA4_O hashes original-order ciphers/extensions
	// without sorting. All three are exposed to firewall rules and
	// forwarded to backends as headers, and the blocklist can match any of
	// them.
	JA3s  = sync.Map{}
	JA4Rs = sync.Map{}
	JA4Os = sync.Map{}

	activeConnections atomic.Int64
	activeConnKeys    = sync.Map{}
)

func OnStateChange(conn net.Conn, state http.ConnState) {
	addr := conn.RemoteAddr().String()
	switch state {
	case http.StateNew:
		if _, loaded := activeConnKeys.LoadOrStore(addr, struct{}{}); !loaded {
			activeConnections.Add(1)
		}
	case http.StateHijacked, http.StateClosed:
		Connections.Delete(addr)
		JA4s.Delete(addr)
		JA3s.Delete(addr)
		JA4Rs.Delete(addr)
		JA4Os.Delete(addr)
		ClientHellos.Delete(addr)
		if _, loaded := activeConnKeys.LoadAndDelete(addr); loaded {
			activeConnections.Add(-1)
		}
	}
}

func ActiveConnectionCount() int64 {
	return activeConnections.Load()
}
