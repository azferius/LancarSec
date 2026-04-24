package firewall

import (
	"net"
	"net/http"
	"sync"
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
)

func OnStateChange(conn net.Conn, state http.ConnState) {
	switch state {
	case http.StateHijacked, http.StateClosed:
		addr := conn.RemoteAddr().String()
		Connections.Delete(addr)
		JA4s.Delete(addr)
		ClientHellos.Delete(addr)
	}
}
