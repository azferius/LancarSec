package firewall

import (
	"net"
	"net/http"
	"sync"
)

var (
	Mutex = &sync.RWMutex{}

	//store unknown fingerprints for ratelimiting
	UnkFps = map[string]int{}
	//sliding window, to keep track of fingerprints
	WindowUnkFps = map[int]map[string]int{}

	//store bypassing ips for ratelimiting
	AccessIps = map[string]int{}
	//sliding window, to keep track of ips
	WindowAccessIps = map[int]map[string]int{}

	//store ips that didnt have verification cookie set for ratelimiting
	AccessIpsCookie = map[string]int{}
	//sliding window, to keep track of ips
	WindowAccessIpsCookie = map[int]map[string]int{}

	//"cache" encryption result of ips for 2 minutes in order to have less load on the proxy
	//Using syncMap here instead of CacheIps = map[string]string{}, since this value should only be written to once per 2 minutes and readonly the rest of the time
	CacheIps = sync.Map{}

	//"cache" captcha images to for 2 minutes in order to have less load on the proxy
	//CacheImgs = map[string]string{}
	CacheImgs = sync.Map{}

	Connections = map[string]string{}
)

// windowKeyCap bounds the number of distinct keys a single 10-second bucket
// may hold (CONC-04). Every key is attacker-controlled — a spoofed
// Cf-Connecting-Ip header, a rotated IPv6 source, or the raw TLS fingerprint —
// so without a cap one connection rotating identities grows the buckets until
// the proxy OOMs. Past the cap, NEW keys are dropped (the request still runs
// the rest of the pipeline); keys already in the bucket keep counting, so a
// volume flood against one identity is still ratelimited.
const windowKeyCap = 200_000

// IncrWindow increments key in the 10-second bucket ts of a sliding-window
// map, creating the bucket lazily (CONC-01). The monitor's prefill in
// evaluateRatelimit is advisory: if it ever lags past the prefilled 120 s
// horizon, a missing bucket must not turn the request path into a nil-map
// panic while holding the write lock — the lock would never be released and
// the whole proxy freezes. Caller must hold firewall.Mutex.
func IncrWindow(bucket map[int]map[string]int, ts int, key string) {
	inner, ok := bucket[ts]
	if !ok {
		inner = map[string]int{}
		bucket[ts] = inner
	}
	if _, exists := inner[key]; !exists && len(inner) >= windowKeyCap {
		return // CONC-04: bucket is full of distinct keys; drop, keep serving
	}
	inner[key]++
}

func OnStateChange(conn net.Conn, state http.ConnState) {

	remoteAddr := conn.RemoteAddr().String()

	switch state {
	case http.StateNew:
	case http.StateHijacked, http.StateClosed:
		//Remove connection from list of fingerprints as it's no longer needed
		Mutex.Lock()
		delete(Connections, remoteAddr)
		Mutex.Unlock()
	}
}
