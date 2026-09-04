package firewall

import (
	"net"
	"net/http"
	"sync"
)

var (
	// Mutex guards everything that is NOT keyed per client: the DomainsData
	// table and its per-domain mutable fields, the fingerprint tables
	// (KnownFingerprints / BotFingerprints / ForbiddenFingerprints), the
	// access-log append and the config publish. The per-key ratelimit state
	// and the per-connection fingerprints live on sharded locks now - see
	// shard.go; CONC-01/CONC-04 moved there with them.
	Mutex = &sync.RWMutex{}

	//"cache" encryption result of ips for 2 minutes in order to have less load on the proxy
	//Using syncMap here instead of CacheIps = map[string]string{}, since this value should only be written to once per 2 minutes and readonly the rest of the time
	CacheIps = sync.Map{}
)

// windowKeyCap bounds the number of distinct keys a single 10-second bucket
// may hold (CONC-04). Every key is attacker-controlled — a spoofed
// Cf-Connecting-Ip header, a rotated IPv6 source, or the raw TLS fingerprint —
// so without a cap one connection rotating identities grows the buckets until
// the proxy OOMs. Past the cap, NEW keys are dropped (the request still runs
// the rest of the pipeline); keys already in the bucket keep counting, so a
// volume flood against one identity is still ratelimited.
// Enforced per shard as windowShardKeyCap (shard.go), so this stays the bound
// on the whole bucket.
const windowKeyCap = 200_000

func OnStateChange(conn net.Conn, state http.ConnState) {

	remoteAddr := conn.RemoteAddr().String()

	switch state {
	case http.StateNew:
	case http.StateHijacked, http.StateClosed:
		//Remove connection from list of fingerprints as it's no longer needed
		Connections.Delete(remoteAddr)
	}
}
