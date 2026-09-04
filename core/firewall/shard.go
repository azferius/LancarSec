package firewall

// WAVE 12 (task B, CONC-01/CONC-04): the per-key ratelimit state moved off the
// one global RWMutex onto 16-way sharded locks.
//
// The audit recorded the request path taking firewall.Mutex three to four
// times per request, twice for writing (the sliding-window increment and the
// access-log append), so throughput inverted as cores were added - 43.7 ns/op
// at GOMAXPROCS=1 degrading to 90.9 ns/op at 16 (BENCHMARK_BASELINE.md). The
// keyed state below is what those write sections were guarding, so it now
// lives in per-key shards: requests for different keys take different locks
// and touch different map memory, while requests for the SAME key still
// serialise - the ratelimit per key must stay exact.
//
// What deliberately did NOT move: DomainsData, the fingerprint tables, the
// access-log append and the config publish stay behind firewall.Mutex (see
// general.go). They are either read-only per request, written once per second
// by the monitor, or appended to under a lock whose critical section is a
// couple of slice writes.

import (
	"slices"
	"sync"
)

const shardCount = 16

// windowShardKeyCap is CONC-04's cap as one shard sees it. The bucket the cap
// used to count is now shardCount buckets, so testing each against the whole
// windowKeyCap would multiply the memory bound by 16 - the cap is divided
// instead, which makes the global bound windowKeyCap exactly rather than
// approximately. A key space skewed onto one shard therefore starts dropping
// before the global total reaches windowKeyCap; that is the safe direction,
// and FNV-1a spreads real keys evenly enough that it is not the normal case.
const windowShardKeyCap = windowKeyCap / shardCount

// shardIndex maps a key to its shard with FNV-1a 32. It is inline rather than
// hash/fnv so the hot path stays allocation-free: the request path calls this
// once per keyed access, and converting the key to []byte for a stdlib writer
// allocates. Deterministic sharding is safe here - the worst an attacker who
// computes it can do is steer his own keys onto one shard, which is the
// behaviour this file replaces, not a property it depends on.
func shardIndex(key string) uint32 {
	var h uint32 = 2166136261
	for i := 0; i < len(key); i++ {
		h ^= uint32(key[i])
		h *= 16777619
	}
	return h % shardCount
}

// counterSet is one ratelimit counter family: the materialised per-key totals
// (what AccessIps / AccessIpsCookie / UnkFps were) plus the sliding windows
// they are rebuilt from, sharded on the key.
//
// The totals are what the request path READS (under its shard's RLock) and the
// windows are what it WRITES (under its shard's Lock) - exactly the
// read/increment pair the global lock used to serialise, now at 1/16th
// contention. The monitor is the only writer of the totals: one sweep every
// five seconds rebuilds them from the live windows and drops expired buckets,
// under every shard's write lock in index order. Production never nests shard
// locks - every keyed access takes exactly one shard for exactly one critical
// section - so the sweep's all-shards-in-order acquisition cannot deadlock
// against the request path or against OnStateChange.
//
// The maps live INSIDE the shards rather than beside the locks on purpose:
// two requests for different keys taking different shard locks but writing the
// same map would still race the map's internal state, and sharing one bucket
// array would also cache-line ping between cores - the locks and the memory
// must shard together or the sharding is cosmetic.
type counterSet struct {
	mu      [shardCount]sync.RWMutex
	counts  [shardCount]map[string]int
	windows [shardCount]map[int]map[string]int
}

// NewCounterSet builds a set with every shard's maps initialised. The old
// globals were nil until the config loaded and the sweeper pre-filled them,
// which CONC-01 records as a panic under the write lock when a request beat
// the prefill past the horizon; every shard starts fully allocated so the
// request path can never see a nil map, and NewCounterSet is exported so tests
// can swap whole sets (mwSaveGlobals) exactly like they swapped the maps.
func NewCounterSet() *counterSet {
	s := &counterSet{}
	for i := range s.counts {
		s.counts[i] = map[string]int{}
		s.windows[i] = map[int]map[string]int{}
	}
	return s
}

// Count returns the materialised total for key. Replaces the plain map read
// the request path did under the global RLock.
func (s *counterSet) Count(key string) int {
	i := shardIndex(key)
	s.mu[i].RLock()
	defer s.mu[i].RUnlock()
	return s.counts[i][key]
}

// IncrWindow increments key in the 10-second bucket ts, creating the bucket
// lazily (CONC-01: the monitor prefill is advisory - a request must never
// panic on a nil inner map while holding a lock) and dropping NEW keys once a
// shard's bucket reaches windowShardKeyCap (CONC-04: a request flood of distinct keys is a
// memory amplifier, not just an address churn). EXISTING keys keep counting
// past the cap: the per-key ratelimit must stay exact for the keys that are
// already being tracked.
func (s *counterSet) IncrWindow(ts int, key string) {
	i := shardIndex(key)
	s.mu[i].Lock()
	defer s.mu[i].Unlock()

	bucket, ok := s.windows[i][ts]
	if !ok {
		bucket = map[string]int{}
		s.windows[i][ts] = bucket
	}
	if _, exists := bucket[key]; !exists && len(bucket) >= windowShardKeyCap {
		return
	}
	bucket[key]++
}

// Stats returns (distinct keys, total requests) across every shard. Replaces
// api.go's len+sum over the old maps, which it did under the global RLock;
// here each shard is read under its own RLock. Not a consistent snapshot
// across shards - no caller needs one, and the all-shards-in-order write lock
// would hold the request path off every key for the length of the walk.
func (s *counterSet) Stats() (keys int, requests int) {
	for i := range s.counts {
		s.mu[i].RLock()
		keys += len(s.counts[i])
		for _, total := range s.counts[i] {
			requests += total
		}
		s.mu[i].RUnlock()
	}
	return keys, requests
}

// CopyCounts returns every shard's (key -> total) as one snapshot. Replaces
// GET_FINGERPRINT_REQUESTS's copy of UnkFps under the global RLock.
func (s *counterSet) CopyCounts() map[string]int {
	out := make(map[string]int, 64)
	for i := range s.counts {
		s.mu[i].RLock()
		for key, total := range s.counts[i] {
			out[key] = total
		}
		s.mu[i].RUnlock()
	}
	return out
}

// Sweep runs the monitor's per-family rebuild: pre-fill the live 120-second
// bucket horizon (so the request path mostly finds buckets already created),
// rebuild the totals from the windows that are still inside the ratelimit
// window, and drop expired buckets. Replaces the body of
// evaluateRatelimit, which did this for all three families under ONE global
// write lock - the total request path's keys blocked behind a once-per-five-
// seconds map rebuild.
//
// window is the ratelimit window in seconds (proxy.RatelimitWindow), passed in
// rather than read from core/proxy: firewall must not import proxy, and the
// owner of the window is the config, whose caller already has it.
//
// Each shard is taken in index order and released before the next one is
// taken, so the sweep never holds two shards at once and a request only ever
// waits for the single shard its key lives on. No request holds two shards
// either, so no lock cycle can form.
func (s *counterSet) Sweep(now, last10, window int) {
	for i := range s.counts {
		s.mu[i].Lock()

		//Initialise Maps before they're ever written, as to save if statements during potential attack
		for ts := last10; ts < last10+120; ts = ts + 10 {
			if s.windows[i][ts] == nil {
				s.windows[i][ts] = map[string]int{}
			}
		}

		// Delete outdated records & calculate requests for every key
		rebuilt := map[string]int{}
		for ts, bucket := range s.windows[i] {
			if ts+window < now {
				delete(s.windows[i], ts)
				continue
			}
			for key, requests := range bucket {
				rebuilt[key] += requests
			}
		}
		s.counts[i] = rebuilt

		s.mu[i].Unlock()
	}
}

// WindowCount returns key's count in bucket ts. Test-only read of the window
// state the request path wrote, replacing the direct WindowAccessIps[ts][key]
// the middleware tests asserted with.
func (s *counterSet) WindowCount(ts int, key string) int {
	i := shardIndex(key)
	s.mu[i].RLock()
	defer s.mu[i].RUnlock()
	return s.windows[i][ts][key]
}

// WindowKeyCount returns how many keys bucket ts holds. Test-only, replacing
// len(WindowAccessIps[ts]) in the cap tests.
func (s *counterSet) WindowKeyCount(ts int) int {
	n := 0
	for i := range s.windows {
		s.mu[i].RLock()
		n += len(s.windows[i][ts])
		s.mu[i].RUnlock()
	}
	return n
}

// Set sets key's materialised total to n. Test-only, replacing the direct map
// pokes (firewall.AccessIps[mwIP] = proxy.IPRatelimit+1) the tests used to
// simulate ratelimited clients with.
func (s *counterSet) Set(key string, n int) {
	i := shardIndex(key)
	s.mu[i].Lock()
	defer s.mu[i].Unlock()
	s.counts[i][key] = n
}

// DropWindow deletes bucket ts from every shard. Test-only, replacing the
// direct delete(WindowAccessIps, ts) the lazy-bucket test used.
func (s *counterSet) DropWindow(ts int) {
	for i := range s.windows {
		s.mu[i].Lock()
		delete(s.windows[i], ts)
		s.mu[i].Unlock()
	}
}

// AddWindow seeds key's count in bucket ts. Test-only, replacing the direct
// WindowAccessIps[ts] = map[string]int{key: n} seeding the monitor tests did.
func (s *counterSet) AddWindow(ts int, key string, n int) {
	i := shardIndex(key)
	s.mu[i].Lock()
	defer s.mu[i].Unlock()
	bucket, ok := s.windows[i][ts]
	if !ok {
		bucket = map[string]int{}
		s.windows[i][ts] = bucket
	}
	bucket[key] += n
}

// WindowTimestamps returns every bucket ts that exists in any shard, sorted.
// Test-only, replacing slices.Sorted(maps.Keys(WindowAccessIps)) in the
// monitor tests.
func (s *counterSet) WindowTimestamps() []int {
	seen := map[int]struct{}{}
	for i := range s.windows {
		s.mu[i].RLock()
		for ts := range s.windows[i] {
			seen[ts] = struct{}{}
		}
		s.mu[i].RUnlock()
	}
	out := make([]int, 0, len(seen))
	for ts := range seen {
		out = append(out, ts)
	}
	slices.Sort(out)
	return out
}

// The three keyed ratelimit families, replacing the old package globals. Each
// is its own counterSet so that the ip and fingerprint key spaces shard
// independently: the same shard index computed for a rateKey and for a tlsFp
// is coincidental, not shared, because the locks and maps are per-family.
//
// IPs and IPsCookie are the SAME key space (rateKey, the /64-granular ratelimit
// bucket) but they stay in separate sets rather than one set with two counters
// per shard: the request path reads both under two RLocks, and two short
// RLocks at 1/16th contention cost less than one wider critical section that
// both R1 and R2 contend on. CONC-04's cap is applied per family either way.
var (
	IPs         = NewCounterSet()
	IPsCookie   = NewCounterSet()
	UnkFps      = NewCounterSet()
	Connections = NewConnSet()
)

// connSet is the TLS fingerprint remembered per CONNECTION, keyed on the raw
// socket address. Written once per handshake (fingerprint.go), read once per
// request (middleware.go), deleted on socket state changes (OnStateChange).
// A handshake per connection means the write rate is bounded by connection
// churn, so the old global-lock write section here was never the measured
// bottleneck - but it was the one remaining keyed write behind firewall.Mutex,
// and its reads contended with DomainsData lookups, so it moves to its own
// shards too.
type connSet struct {
	mu [shardCount]sync.RWMutex
	m  [shardCount]map[string]string
}

// NewConnSet builds a set with every shard's map initialised, for the same
// CONC-01 reason as NewCounterSet.
func NewConnSet() *connSet {
	c := &connSet{}
	for i := range c.m {
		c.m[i] = map[string]string{}
	}
	return c
}

// Get returns the fingerprint remembered for the socket address, and whether
// there was one.
func (c *connSet) Get(addr string) (string, bool) {
	i := shardIndex(addr)
	c.mu[i].RLock()
	defer c.mu[i].RUnlock()
	fp, ok := c.m[i][addr]
	return fp, ok
}

// Set remembers the fingerprint for a socket address. Replaces the global
// Mutex section in Fingerprint.
func (c *connSet) Set(addr, fp string) {
	i := shardIndex(addr)
	c.mu[i].Lock()
	defer c.mu[i].Unlock()
	c.m[i][addr] = fp
}

// Delete forgets a socket address. Replaces the global Mutex section in
// OnStateChange.
func (c *connSet) Delete(addr string) {
	i := shardIndex(addr)
	c.mu[i].Lock()
	defer c.mu[i].Unlock()
	delete(c.m[i], addr)
}

// Len counts every entry across all shards. Test-only, replacing the
// len(Connections) the fingerprint tests asserted with.
func (c *connSet) Len() int {
	n := 0
	for i := range c.m {
		c.mu[i].RLock()
		n += len(c.m[i])
		c.mu[i].RUnlock()
	}
	return n
}

// Range walks every entry across all shards. Test-only.
func (c *connSet) Range(fn func(addr, fp string)) {
	for i := range c.m {
		c.mu[i].RLock()
		for addr, fp := range c.m[i] {
			fn(addr, fp)
		}
		c.mu[i].RUnlock()
	}
}

// Reset empties every shard. Test-only, replacing the swap of the old map in
// withCleanConnections.
func (c *connSet) Reset() {
	for i := range c.m {
		c.mu[i].Lock()
		c.m[i] = map[string]string{}
		c.mu[i].Unlock()
	}
}

// LockShard takes the write lock of the shard addr hashes to, and returns the
// unlock function. Test-only: TestOnStateChangeEvictionHoldsTheMutex used to
// hold firewall.Mutex to prove the eviction actually takes a lock; with
// sharded locks the eviction takes the SHARD, so the test holds the shard
// instead - holding the global lock would no longer block it, and the
// assertion would fail for a reason that has nothing to do with correctness.
func (c *connSet) LockShard(addr string) func() {
	i := shardIndex(addr)
	c.mu[i].Lock()
	return func() { c.mu[i].Unlock() }
}

// peekLocked reads a shard the caller already holds the lock on, without
// taking it again. Test-only, and the counterpart to LockShard: Get would
// re-take that shard's RLock, which self-deadlocks against the caller's own
// write lock (and, because a blocked writer queues ahead of new readers, would
// deadlock even against a caller holding only the read lock).
func (c *connSet) peekLocked(addr string) (string, bool) {
	fp, ok := c.m[shardIndex(addr)][addr]
	return fp, ok
}
