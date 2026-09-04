package firewall

import (
	"strconv"
	"testing"
)

// CONC-01: a missing bucket is created lazily. This is the regression test for
// the nil-map panic that used to freeze the proxy — the request path used to
// write WindowAccessIps[ts][ip]++ with the inner map created only by the
// monitor's prefill, so a lagging monitor meant "assignment to entry in nil
// map" while holding the write lock, which was never released.
func TestIncrWindowCreatesMissingBucket(t *testing.T) {
	set := NewCounterSet()
	set.IncrWindow(100, "1.2.3.4")
	set.IncrWindow(100, "1.2.3.4")
	if got := set.WindowCount(100, "1.2.3.4"); got != 2 {
		t.Fatalf("bucket[100][1.2.3.4] = %d, want 2", got)
	}
	// A second timestamp gets its own bucket; the first is untouched.
	set.IncrWindow(110, "5.6.7.8")
	if got := set.WindowCount(110, "5.6.7.8"); got != 1 {
		t.Fatalf("bucket[110][5.6.7.8] = %d, want 1", got)
	}
	if got := set.WindowCount(100, "5.6.7.8"); got != 0 {
		t.Fatalf("bucket[100][5.6.7.8] = %d, want 0", got)
	}
}

// keysForShard returns n distinct keys that all hash to shard target. The cap
// tests fill exactly one shard with it: since wave 12 the cap is enforced per
// shard, so feeding in sequential keys would test whichever shard FNV-1a
// happened to fill first and would say nothing about the bound.
func keysForShard(target uint32, n int) []string {
	keys := make([]string, 0, n)
	for i := 0; len(keys) < n; i++ {
		if k := strconv.Itoa(i); shardIndex(k) == target {
			keys = append(keys, k)
		}
	}
	return keys
}

// CONC-04: once a shard's bucket holds windowShardKeyCap distinct keys, NEW
// keys on that shard are dropped while other shards keep accepting. The set's
// bound is shardCount * windowShardKeyCap == windowKeyCap.
func TestIncrWindowDropsNewKeysAtCap(t *testing.T) {
	set := NewCounterSet()
	keys := keysForShard(0, windowShardKeyCap+1)
	for _, k := range keys[:windowShardKeyCap] {
		set.IncrWindow(100, k)
	}
	if got := set.WindowKeyCount(100); got != windowShardKeyCap {
		t.Fatalf("bucket holds %d keys, want %d", got, windowShardKeyCap)
	}

	overflow := keys[windowShardKeyCap]
	set.IncrWindow(100, overflow)
	if got := set.WindowCount(100, overflow); got != 0 {
		t.Fatalf("overflow key = %d, want 0 (dropped at cap)", got)
	}
	if got := set.WindowKeyCount(100); got != windowShardKeyCap {
		t.Fatalf("bucket grew to %d keys past the cap", got)
	}

	// A key on a shard that is not full still lands -- the cap bounds each
	// shard, and a full shard must not block the other fifteen.
	other := keysForShard(1, 1)[0]
	set.IncrWindow(100, other)
	if got := set.WindowCount(100, other); got != 1 {
		t.Fatalf("key on an unfilled shard = %d, want 1", got)
	}
	if got := set.WindowKeyCount(100); got != windowShardKeyCap+1 {
		t.Fatalf("set holds %d keys, want %d", got, windowShardKeyCap+1)
	}
}

// The cap tests above all fill exactly ONE shard and compare against
// windowShardKeyCap, so they use the constant on both sides and pass whatever
// its value is. This is what pins the actual memory bound: shardCount shards of
// windowShardKeyCap must add up to windowKeyCap, not to a multiple of it.
// Without it, enforcing the whole windowKeyCap per shard - the obvious reading
// of the pre-wave-12 code - silently multiplies the bound by 16 and every other
// test still passes.
func TestWindowKeyCapIsDividedAcrossShards(t *testing.T) {
	if got := shardCount * windowShardKeyCap; got != windowKeyCap {
		t.Errorf("all shards together hold %d keys, want windowKeyCap = %d", got, windowKeyCap)
	}
}

// CONC-04 edge: the cap check is on EXISTENCE, not on the increment, so a key
// already in a full shard still increments.
func TestIncrWindowCountsExistingKeysPastCap(t *testing.T) {
	set := NewCounterSet()
	keys := keysForShard(0, windowShardKeyCap)
	for _, k := range keys {
		set.IncrWindow(100, k)
	}
	set.IncrWindow(100, keys[0]) // existing key on a full shard
	if got := set.WindowCount(100, keys[0]); got != 2 {
		t.Fatalf("existing key = %d, want 2 (must still count past the cap)", got)
	}
}

// Separate buckets are capped independently.
func TestIncrWindowCapIsPerBucket(t *testing.T) {
	set := NewCounterSet()
	keys := keysForShard(0, windowShardKeyCap+1)
	for _, k := range keys[:windowShardKeyCap] {
		set.IncrWindow(100, k)
	}
	set.IncrWindow(110, keys[windowShardKeyCap]) // different ts, fresh cap
	if got := set.WindowCount(110, keys[windowShardKeyCap]); got != 1 {
		t.Fatalf("overflow on a fresh bucket = %d, want 1", got)
	}
}
