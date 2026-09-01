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
	bucket := map[int]map[string]int{}
	IncrWindow(bucket, 100, "1.2.3.4")
	IncrWindow(bucket, 100, "1.2.3.4")
	if got := bucket[100]["1.2.3.4"]; got != 2 {
		t.Fatalf("bucket[100][1.2.3.4] = %d, want 2", got)
	}
	// A second timestamp gets its own bucket; the first is untouched.
	IncrWindow(bucket, 110, "5.6.7.8")
	if got := bucket[110]["5.6.7.8"]; got != 1 {
		t.Fatalf("bucket[110][5.6.7.8] = %d, want 1", got)
	}
	if got := bucket[100]["5.6.7.8"]; got != 0 {
		t.Fatalf("bucket[100][5.6.7.8] = %d, want 0", got)
	}
}

// CONC-04: once a bucket holds windowKeyCap distinct keys, NEW keys are
// dropped while keys already present keep counting.
func TestIncrWindowDropsNewKeysAtCap(t *testing.T) {
	bucket := map[int]map[string]int{}
	for i := 0; i < windowKeyCap; i++ {
		IncrWindow(bucket, 100, strconv.Itoa(i))
	}
	if len(bucket[100]) != windowKeyCap {
		t.Fatalf("bucket holds %d keys, want %d", len(bucket[100]), windowKeyCap)
	}
	IncrWindow(bucket, 100, "overflow")
	if got := bucket[100]["overflow"]; got != 0 {
		t.Fatalf("overflow key = %d, want 0 (dropped at cap)", got)
	}
	if len(bucket[100]) != windowKeyCap {
		t.Fatalf("bucket grew to %d keys past the cap", len(bucket[100]))
	}
}

// CONC-04 edge: the cap check is on EXISTENCE, not on the increment, so a key
// already in a full bucket still increments.
func TestIncrWindowCountsExistingKeysPastCap(t *testing.T) {
	bucket := map[int]map[string]int{100: {}}
	for i := 0; i < windowKeyCap; i++ {
		IncrWindow(bucket, 100, strconv.Itoa(i))
	}
	IncrWindow(bucket, 100, "0") // existing key on a full bucket
	if got := bucket[100]["0"]; got != 2 {
		t.Fatalf("existing key = %d, want 2 (must still count past the cap)", got)
	}
}

// Separate buckets are capped independently.
func TestIncrWindowCapIsPerBucket(t *testing.T) {
	bucket := map[int]map[string]int{}
	for i := 0; i < windowKeyCap; i++ {
		IncrWindow(bucket, 100, strconv.Itoa(i))
	}
	IncrWindow(bucket, 110, "overflow") // different ts, fresh cap
	if got := bucket[110]["overflow"]; got != 1 {
		t.Fatalf("overflow on a fresh bucket = %d, want 1", got)
	}
}
