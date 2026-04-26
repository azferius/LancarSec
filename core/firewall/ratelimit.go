package firewall

import (
	"lancarsec/core/pnc"
	"lancarsec/core/proxy"
	"time"
)

// MaxBucketKeys bounds the per-bucket map size so a high-cardinality attack
// (e.g. each request from a fresh IPv6 address) can't explode the ratelimit
// window into a multi-GB memory footprint. Above this cap, new keys are
// dropped from counting — the attacker still hits other defenses.
const MaxBucketKeys = 200_000

// Incr bumps window[bucket][key] atomically with respect to readers by
// taking CountersMu, but additionally drops the increment if the bucket is
// already at MaxBucketKeys to keep memory bounded under high-cardinality
// attacks. Returns true if the increment happened (i.e. the key is tracked).
func Incr(window map[int]map[string]int, bucket int, key string) bool {
	CountersMu.Lock()
	defer CountersMu.Unlock()
	b, ok := window[bucket]
	if !ok {
		b = make(map[string]int, 64)
		window[bucket] = b
	}
	if _, tracked := b[key]; !tracked && len(b) >= MaxBucketKeys {
		return false
	}
	b[key]++
	return true
}

// trimTime rounds a unix-seconds value down to the nearest 10-second bucket.
// Inlined here (was utils.TrimTime) so the firewall package stays leaf-level
// and does not pull in utils, which would cycle back through proxy.
func trimTime(timestamp int) int { return (timestamp / 10) * 10 }

// SumWindow returns the live per-key count by summing the sliding window
// buckets in one pass. The hot path in middleware calls this instead of
// reading AccessIps / AccessIpsCookie / UnkFps, because those cached maps
// are only rebuilt every 5 s — between rebuilds an attacker can send
// unbounded requests without the ratelimit view advancing. The caller must
// hold CountersMu at least for read.
//
// keyBuf is optional: passing a non-nil map avoids an allocation when the
// caller is polling several counters in a row. Returns 0 if the key is
// absent or the window empty.
func SumWindow(window map[int]map[string]int, key string, windowSeconds, now int) int {
	horizon := now - windowSeconds
	total := 0
	for bucketTime, bucket := range window {
		if trimTime(bucketTime) < horizon {
			continue
		}
		total += bucket[key]
	}
	return total
}

// EvaluateRatelimit rebuilds the IP/fingerprint counter maps from the sliding
// window buckets every 5 seconds. Old buckets are dropped; live ones are
// summed so middleware can read a single map without iterating windows.
func EvaluateRatelimit() {
	defer pnc.PanicHndl()

	for {
		CountersMu.Lock()
		// Pre-initialize the next 120 seconds of buckets so the hot path can
		// write without allocating.
		last10 := proxy.GetLast10SecondTimestamp()
		for i := last10; i < last10+120; i += 10 {
			if WindowAccessIps[i] == nil {
				WindowAccessIps[i] = map[string]int{}
			}
			if WindowAccessIpsCookie[i] == nil {
				WindowAccessIpsCookie[i] = map[string]int{}
			}
			if WindowUnkFps[i] == nil {
				WindowUnkFps[i] = map[string]int{}
			}
			if WindowPathLimits[i] == nil {
				WindowPathLimits[i] = map[string]int{}
			}
		}

		AccessIps = rebuildCounter(WindowAccessIps)
		AccessIpsCookie = rebuildCounter(WindowAccessIpsCookie)
		UnkFps = rebuildCounter(WindowUnkFps)
		// WindowPathLimits has no rebuilt-summary map exposed to middleware —
		// path evaluation reads SumWindow directly per rule. We still call
		// rebuildCounter so the expiry sweep runs on it.
		_ = rebuildCounter(WindowPathLimits)
		CountersMu.Unlock()

		proxy.SetInitialised(true)
		time.Sleep(5 * time.Second)
	}
}

// rebuildCounter drops expired windows and sums live ones into a fresh map.
// Caller must hold Mutex for writes.
func rebuildCounter(windows map[int]map[string]int) map[string]int {
	result := map[string]int{}
	now := proxy.GetLastSecondTimestamp()
	for windowTime, bucket := range windows {
		if trimTime(windowTime)+proxy.RatelimitWindow < now {
			delete(windows, windowTime)
			continue
		}
		for key, count := range bucket {
			result[key] += count
		}
	}
	return result
}
