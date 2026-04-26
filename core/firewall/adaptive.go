package firewall

import (
	"sync"
	"sync/atomic"
	"time"
)

// Adaptive PoW difficulty — the Stage 2 JavaScript proof-of-work scales
// with the current attack intensity instead of staying at a fixed
// per-domain number. Idle traffic gets the configured base (typically 5,
// ~3 seconds of browser compute). A bypassing attack bumps it up so each
// attacker-client pays more CPU to earn a pass; the baseline stays
// exactly where the domain config put it for normal visitors.
//
// Difficulty is hex-digit length of the PoW suffix, so work scales as
// 16^N. Going from 5 -> 6 is a 16× cost; 5 -> 7 is 256×. We cap the
// ceiling to avoid pinning real browsers for minutes.
//
// Per-domain ceiling decisions are cheap atomics; the setting is read on
// every Stage 2 challenge render in middleware.
var perDomainDifficulty atomic.Value // map[string]int

func init() {
	perDomainDifficulty.Store(map[string]int{})
}

// SetDifficulty publishes an effective difficulty for a domain. Called
// from the monitor loop when checkAttack observes bypass_attack, and again
// when the attack subsides. Concurrent-safe because the map is
// atomically replaced, never mutated in place.
func SetDifficulty(domain string, value int) {
	cur := perDomainDifficulty.Load().(map[string]int)
	if cur[domain] == value {
		return
	}
	next := make(map[string]int, len(cur)+1)
	for k, v := range cur {
		next[k] = v
	}
	next[domain] = value
	perDomainDifficulty.Store(next)
}

// DifficultyFor returns the current effective Stage 2 difficulty for a
// domain. Callers pass the config base value as fallback — when no
// adaptive bump is in place the base is used unchanged.
func DifficultyFor(domain string, base int) int {
	if base <= 0 {
		base = 5
	}
	if base > MaxDifficulty {
		base = MaxDifficulty
	}
	cur := perDomainDifficulty.Load().(map[string]int)
	if v, ok := cur[domain]; ok && v > 0 {
		if v > MaxDifficulty {
			return MaxDifficulty
		}
		return v
	}
	return base
}

// AdaptDifficulty decides a new difficulty based on current attack state
// + bypass rate. Called from checkAttack once per second per domain.
//
//	idle, stage 1          -> base
//	raw attack, no bypass  -> base (stage 2 not even shown)
//	bypass attack, mild    -> base + 1  (16× cost)
//	bypass attack, heavy   -> base + 2  (256× cost)
//	bypass attack, extreme -> base + 3  (4096× cost, capped at MaxDifficulty)
//
// "heavy" = bypass r/s above 10× the configured BypassStage1.
// "extreme" = bypass r/s above 50× that threshold. Those multipliers are
// deliberately generous so normal human bursts don't trip the cap — the
// proxy can always be forced into a specific stage manually.
const MaxDifficulty = 8

func AdaptDifficulty(domain string, base int, bypassing bool, bypassRPS, bypassStage1 int) int {
	if base <= 0 {
		base = 5
	}
	if base > MaxDifficulty {
		base = MaxDifficulty
	}
	if !bypassing || bypassRPS <= 0 {
		return base
	}
	threshold := bypassStage1
	if threshold <= 0 {
		threshold = 20
	}
	bump := 1
	if bypassRPS >= threshold*10 {
		bump = 2
	}
	if bypassRPS >= threshold*50 {
		bump = 3
	}
	target := base + bump
	if target > MaxDifficulty {
		target = MaxDifficulty
	}
	return target
}

// Per-IP escalation. When a single IP keeps failing the Stage 2 cookie
// challenge we want to raise THAT IP's effective difficulty without
// punishing every other Stage 2 visitor on the same domain. The bump is
// additive on top of DifficultyFor's per-domain adaptive value, capped at
// MaxDifficulty, and decays after a short TTL when the IP stops failing.
//
// This complements AdaptDifficulty (which reacts to aggregate traffic):
// AdaptDifficulty raises the floor for everybody during a heavy bypass
// attack, while the per-IP bump surgically punishes the IPs actually
// driving that bypass volume.

const (
	// IPBumpThreshold is the number of cookie-failures within the rate
	// window that triggers a +1 bump for the offending IP.
	IPBumpThreshold = 8

	// IPBumpHeavyThreshold triggers the maximum +IPBumpMaxStack bump
	// (~16^stack× cost vs base). Crossed by sustained bot retry loops.
	IPBumpHeavyThreshold = 25

	// IPBumpMaxStack caps how many extra levels one IP can stack on top
	// of the per-domain difficulty. Three levels = 4096× extra work for
	// the attacker; legitimate humans who fail once or twice never hit it.
	IPBumpMaxStack = 3

	// IPBumpTTL is how long a bump stays active without further failures.
	// Decay happens via the periodic ClearProxyCache sweep.
	IPBumpTTL = 5 * time.Minute
)

type ipBump struct {
	level     int
	expiresAt time.Time
}

// ipDifficultyBumps maps a client IP to its current bump record. sync.Map
// fits because an attacking IP writes once per failed challenge but reads
// once per Stage 2 render — write-rare, read-often. Cardinality is bounded
// by the attacking-IP fleet minus natural decay, well under any sane limit
// in practice.
var ipDifficultyBumps sync.Map

// BumpIPDifficultyOn observes a cookie-failure event and updates the bump
// for the given IP. count is the post-increment failure count read off the
// sliding window. Returns the bump level now active for the IP (0/1/2/3).
// Idempotent within the TTL: repeated failures refresh the expiry rather
// than linearly stacking.
func BumpIPDifficultyOn(ip string, count int) int {
	if ip == "" {
		return 0
	}
	var level int
	switch {
	case count >= IPBumpHeavyThreshold:
		level = IPBumpMaxStack
	case count >= IPBumpThreshold:
		level = 1
	default:
		return 0
	}
	ipDifficultyBumps.Store(ip, ipBump{
		level:     level,
		expiresAt: time.Now().Add(IPBumpTTL),
	})
	return level
}

// IPDifficultyBumpFor returns the active per-IP bump level. 0 means no
// bump or the previous bump has expired. Called on every Stage 2 render
// so the lookup is a single sync.Map read plus a deadline compare.
func IPDifficultyBumpFor(ip string) int {
	if ip == "" {
		return 0
	}
	v, ok := ipDifficultyBumps.Load(ip)
	if !ok {
		return 0
	}
	b := v.(ipBump)
	if time.Now().After(b.expiresAt) {
		ipDifficultyBumps.Delete(ip)
		return 0
	}
	return b.level
}

// SweepIPDifficulty drops expired bumps. Bound the map size under sustained
// IP rotation. Called from ClearProxyCache on its 2-min ticker.
func SweepIPDifficulty() {
	now := time.Now()
	ipDifficultyBumps.Range(func(k, v any) bool {
		if v.(ipBump).expiresAt.Before(now) {
			ipDifficultyBumps.Delete(k)
		}
		return true
	})
}

// EffectiveDifficulty composes the per-domain adaptive difficulty with the
// per-IP bump for one specific request. Use at challenge render time so a
// repeatedly-failing IP earns a harder Stage 2 puzzle than the rest of the
// domain's traffic. Cap at MaxDifficulty so the JS PoW remains solvable
// for real browsers no matter how many bumps stack.
func EffectiveDifficulty(domain, ip string, base int) int {
	d := DifficultyFor(domain, base)
	bump := IPDifficultyBumpFor(ip)
	if bump <= 0 {
		return d
	}
	if d+bump > MaxDifficulty {
		return MaxDifficulty
	}
	return d + bump
}
