package firewall

import (
	"sync/atomic"
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
	cur := perDomainDifficulty.Load().(map[string]int)
	if v, ok := cur[domain]; ok && v > 0 {
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
