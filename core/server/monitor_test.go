package server

// Wave 3 tripwire tests for core/server/monitor.go.
//
// SCOPE / OWNERSHIP: this file owns TestRatelimit* and TestMonitor*. Every
// helper defined here is prefixed `rl` so it cannot collide with the
// middleware_test.go that shares package `server`.
//
// HONESTY NOTE (read this before trusting the ratelimit coverage below):
// `evaluateRatelimit` is `for { ...; time.Sleep(5 * time.Second) }`. It cannot
// be called from a test without either leaking a goroutine that keeps mutating
// package globals underneath every later test in this package (guaranteed
// -race failures) or parking it on firewall.Mutex forever (guaranteed deadlock
// of the whole test binary). So the sliding-window arithmetic below is driven
// through `rlPrefillWindows` + `rlSweepWindows`, which are a line-for-line
// transcription of the loop body. That makes these tests a SPEC, not a direct
// exercise of the shipped code: if wave 7 changes evaluateRatelimit without
// changing this file, these tests keep passing. They are still the right
// tripwire, because wave 7 is expected to delete the transcription along with
// the original and a reviewer diffing this file sees exactly which arithmetic
// was replaced. Read `blockers` in the wave 3 report for the full caveat.
//
// Directly exercised (real production functions, no transcription):
//   utils.TrimTime, checkAttack, and the nil-map write shape from
//   middleware.go:96.

import (
	"fmt"
	"maps"
	"slices"
	"strings"
	"testing"

	"github.com/azferius/lancarsec/core/domains"
	"github.com/azferius/lancarsec/core/firewall"
	"github.com/azferius/lancarsec/core/proxy"
	"github.com/azferius/lancarsec/core/utils"
)

// rlBase is a fixed, 10-aligned unix timestamp. Nothing in these tests reads
// the wall clock; every timestamp is derived from this constant.
const rlBase = 1700000000

// ---------------------------------------------------------------------------
// helpers (all `rl`-prefixed; see ownership note above)
// ---------------------------------------------------------------------------

// rlSnapshotGlobals saves and restores every package-level global the ratelimit
// arithmetic touches. evaluateRatelimit replaces the AccessIps/AccessIpsCookie/
// UnkFps map VARIABLES wholesale each pass, so saving the variables (not their
// contents) is what restores correctly.
func rlSnapshotGlobals(t *testing.T) {
	t.Helper()

	oldWindowAccessIps := firewall.WindowAccessIps
	oldWindowAccessIpsCookie := firewall.WindowAccessIpsCookie
	oldWindowUnkFps := firewall.WindowUnkFps
	oldAccessIps := firewall.AccessIps
	oldAccessIpsCookie := firewall.AccessIpsCookie
	oldUnkFps := firewall.UnkFps

	oldLast10 := proxy.Last10SecondTimestamp
	oldLastSecond := proxy.LastSecondTimestamp
	oldWindow := proxy.RatelimitWindow
	oldInitialised := proxy.Initialised

	t.Cleanup(func() {
		firewall.WindowAccessIps = oldWindowAccessIps
		firewall.WindowAccessIpsCookie = oldWindowAccessIpsCookie
		firewall.WindowUnkFps = oldWindowUnkFps
		firewall.AccessIps = oldAccessIps
		firewall.AccessIpsCookie = oldAccessIpsCookie
		firewall.UnkFps = oldUnkFps

		proxy.Last10SecondTimestamp = oldLast10
		proxy.LastSecondTimestamp = oldLastSecond
		proxy.RatelimitWindow = oldWindow
		proxy.Initialised = oldInitialised
	})

	firewall.WindowAccessIps = map[int]map[string]int{}
	firewall.WindowAccessIpsCookie = map[int]map[string]int{}
	firewall.WindowUnkFps = map[int]map[string]int{}
	firewall.AccessIps = map[string]int{}
	firewall.AccessIpsCookie = map[string]int{}
	firewall.UnkFps = map[string]int{}
	proxy.RatelimitWindow = 120
}

// rlPrefillWindows is a verbatim transcription of the bucket-prefill loop at
// the top of evaluateRatelimit's body. Note the hardcoded literal 120 — it is
// NOT proxy.RatelimitWindow. TestRatelimitPrefillIgnoresConfiguredWindow pins
// that divergence.
func rlPrefillWindows() {
	for i := proxy.Last10SecondTimestamp; i < proxy.Last10SecondTimestamp+120; i = i + 10 {
		if firewall.WindowAccessIps[i] == nil {
			firewall.WindowAccessIps[i] = map[string]int{}
		}
		if firewall.WindowAccessIpsCookie[i] == nil {
			firewall.WindowAccessIpsCookie[i] = map[string]int{}
		}
		if firewall.WindowUnkFps[i] == nil {
			firewall.WindowUnkFps[i] = map[string]int{}
		}
	}
}

// rlSweepWindows is a verbatim transcription of evaluateRatelimit's expiry +
// summation pass. The lock, the `proxy.Initialised = true` publish and the
// 5-second sleep are the only parts omitted.
func rlSweepWindows() {
	firewall.AccessIps = map[string]int{}
	for windowTime, accessIPs := range firewall.WindowAccessIps {
		if utils.TrimTime(windowTime)+proxy.RatelimitWindow < proxy.LastSecondTimestamp {
			delete(firewall.WindowAccessIps, windowTime)
		} else {
			for IP, requests := range accessIPs {
				firewall.AccessIps[IP] += requests
			}
		}
	}
	firewall.AccessIpsCookie = map[string]int{}
	for windowTime, accessIPsCookie := range firewall.WindowAccessIpsCookie {
		if utils.TrimTime(windowTime)+proxy.RatelimitWindow < proxy.LastSecondTimestamp {
			delete(firewall.WindowAccessIpsCookie, windowTime)
		} else {
			for IP, requests := range accessIPsCookie {
				firewall.AccessIpsCookie[IP] += requests
			}
		}
	}
	firewall.UnkFps = map[string]int{}
	for windowTime, unkFps := range firewall.WindowUnkFps {
		if utils.TrimTime(windowTime)+proxy.RatelimitWindow < proxy.LastSecondTimestamp {
			delete(firewall.WindowUnkFps, windowTime)
		} else {
			for IP, requests := range unkFps {
				firewall.UnkFps[IP] += requests
			}
		}
	}
}

// rlPass runs one complete evaluateRatelimit iteration body.
func rlPass() {
	rlPrefillWindows()
	rlSweepWindows()
}

func rlBucketKeys(m map[int]map[string]int) []int {
	return slices.Sorted(maps.Keys(m))
}

// rlMustPanic runs fn and returns the recovered value formatted as a string.
// It fails the test if fn did not panic. It deliberately takes NO lock, so a
// panic recovered here can never strand firewall.Mutex and hang the binary.
func rlMustPanic(t *testing.T, fn func()) (msg string) {
	t.Helper()
	panicked := false
	func() {
		defer func() {
			if r := recover(); r != nil {
				panicked = true
				msg = rlPanicString(r)
			}
		}()
		fn()
	}()
	if !panicked {
		t.Fatal("expected a panic, got none")
	}
	return msg
}

func rlPanicString(v any) string {
	switch p := v.(type) {
	case error:
		return p.Error()
	case string:
		return p
	default:
		return fmt.Sprintf("%v", p)
	}
}

// ---------------------------------------------------------------------------
// utils.TrimTime — the bucket-boundary helper the whole window scheme rests on.
// Called directly; no transcription. (Duplicate coverage with the utils agent
// is intentional and allowed.)
// ---------------------------------------------------------------------------

func TestRatelimitTrimTimeBucketBoundaries(t *testing.T) {
	tests := []struct {
		name string
		in   int
		want int
	}{
		{name: "zero", in: 0, want: 0},
		{name: "just below first boundary", in: 9, want: 0},
		{name: "exact boundary", in: 10, want: 10},
		{name: "one past boundary", in: 11, want: 10},
		{name: "just below next boundary", in: 19, want: 10},
		{name: "next boundary", in: 20, want: 20},
		{name: "aligned base", in: rlBase, want: rlBase},
		{name: "base plus 1", in: rlBase + 1, want: rlBase},
		{name: "base plus 9", in: rlBase + 9, want: rlBase},
		{name: "base plus 10", in: rlBase + 10, want: rlBase + 10},

		// BUG (a later wave may flip these): TrimTime is integer division,
		// which truncates TOWARD ZERO, not toward negative infinity. For any
		// negative timestamp the bucket rounds UP instead of down, so -1..-9
		// all land in bucket 0 alongside 0..9 — a 19-second-wide bucket
		// straddling the epoch. Unreachable with real unix timestamps, but it
		// means TrimTime is not a floor function and must not be treated as
		// one. A floor-based fix flips the three assertions below to -10, -10
		// and -20.
		{name: "negative one truncates toward zero", in: -1, want: 0},
		{name: "negative nine truncates toward zero", in: -9, want: 0},
		{name: "negative eleven truncates toward zero", in: -11, want: -10},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := utils.TrimTime(tc.in); got != tc.want {
				t.Errorf("TrimTime(%d) = %d, want %d", tc.in, got, tc.want)
			}
		})
	}
}

func TestRatelimitTrimTimeIsIdempotent(t *testing.T) {
	for _, in := range []int{0, 3, 10, 17, rlBase, rlBase + 7, rlBase - 3} {
		once := utils.TrimTime(in)
		twice := utils.TrimTime(once)
		if once != twice {
			t.Errorf("TrimTime not idempotent for %d: %d then %d", in, once, twice)
		}
	}
}

// ---------------------------------------------------------------------------
// Bucket creation
// ---------------------------------------------------------------------------

func TestRatelimitPrefillCreatesTwelveBucketsAhead(t *testing.T) {
	rlSnapshotGlobals(t)
	proxy.Last10SecondTimestamp = rlBase
	proxy.LastSecondTimestamp = rlBase + 5

	rlPrefillWindows()

	want := []int{}
	for i := rlBase; i < rlBase+120; i += 10 {
		want = append(want, i)
	}

	for name, m := range map[string]map[int]map[string]int{
		"WindowAccessIps":       firewall.WindowAccessIps,
		"WindowAccessIpsCookie": firewall.WindowAccessIpsCookie,
		"WindowUnkFps":          firewall.WindowUnkFps,
	} {
		got := rlBucketKeys(m)
		if !slices.Equal(got, want) {
			t.Errorf("%s buckets = %v, want %v", name, got, want)
		}
		if len(got) != 12 {
			t.Errorf("%s bucket count = %d, want 12 (120s of 10s buckets)", name, len(got))
		}
	}

	// The prefill is half-open: [now, now+120). The bucket exactly 120s out is
	// NOT created. This is the boundary that produces the nil-map panic pinned
	// by TestRatelimitMissingBucketWritePanics.
	if _, ok := firewall.WindowAccessIps[rlBase+120]; ok {
		t.Error("bucket at now+120 was created; prefill is supposed to be half-open")
	}
	// Nor is anything in the past.
	if _, ok := firewall.WindowAccessIps[rlBase-10]; ok {
		t.Error("bucket at now-10 was created; prefill only looks forward")
	}
}

func TestRatelimitPrefillPreservesExistingCounts(t *testing.T) {
	rlSnapshotGlobals(t)
	proxy.Last10SecondTimestamp = rlBase
	proxy.LastSecondTimestamp = rlBase

	firewall.WindowAccessIps[rlBase] = map[string]int{"1.1.1.1": 7}
	firewall.WindowAccessIpsCookie[rlBase+30] = map[string]int{"2.2.2.2": 3}
	firewall.WindowUnkFps[rlBase+60] = map[string]int{"deadbeef": 5}

	rlPrefillWindows()

	if got := firewall.WindowAccessIps[rlBase]["1.1.1.1"]; got != 7 {
		t.Errorf("prefill clobbered an existing WindowAccessIps bucket: got %d, want 7", got)
	}
	if got := firewall.WindowAccessIpsCookie[rlBase+30]["2.2.2.2"]; got != 3 {
		t.Errorf("prefill clobbered an existing WindowAccessIpsCookie bucket: got %d, want 3", got)
	}
	if got := firewall.WindowUnkFps[rlBase+60]["deadbeef"]; got != 5 {
		t.Errorf("prefill clobbered an existing WindowUnkFps bucket: got %d, want 5", got)
	}
	// The nil check is per-map, so a bucket that exists in one window map is
	// still created in the other two.
	if len(firewall.WindowAccessIps) != 12 {
		t.Errorf("WindowAccessIps bucket count = %d, want 12", len(firewall.WindowAccessIps))
	}
}

// BUG (a later wave flips this): the prefill loop hardcodes the literal 120
// while the expiry test uses proxy.RatelimitWindow, which is operator-
// configurable via config.json `ratelimit_time`. Raise the window to 300 and
// the sweep will happily keep 300 seconds of buckets, but the prefill still
// only creates 12. Nothing ever creates buckets between now+120 and now+300;
// they are only born lazily by a LATER pass once Last10SecondTimestamp has
// advanced. When the two are unified, the assertion below flips from 12 to 30.
func TestRatelimitPrefillIgnoresConfiguredWindow(t *testing.T) {
	rlSnapshotGlobals(t)
	proxy.RatelimitWindow = 300
	proxy.Last10SecondTimestamp = rlBase
	proxy.LastSecondTimestamp = rlBase

	rlPrefillWindows()

	if got := len(firewall.WindowAccessIps); got != 12 {
		t.Errorf("bucket count with RatelimitWindow=300 = %d, want 12 (prefill hardcodes 120)", got)
	}
	if _, ok := firewall.WindowAccessIps[rlBase+200]; ok {
		t.Error("prefill created a bucket beyond the hardcoded 120s horizon")
	}
}

// ---------------------------------------------------------------------------
// Bucket expiry as the window slides
// ---------------------------------------------------------------------------

// Retention rule as written: a bucket B survives iff
//
//	TrimTime(B) + proxy.RatelimitWindow >= proxy.LastSecondTimestamp
//
// Buckets are always 10-aligned, so TrimTime(B) == B and, with the default
// window of 120 and LastSecondTimestamp == rlBase+5, the cutoff falls at
// B < rlBase-115, i.e. everything at or below rlBase-120 dies.
func TestRatelimitSweepExpiresOutdatedBuckets(t *testing.T) {
	rlSnapshotGlobals(t)
	proxy.Last10SecondTimestamp = rlBase
	proxy.LastSecondTimestamp = rlBase + 5

	seeded := []int{rlBase - 140, rlBase - 130, rlBase - 120, rlBase - 110, rlBase - 10, rlBase}
	for _, ts := range seeded {
		firewall.WindowAccessIps[ts] = map[string]int{"1.1.1.1": 1}
	}

	rlSweepWindows()

	tests := []struct {
		name      string
		bucket    int
		wantAlive bool
	}{
		{name: "140s old is expired", bucket: rlBase - 140, wantAlive: false},
		{name: "130s old is expired", bucket: rlBase - 130, wantAlive: false},
		// Exactly at the window edge: B+120 == rlBase, and rlBase < rlBase+5,
		// so it is deleted. The window is measured against the 1-second
		// timestamp, not the 10-second one, which is why a bucket exactly
		// RatelimitWindow old already counts as outdated.
		{name: "exactly 120s old is expired", bucket: rlBase - 120, wantAlive: false},
		{name: "110s old survives", bucket: rlBase - 110, wantAlive: true},
		{name: "10s old survives", bucket: rlBase - 10, wantAlive: true},
		{name: "current survives", bucket: rlBase, wantAlive: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, alive := firewall.WindowAccessIps[tc.bucket]
			if alive != tc.wantAlive {
				t.Errorf("bucket %d alive = %v, want %v", tc.bucket, alive, tc.wantAlive)
			}
		})
	}
}

// The sweep decides expiry off proxy.LastSecondTimestamp, which the monitor
// thread refreshes once a second. Freeze the clock and no bucket ever expires,
// no matter how many passes run.
func TestRatelimitSweepExpiryFollowsTheClockNotThePassCount(t *testing.T) {
	rlSnapshotGlobals(t)
	proxy.Last10SecondTimestamp = rlBase
	proxy.LastSecondTimestamp = rlBase

	firewall.WindowAccessIps[rlBase-100] = map[string]int{"1.1.1.1": 3}

	for range 5 {
		rlSweepWindows()
	}
	if _, alive := firewall.WindowAccessIps[rlBase-100]; !alive {
		t.Fatal("bucket expired without the clock moving")
	}

	// Advance the clock past the window and a single pass reaps it.
	proxy.LastSecondTimestamp = rlBase + 25
	rlSweepWindows()
	if _, alive := firewall.WindowAccessIps[rlBase-100]; alive {
		t.Error("bucket survived past the ratelimit window")
	}
}

// ---------------------------------------------------------------------------
// Summation across live buckets
// ---------------------------------------------------------------------------

func TestRatelimitSweepSumsAcrossLiveBucketsOnly(t *testing.T) {
	rlSnapshotGlobals(t)
	proxy.Last10SecondTimestamp = rlBase
	proxy.LastSecondTimestamp = rlBase + 5

	// live
	firewall.WindowAccessIps[rlBase] = map[string]int{"1.1.1.1": 4, "2.2.2.2": 1}
	firewall.WindowAccessIps[rlBase-10] = map[string]int{"1.1.1.1": 6}
	firewall.WindowAccessIps[rlBase-110] = map[string]int{"1.1.1.1": 90}
	// expired: its 5000 requests must not reach AccessIps
	firewall.WindowAccessIps[rlBase-200] = map[string]int{"1.1.1.1": 5000, "3.3.3.3": 5000}

	// A stale total from a previous pass, to prove AccessIps is rebuilt and
	// not accumulated into.
	firewall.AccessIps = map[string]int{"9.9.9.9": 999999}

	rlSweepWindows()

	want := map[string]int{"1.1.1.1": 100, "2.2.2.2": 1}
	if !maps.Equal(firewall.AccessIps, want) {
		t.Errorf("AccessIps = %v, want %v", firewall.AccessIps, want)
	}
}

func TestRatelimitSweepIsIdempotentForAFixedClock(t *testing.T) {
	rlSnapshotGlobals(t)
	proxy.Last10SecondTimestamp = rlBase
	proxy.LastSecondTimestamp = rlBase + 5

	firewall.WindowAccessIps[rlBase] = map[string]int{"1.1.1.1": 4}
	firewall.WindowAccessIps[rlBase-10] = map[string]int{"1.1.1.1": 6}

	rlSweepWindows()
	first := maps.Clone(firewall.AccessIps)
	rlSweepWindows()

	if !maps.Equal(firewall.AccessIps, first) {
		t.Errorf("second sweep changed totals: %v then %v", first, firewall.AccessIps)
	}
	if got := firewall.AccessIps["1.1.1.1"]; got != 10 {
		t.Errorf("AccessIps[1.1.1.1] = %d, want 10 (sweep must reset, not accumulate)", got)
	}
}

func TestRatelimitSweepKeepsTheThreeWindowsIndependent(t *testing.T) {
	rlSnapshotGlobals(t)
	proxy.Last10SecondTimestamp = rlBase
	proxy.LastSecondTimestamp = rlBase + 5

	firewall.WindowAccessIps[rlBase] = map[string]int{"1.1.1.1": 1}
	firewall.WindowAccessIpsCookie[rlBase] = map[string]int{"1.1.1.1": 2}
	firewall.WindowUnkFps[rlBase] = map[string]int{"deadbeef": 3}

	rlSweepWindows()

	if !maps.Equal(firewall.AccessIps, map[string]int{"1.1.1.1": 1}) {
		t.Errorf("AccessIps = %v", firewall.AccessIps)
	}
	if !maps.Equal(firewall.AccessIpsCookie, map[string]int{"1.1.1.1": 2}) {
		t.Errorf("AccessIpsCookie = %v", firewall.AccessIpsCookie)
	}
	if !maps.Equal(firewall.UnkFps, map[string]int{"deadbeef": 3}) {
		t.Errorf("UnkFps = %v", firewall.UnkFps)
	}
}

// A full pass with an empty world must not blow up and must publish empty
// totals rather than nil ones — middleware reads these maps unconditionally.
func TestRatelimitFullPassFromEmptyStateProducesEmptyTotals(t *testing.T) {
	rlSnapshotGlobals(t)
	proxy.Last10SecondTimestamp = rlBase
	proxy.LastSecondTimestamp = rlBase

	rlPass()

	if firewall.AccessIps == nil || len(firewall.AccessIps) != 0 {
		t.Errorf("AccessIps = %v, want empty non-nil map", firewall.AccessIps)
	}
	if got := firewall.AccessIps["8.8.8.8"]; got != 0 {
		t.Errorf("lookup of an unseen ip = %d, want 0", got)
	}
	if len(firewall.WindowAccessIps) != 12 {
		t.Errorf("bucket count after a full pass = %d, want 12", len(firewall.WindowAccessIps))
	}
}

// Requests recorded into the current bucket are invisible to the ratelimit
// until the NEXT pass runs. evaluateRatelimit sleeps 5 seconds between passes,
// so an attacker gets up to a 5-second free window against IPRatelimit /
// FPRatelimit. This is the "hot path reads stale totals" defect; a later wave
// is expected to make ratelimit decisions read the Window* maps directly, at
// which point the first assertion below flips from 0 to 50.
func TestRatelimitTotalsLagBehindTheCurrentBucketByOnePass(t *testing.T) {
	rlSnapshotGlobals(t)
	proxy.Last10SecondTimestamp = rlBase
	proxy.LastSecondTimestamp = rlBase

	rlPass()

	// Simulate 50 requests landing in the current bucket (the middleware's
	// `firewall.WindowAccessIps[proxy.Last10SecondTimestamp][ip]++`).
	for range 50 {
		firewall.WindowAccessIps[proxy.Last10SecondTimestamp]["1.1.1.1"]++
	}

	// BUG (a later wave flips this to 50): the published total the ratelimit
	// actually consults still says zero.
	if got := firewall.AccessIps["1.1.1.1"]; got != 0 {
		t.Errorf("AccessIps[1.1.1.1] = %d immediately after the burst, want 0 (stale by design today)", got)
	}

	rlPass()

	if got := firewall.AccessIps["1.1.1.1"]; got != 50 {
		t.Errorf("AccessIps[1.1.1.1] = %d after the next pass, want 50", got)
	}
}

// ---------------------------------------------------------------------------
// The missing-bucket panic (audit finding at core/server/middleware.go:96)
// ---------------------------------------------------------------------------

// This is the tripwire that matters most. middleware.go does, under a bare
// firewall.Mutex.Lock() with NO defer Unlock:
//
//	firewall.WindowAccessIps[proxy.Last10SecondTimestamp][ip]++
//
// If the monitor thread has not prefilled that bucket, the inner map is nil and
// the increment panics. pnc.PanicHndl recovers it — and because the Unlock is a
// plain statement that is now skipped, firewall.Mutex stays locked forever and
// every subsequent request blocks on it. The proxy is dead, silently.
//
// The test below reproduces the WRITE, not the lock. It never touches
// firewall.Mutex, so it demonstrates the panic without any chance of hanging
// the test binary.
func TestRatelimitMissingBucketWritePanics(t *testing.T) {
	rlSnapshotGlobals(t)
	proxy.Last10SecondTimestamp = rlBase

	// No prefill has run: the bucket does not exist.
	if _, ok := firewall.WindowAccessIps[proxy.Last10SecondTimestamp]; ok {
		t.Fatal("test setup wrong: bucket should be absent")
	}

	msg := rlMustPanic(t, func() {
		firewall.WindowAccessIps[proxy.Last10SecondTimestamp]["1.1.1.1"]++
	})
	if !strings.Contains(msg, "nil map") {
		t.Errorf("panic message = %q, want it to mention a nil map", msg)
	}
}

// The realistic trigger: a pass ran, so buckets exist for [now, now+120), but
// the monitor thread then stalled for more than 120 seconds while traffic kept
// arriving. Last10SecondTimestamp has walked past the prefilled horizon and the
// next request writes into a hole. All three window maps have the same hole.
func TestRatelimitMissingBucketWritePanicsWhenMonitorStallsPastHorizon(t *testing.T) {
	rlSnapshotGlobals(t)
	proxy.Last10SecondTimestamp = rlBase
	proxy.LastSecondTimestamp = rlBase
	rlPass()

	// Furthest bucket the pass created is rlBase+110; rlBase+120 is the hole.
	if _, ok := firewall.WindowAccessIps[rlBase+110]; !ok {
		t.Fatal("expected rlBase+110 to be prefilled")
	}

	tests := []struct {
		name  string
		write func()
	}{
		{
			name:  "WindowAccessIps",
			write: func() { firewall.WindowAccessIps[rlBase+120]["1.1.1.1"]++ },
		},
		{
			name:  "WindowAccessIpsCookie",
			write: func() { firewall.WindowAccessIpsCookie[rlBase+120]["1.1.1.1"]++ },
		},
		{
			name:  "WindowUnkFps",
			write: func() { firewall.WindowUnkFps[rlBase+120]["deadbeef"]++ },
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			msg := rlMustPanic(t, tc.write)
			if !strings.Contains(msg, "nil map") {
				t.Errorf("panic message = %q, want it to mention a nil map", msg)
			}
		})
	}
}

// Reading a missing bucket is safe — only writing panics. Worth pinning so a
// later wave does not "fix" the read path and assume the write path is covered.
func TestRatelimitMissingBucketReadIsSafe(t *testing.T) {
	rlSnapshotGlobals(t)
	proxy.Last10SecondTimestamp = rlBase

	if got := firewall.WindowAccessIps[rlBase]["1.1.1.1"]; got != 0 {
		t.Errorf("read through a missing bucket = %d, want 0", got)
	}
	if got := len(firewall.WindowAccessIps[rlBase]); got != 0 {
		t.Errorf("len of a missing bucket = %d, want 0", got)
	}
}

// A prefilled bucket makes the same write safe. This is the invariant the
// prefill loop exists to maintain.
func TestRatelimitPrefilledBucketWriteIsSafe(t *testing.T) {
	rlSnapshotGlobals(t)
	proxy.Last10SecondTimestamp = rlBase
	proxy.LastSecondTimestamp = rlBase
	rlPrefillWindows()

	firewall.WindowAccessIps[proxy.Last10SecondTimestamp]["1.1.1.1"]++
	firewall.WindowAccessIps[proxy.Last10SecondTimestamp]["1.1.1.1"]++

	if got := firewall.WindowAccessIps[rlBase]["1.1.1.1"]; got != 2 {
		t.Errorf("bucket count = %d, want 2", got)
	}
}

// ---------------------------------------------------------------------------
// checkAttack — REAL function, called directly.
// ---------------------------------------------------------------------------

// rlRegisterDomain installs a DomainSettings entry (checkAttack type-asserts
// the DomainsMap load without checking `ok`, so the entry must exist) and
// registers cleanup for both global maps.
func rlRegisterDomain(t *testing.T, name string, s domains.DomainSettings) {
	t.Helper()
	s.Name = name
	// Webhook URL stays empty: utils.SendWebhook returns immediately on an
	// empty URL, so checkAttack makes no network call.
	domains.DomainsMap.Store(name, s)
	t.Cleanup(func() {
		domains.DomainsMap.Delete(name)
		firewall.Mutex.Lock()
		delete(domains.DomainsData, name)
		firewall.Mutex.Unlock()
	})
}

// rlThresholds is a neutral, well-separated threshold set.
func rlThresholds() domains.DomainSettings {
	return domains.DomainSettings{
		BypassStage1:        10,
		BypassStage2:        100,
		DisableBypassStage2: 5,
		DisableRawStage2:    1000,
		DisableBypassStage3: 5,
		DisableRawStage3:    1000,
	}
}

// rlTick adds one second's worth of traffic and runs checkAttack, returning the
// state checkAttack persisted.
func rlTick(t *testing.T, name string, d domains.DomainData, total, bypassed int) domains.DomainData {
	t.Helper()
	d.Name = name
	d.TotalRequests += total
	d.BypassedRequests += bypassed
	checkAttack(name, d)
	firewall.Mutex.RLock()
	out := domains.DomainsData[name]
	firewall.Mutex.RUnlock()
	return out
}

func TestMonitorCheckAttackComputesPerSecondDeltas(t *testing.T) {
	const name = "rl-deltas.test"
	rlRegisterDomain(t, name, rlThresholds())

	d := domains.DomainData{Name: name, Stage: 1, TotalRequests: 40, BypassedRequests: 10, PrevRequests: 40, PrevBypassed: 10}
	got := rlTick(t, name, d, 60, 0)

	if got.RequestsPerSecond != 60 {
		t.Errorf("RequestsPerSecond = %d, want 60", got.RequestsPerSecond)
	}
	if got.RequestsBypassedPerSecond != 0 {
		t.Errorf("RequestsBypassedPerSecond = %d, want 0", got.RequestsBypassedPerSecond)
	}
	// Prev* are rolled forward so the next tick measures a fresh delta.
	if got.PrevRequests != 100 {
		t.Errorf("PrevRequests = %d, want 100", got.PrevRequests)
	}
	if got.PrevBypassed != 10 {
		t.Errorf("PrevBypassed = %d, want 10", got.PrevBypassed)
	}
	if got.Stage != 1 {
		t.Errorf("Stage = %d, want 1 (60 r/s is below every threshold here)", got.Stage)
	}
}

// The "debug" domain is short-circuited before anything is computed, and — note
// — before the write-back at the bottom of the function. Nothing about it is
// ever persisted.
func TestMonitorCheckAttackSkipsDebugDomain(t *testing.T) {
	firewall.Mutex.Lock()
	_, existed := domains.DomainsData["debug"]
	firewall.Mutex.Unlock()
	if existed {
		t.Skip("a debug domain already exists in this process; refusing to disturb it")
	}
	t.Cleanup(func() {
		firewall.Mutex.Lock()
		delete(domains.DomainsData, "debug")
		firewall.Mutex.Unlock()
	})

	// No DomainsMap entry is registered on purpose: if checkAttack did not
	// return early it would panic on the unchecked type assertion.
	checkAttack("debug", domains.DomainData{Name: "debug", Stage: 1, TotalRequests: 100000})

	firewall.Mutex.RLock()
	_, written := domains.DomainsData["debug"]
	firewall.Mutex.RUnlock()
	if written {
		t.Error("checkAttack persisted state for the debug domain; it must return before the write-back")
	}
}

func TestMonitorCheckAttackStageEscalation(t *testing.T) {
	tests := []struct {
		name          string
		stage         int
		bypassAttack  bool
		rawAttack     bool
		total         int
		bypassed      int
		wantStage     int
		wantBypassAtk bool
		wantCooldown  int
	}{
		{
			name:  "stage 1 escalates when bypassed exceeds BypassStage1",
			stage: 1, total: 20, bypassed: 11,
			wantStage: 2, wantBypassAtk: true, wantCooldown: 10,
		},
		{
			// Strictly greater-than: exactly at the threshold is not an attack.
			name:  "stage 1 holds at exactly BypassStage1",
			stage: 1, total: 20, bypassed: 10,
			wantStage: 1, wantBypassAtk: false, wantCooldown: 0,
		},
		{
			name:  "stage 2 escalates when bypassed exceeds BypassStage2",
			stage: 2, bypassAttack: true, total: 200, bypassed: 101,
			wantStage: 3, wantBypassAtk: true, wantCooldown: 0,
		},
		{
			name:  "stage 2 holds at exactly BypassStage2",
			stage: 2, bypassAttack: true, total: 200, bypassed: 100,
			wantStage: 2, wantBypassAtk: true, wantCooldown: 0,
		},
		{
			name:  "stage 2 de-escalates when both metrics drop below the disable thresholds",
			stage: 2, bypassAttack: true, total: 4, bypassed: 4,
			wantStage: 1, wantBypassAtk: false, wantCooldown: 0,
		},
		{
			// BUG (a later wave may flip this): de-escalation from stage 2 is
			// gated on BypassAttack. A domain parked in stage 2 by anything
			// other than the bypass-attack path (a reload leaving Stage=2, a
			// stage-3 de-escalation whose BypassAttack was already cleared)
			// can never fall back to stage 1, so every visitor keeps paying
			// the JS challenge forever. Flipping this expects Stage 1.
			name:  "stage 2 sticks when BypassAttack is false",
			stage: 2, bypassAttack: false, total: 4, bypassed: 4,
			wantStage: 2, wantBypassAtk: false, wantCooldown: 0,
		},
		{
			name:  "stage 3 de-escalates when both metrics drop below the disable thresholds",
			stage: 3, bypassAttack: true, total: 4, bypassed: 4,
			wantStage: 2, wantBypassAtk: true, wantCooldown: 0,
		},
		{
			// Stage 3 needs BOTH below. Raw traffic alone pins it at 3.
			name:  "stage 3 holds while raw traffic stays above DisableRawStage3",
			stage: 3, bypassAttack: true, total: 1001, bypassed: 4,
			wantStage: 3, wantBypassAtk: true, wantCooldown: 0,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			name := "rl-esc-" + strings.ReplaceAll(tc.name, " ", "-") + ".test"
			rlRegisterDomain(t, name, rlThresholds())

			d := domains.DomainData{
				Name:         name,
				Stage:        tc.stage,
				BypassAttack: tc.bypassAttack,
				RawAttack:    tc.rawAttack,
			}
			got := rlTick(t, name, d, tc.total, tc.bypassed)

			if got.Stage != tc.wantStage {
				t.Errorf("Stage = %d, want %d", got.Stage, tc.wantStage)
			}
			if got.BypassAttack != tc.wantBypassAtk {
				t.Errorf("BypassAttack = %v, want %v", got.BypassAttack, tc.wantBypassAtk)
			}
			if got.BufferCooldown != tc.wantCooldown {
				t.Errorf("BufferCooldown = %d, want %d", got.BufferCooldown, tc.wantCooldown)
			}
		})
	}
}

// BUG (a later wave may flip this): a raw (non-bypassing) flood sets RawAttack
// and arms the 10-tick cooldown, but never raises Stage. The proxy notices the
// flood, opens a webhook/logging window for it, and then serves it exactly as
// before. Only a BYPASSING attack ever changes the challenge stage. When raw
// floods are made to escalate, wantStage below flips from 1 to 2.
func TestMonitorCheckAttackRawAttackDoesNotEscalateStage(t *testing.T) {
	const name = "rl-raw.test"
	rlRegisterDomain(t, name, rlThresholds())

	d := domains.DomainData{Name: name, Stage: 1}
	got := rlTick(t, name, d, 1001, 0)

	if !got.RawAttack {
		t.Error("RawAttack = false, want true (1001 r/s exceeds DisableRawStage2=1000)")
	}
	if got.Stage != 1 {
		t.Errorf("Stage = %d, want 1 (raw attacks do not escalate today)", got.Stage)
	}
	if got.BufferCooldown != 10 {
		t.Errorf("BufferCooldown = %d, want 10", got.BufferCooldown)
	}
	if got.PeakRequestsPerSecond != 1001 {
		t.Errorf("PeakRequestsPerSecond = %d, want 1001", got.PeakRequestsPerSecond)
	}
	if len(got.RequestLogger) != 1 {
		t.Errorf("RequestLogger len = %d, want 1", len(got.RequestLogger))
	}
}

// BUG (a later wave may flip this): DisableRawStage2 is used as BOTH the
// trigger (`rps > DisableRawStage2`) and the clear (`rps < DisableRawStage2`)
// for a raw attack, so at exactly the threshold neither branch runs and an
// active RawAttack latches on indefinitely at a steady 1000 r/s. A fix that
// separates the two thresholds, or makes the clear `<=`, flips this to false.
func TestMonitorCheckAttackRawAttackLatchesAtExactThreshold(t *testing.T) {
	const name = "rl-raw-latch.test"
	rlRegisterDomain(t, name, rlThresholds())

	d := domains.DomainData{Name: name, Stage: 1, RawAttack: true, BufferCooldown: 10}
	got := rlTick(t, name, d, 1000, 0)

	if !got.RawAttack {
		t.Error("RawAttack = false at exactly DisableRawStage2; today it latches on")
	}

	// One request fewer and it clears.
	got2 := rlTick(t, name, got, 999, 0)
	if got2.RawAttack {
		t.Error("RawAttack = true at 999 r/s, want false")
	}
}

// A manually pinned stage bypasses the whole detection block — but the
// per-second counters ARE still recomputed and persisted, because that happens
// above the guard.
func TestMonitorCheckAttackHonoursManuallySetStage(t *testing.T) {
	const name = "rl-manual.test"
	rlRegisterDomain(t, name, rlThresholds())

	d := domains.DomainData{Name: name, Stage: 1, StageManuallySet: true}
	got := rlTick(t, name, d, 100000, 100000)

	if got.Stage != 1 {
		t.Errorf("Stage = %d, want 1 (stage is pinned)", got.Stage)
	}
	if got.BypassAttack || got.RawAttack {
		t.Errorf("attack flags set on a pinned domain: bypass=%v raw=%v", got.BypassAttack, got.RawAttack)
	}
	if got.RequestsPerSecond != 100000 {
		t.Errorf("RequestsPerSecond = %d, want 100000 (counters update even when pinned)", got.RequestsPerSecond)
	}
	if got.PrevRequests != 100000 {
		t.Errorf("PrevRequests = %d, want 100000", got.PrevRequests)
	}
}

// A pinned stage with a cooldown still running DOES re-enter the block — the
// guard is `!StageManuallySet || BufferCooldown > 0`. So pinning the stage
// mid-attack does not stop the stage from moving until the cooldown drains.
func TestMonitorCheckAttackManualStageStillRunsWhileCooldownActive(t *testing.T) {
	const name = "rl-manual-cooldown.test"
	rlRegisterDomain(t, name, rlThresholds())

	d := domains.DomainData{Name: name, Stage: 1, StageManuallySet: true, BufferCooldown: 5}
	got := rlTick(t, name, d, 50, 50)

	if got.Stage != 2 {
		t.Errorf("Stage = %d, want 2 (cooldown re-opens the detection block despite the pin)", got.Stage)
	}
}

func TestMonitorCheckAttackCooldownDrainsAndResetsPeaks(t *testing.T) {
	const name = "rl-cooldown.test"
	rlRegisterDomain(t, name, rlThresholds())

	// Quiet traffic, no attack flags, cooldown counting down.
	d := domains.DomainData{
		Name:                          name,
		Stage:                         1,
		BufferCooldown:                3,
		PeakRequestsPerSecond:         500,
		PeakRequestsBypassedPerSecond: 400,
		RequestLogger:                 []domains.RequestLog{{Total: 500, Allowed: 400}},
	}

	got := rlTick(t, name, d, 1, 1)
	if got.BufferCooldown != 2 {
		t.Fatalf("BufferCooldown = %d, want 2", got.BufferCooldown)
	}
	// While the cooldown runs, every tick appends another sample.
	if len(got.RequestLogger) != 2 {
		t.Errorf("RequestLogger len = %d, want 2", len(got.RequestLogger))
	}

	got = rlTick(t, name, got, 1, 1)
	if got.BufferCooldown != 1 {
		t.Fatalf("BufferCooldown = %d, want 1", got.BufferCooldown)
	}

	got = rlTick(t, name, got, 1, 1)
	if got.BufferCooldown != 0 {
		t.Fatalf("BufferCooldown = %d, want 0", got.BufferCooldown)
	}
	// Hitting zero fires the attack-over webhook and wipes the report buffers —
	// including the sample this very tick just appended.
	if got.PeakRequestsPerSecond != 0 || got.PeakRequestsBypassedPerSecond != 0 {
		t.Errorf("peaks not reset: %d / %d", got.PeakRequestsPerSecond, got.PeakRequestsBypassedPerSecond)
	}
	if len(got.RequestLogger) != 0 {
		t.Errorf("RequestLogger len = %d, want 0 after the cooldown expires", len(got.RequestLogger))
	}
}

// BUG (a later wave flips this): RequestLogger is appended to on EVERY tick
// while BufferCooldown > 0, and BufferCooldown is re-armed to 10 on every fresh
// attack trigger while never being decremented during a sustained bypass
// attack. A flood that holds stage 2 therefore grows RequestLogger without any
// bound for the whole duration of the attack — one struct per second, per
// domain, held in memory precisely when memory is scarcest. When the logger
// gains a cap, the assertion below stops being "exactly one per tick".
func TestMonitorCheckAttackRequestLoggerGrowsUnboundedDuringSustainedAttack(t *testing.T) {
	const name = "rl-logger.test"
	rlRegisterDomain(t, name, rlThresholds())

	d := domains.DomainData{Name: name, Stage: 1}
	for range 8 {
		d = rlTick(t, name, d, 60, 50)
	}

	if d.Stage != 2 {
		t.Fatalf("Stage = %d, want 2", d.Stage)
	}
	if d.BufferCooldown != 10 {
		t.Errorf("BufferCooldown = %d, want 10 (never drains while BypassAttack holds)", d.BufferCooldown)
	}
	if len(d.RequestLogger) != 8 {
		t.Errorf("RequestLogger len = %d, want 8 (one entry per tick, no cap)", len(d.RequestLogger))
	}
}

func TestMonitorCheckAttackTracksPeaksDuringCooldown(t *testing.T) {
	const name = "rl-peaks.test"
	rlRegisterDomain(t, name, rlThresholds())

	d := domains.DomainData{Name: name, Stage: 1}
	d = rlTick(t, name, d, 60, 50) // trigger: peaks = 60/50
	d = rlTick(t, name, d, 90, 70) // higher: peaks = 90/70
	d = rlTick(t, name, d, 20, 10) // lower: peaks unchanged
	d = rlTick(t, name, d, 80, 90) // total lower, bypassed higher

	if d.PeakRequestsPerSecond != 90 {
		t.Errorf("PeakRequestsPerSecond = %d, want 90", d.PeakRequestsPerSecond)
	}
	if d.PeakRequestsBypassedPerSecond != 90 {
		t.Errorf("PeakRequestsBypassedPerSecond = %d, want 90", d.PeakRequestsBypassedPerSecond)
	}
}
