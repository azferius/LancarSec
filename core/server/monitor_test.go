package server

// Wave 3 tripwire tests for core/server/monitor.go.
//
// SCOPE / OWNERSHIP: this file owns TestRatelimit* and TestMonitor*. Every
// helper defined here is prefixed `rl` so it cannot collide with the
// middleware_test.go that shares package `server`.
//
// HONESTY NOTE (read this before trusting the ratelimit coverage below):
// `evaluateRatelimit` is `for { ...; time.Sleep(5 * time.Second) }`. It cannot
// be called in-process without either leaking a goroutine that keeps mutating
// package globals underneath every later test in this package (guaranteed
// -race failures) or parking it on firewall.Mutex forever (guaranteed deadlock
// of the whole test binary). So most of the sliding-window arithmetic below is
// driven through `rlPrefillWindows` + `rlSweepWindows`, which are a
// line-for-line transcription of the loop body. Those tests are a SPEC, not an
// exercise of the shipped code: an edit inside `func evaluateRatelimit` alone
// leaves every one of them passing.
//
// TestRatelimitEvaluateRatelimitOnePass closes that gap. It runs the REAL
// function once in a child process - which can afford the goroutine leak,
// because the process exits - and asserts the prefill horizon, the expiry
// direction and the summation on the output. Keep it: without it the
// transcription is unanchored.
//
// Directly exercised (real production functions, no transcription):
//   utils.TrimTime, evaluateRatelimit (via the child process), checkAttack,
//   utils.SendWebhook's notification types (via checkAttack, in a
//   network-isolated child process), and the nil-map write shape from
//   middleware.go:96.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"slices"
	"strings"
	"testing"
	"time"

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

	// WAVE 7: the clock is atomics now — there is nothing to snapshot. Every
	// test pins the clock explicitly via rlSetClock before it reads it.

	oldWindow := proxy.RatelimitWindow
	oldInitialised := proxy.Initialised

	t.Cleanup(func() {
		firewall.WindowAccessIps = oldWindowAccessIps
		firewall.WindowAccessIpsCookie = oldWindowAccessIpsCookie
		firewall.WindowUnkFps = oldWindowUnkFps
		firewall.AccessIps = oldAccessIps
		firewall.AccessIpsCookie = oldAccessIpsCookie
		firewall.UnkFps = oldUnkFps

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

// rlSetClock pins the atomic clock: last-second timestamp unix and the 10s
// bucket derived from it (TrimTime(unix), which for a 10-aligned base is the
// base itself). This is the only writer tests may use.
func rlSetClock(unix int64) {
	proxy.UpdateClock(time.Unix(unix, 0))
}

// rlPrefillWindows is a verbatim transcription of the bucket-prefill loop at
// the top of evaluateRatelimit's body. Note the hardcoded literal 120 — it is
// NOT proxy.RatelimitWindow. TestRatelimitPrefillIgnoresConfiguredWindow pins
// that divergence.
func rlPrefillWindows() {
	last10 := int(proxy.Last10SecondTimestamp())
	for i := last10; i < last10+120; i = i + 10 {
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
	now := int(proxy.LastSecondTimestamp())
	firewall.AccessIps = map[string]int{}
	for windowTime, accessIPs := range firewall.WindowAccessIps {
		if utils.TrimTime(windowTime)+proxy.RatelimitWindow < now {
			delete(firewall.WindowAccessIps, windowTime)
		} else {
			for IP, requests := range accessIPs {
				firewall.AccessIps[IP] += requests
			}
		}
	}
	firewall.AccessIpsCookie = map[string]int{}
	for windowTime, accessIPsCookie := range firewall.WindowAccessIpsCookie {
		if utils.TrimTime(windowTime)+proxy.RatelimitWindow < now {
			delete(firewall.WindowAccessIpsCookie, windowTime)
		} else {
			for IP, requests := range accessIPsCookie {
				firewall.AccessIpsCookie[IP] += requests
			}
		}
	}
	firewall.UnkFps = map[string]int{}
	for windowTime, unkFps := range firewall.WindowUnkFps {
		if utils.TrimTime(windowTime)+proxy.RatelimitWindow < now {
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
	rlSetClock(rlBase + 5)

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
	rlSetClock(rlBase)

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
	rlSetClock(rlBase)

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
	rlSetClock(rlBase + 5)

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
	rlSetClock(rlBase)

	firewall.WindowAccessIps[rlBase-100] = map[string]int{"1.1.1.1": 3}

	for range 5 {
		rlSweepWindows()
	}
	if _, alive := firewall.WindowAccessIps[rlBase-100]; !alive {
		t.Fatal("bucket expired without the clock moving")
	}

	// Advance the clock past the window and a single pass reaps it.
	rlSetClock(rlBase + 25)
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
	rlSetClock(rlBase + 5)

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
	rlSetClock(rlBase + 5)

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
	rlSetClock(rlBase + 5)

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
	rlSetClock(rlBase)

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
	rlSetClock(rlBase)

	rlPass()

	// Simulate 50 requests landing in the current bucket (the middleware's
	// `firewall.WindowAccessIps[int(proxy.Last10SecondTimestamp())][ip]++`).
	for range 50 {
		firewall.WindowAccessIps[int(proxy.Last10SecondTimestamp())]["1.1.1.1"]++
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
// evaluateRatelimit — the REAL function, run in a child process.
// ---------------------------------------------------------------------------
//
// Everything above this banner drives rlPrefillWindows/rlSweepWindows, which
// are a transcription of evaluateRatelimit's body: they pin the arithmetic but
// they do not execute the shipped function, so an edit inside
// `func evaluateRatelimit` alone changes nothing they assert.
//
// evaluateRatelimit cannot be called in-process: it is `for { ...; time.Sleep(5
// * time.Second) }`, so it either leaks a goroutine that keeps mutating package
// globals under every later test in this binary, or it has to be parked on
// firewall.Mutex forever, which deadlocks the binary. The way out is a child
// process: it runs one real pass, reports what the globals look like
// afterwards, and exits. The leak dies with it.
//
// Synchronisation with the child's evaluateRatelimit goroutine goes entirely
// through firewall.Mutex. The child seeds firewall.AccessIps with a sentinel
// key; the sweep's unconditional `firewall.AccessIps = map[string]int{}` drops
// it, so "sentinel gone" means the whole locked pass has completed, and reading
// under the same lock gives a proper happens-before edge. The child never reads
// proxy.Initialised, which evaluateRatelimit publishes outside the lock.

const rlChildEnv = "LANCARSEC_TEST_EVALUATE_RATELIMIT_CHILD"

const (
	rlChildJSONStart = "<<<RL_EVALUATE_RATELIMIT_JSON"
	rlChildJSONEnd   = "RL_EVALUATE_RATELIMIT_JSON>>>"
	rlChildSentinel  = "__rl_pass_not_run_yet__"
)

// rlChildReport is what the child observes after exactly one real pass.
type rlChildReport struct {
	AccessIps       map[string]int `json:"accessIps"`
	AccessIpsCookie map[string]int `json:"accessIpsCookie"`
	UnkFps          map[string]int `json:"unkFps"`
	AccessBuckets   []int          `json:"accessBuckets"`
	CookieBuckets   []int          `json:"cookieBuckets"`
	UnkFpBuckets    []int          `json:"unkFpBuckets"`
}

// TestRatelimitEvaluateRatelimitChild is the child half of
// TestRatelimitEvaluateRatelimitOnePass. Without the env var it is a no-op, so
// an ordinary `go test` run never enters it.
func TestRatelimitEvaluateRatelimitChild(t *testing.T) {
	if os.Getenv(rlChildEnv) != "1" {
		t.Skip("child-process helper, driven by TestRatelimitEvaluateRatelimitOnePass")
	}

	// Fixture. rlBase-1000 is far outside any sane window and must be swept;
	// rlBase-110, rlBase-10 and rlBase are inside it and must be summed. The
	// prefill is expected to add rlBase+10 .. rlBase+110 on top.
	rlSetClock(rlBase + 5)
	proxy.RatelimitWindow = 120

	firewall.WindowAccessIps = map[int]map[string]int{
		rlBase - 1000: {"expired.example": 5000},
		rlBase - 110:  {"1.1.1.1": 90},
		rlBase - 10:   {"1.1.1.1": 6},
		rlBase:        {"1.1.1.1": 4, "2.2.2.2": 1},
	}
	firewall.WindowAccessIpsCookie = map[int]map[string]int{
		rlBase - 1000: {"expired.example": 5000},
		rlBase:        {"1.1.1.1": 2},
	}
	firewall.WindowUnkFps = map[int]map[string]int{
		rlBase - 1000: {"expired-fp": 5000},
		rlBase:        {"deadbeef": 3},
	}
	firewall.AccessIps = map[string]int{rlChildSentinel: 1}
	firewall.AccessIpsCookie = map[string]int{rlChildSentinel: 1}
	firewall.UnkFps = map[string]int{rlChildSentinel: 1}

	go evaluateRatelimit()

	var report rlChildReport
	deadline := time.Now().Add(30 * time.Second)
	for {
		firewall.Mutex.Lock()
		_, stillSeeded := firewall.AccessIps[rlChildSentinel]
		if !stillSeeded {
			report = rlChildReport{
				AccessIps:       maps.Clone(firewall.AccessIps),
				AccessIpsCookie: maps.Clone(firewall.AccessIpsCookie),
				UnkFps:          maps.Clone(firewall.UnkFps),
				AccessBuckets:   rlBucketKeys(firewall.WindowAccessIps),
				CookieBuckets:   rlBucketKeys(firewall.WindowAccessIpsCookie),
				UnkFpBuckets:    rlBucketKeys(firewall.WindowUnkFps),
			}
		}
		firewall.Mutex.Unlock()

		if !stillSeeded {
			break
		}
		if time.Now().After(deadline) {
			fmt.Println("evaluateRatelimit did not complete a pass within 30s")
			os.Exit(2)
		}
		time.Sleep(time.Millisecond)
	}

	payload, err := json.Marshal(report)
	if err != nil {
		fmt.Println("marshal report:", err)
		os.Exit(3)
	}
	fmt.Println(rlChildJSONStart)
	fmt.Println(string(payload))
	fmt.Println(rlChildJSONEnd)

	// Exit before evaluateRatelimit's 5-second sleep expires and it mutates
	// everything again. The leaked goroutine dies with the process.
	os.Exit(0)
}

// rlRunChild re-executes this test binary with exactly one test enabled, plus
// the extra environment the child needs. It fails the calling test - dumping
// the child's output - if the child exits non-zero.
func rlRunChild(t *testing.T, testName string, env ...string) string {
	t.Helper()

	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("locate the test binary: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, exe, "-test.run=^"+testName+"$", "-test.v")
	cmd.Env = append(os.Environ(), env...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("child process %s failed: %v\n--- child output ---\n%s", testName, err, out)
	}
	return string(out)
}

// rlRunEvaluateRatelimitChild re-executes this test binary, runs one real
// evaluateRatelimit pass in it, and returns what the child observed.
func rlRunEvaluateRatelimitChild(t *testing.T) rlChildReport {
	t.Helper()

	text := rlRunChild(t, "TestRatelimitEvaluateRatelimitChild", rlChildEnv+"=1")
	i := strings.Index(text, rlChildJSONStart)
	j := strings.Index(text, rlChildJSONEnd)
	if i < 0 || j < 0 || j < i {
		t.Fatalf("child produced no report\n--- output ---\n%s", text)
	}

	var report rlChildReport
	if err := json.Unmarshal([]byte(text[i+len(rlChildJSONStart):j]), &report); err != nil {
		t.Fatalf("decode child report: %v\n--- output ---\n%s", err, text)
	}
	return report
}

// One real pass of evaluateRatelimit, asserted end to end.
//
// Two things are pinned here that nothing else in this package can see:
//
//   - the PREFILL HORIZON. The loop runs `i < Last10SecondTimestamp+120` in
//     steps of 10, i.e. it creates the current bucket plus eleven ahead of it.
//     That horizon is the only thing keeping Middleware's
//     `firewall.WindowAccessIps[int(proxy.Last10SecondTimestamp())][ip]++` from writing
//     into a nil map, and that write happens while holding the write lock with
//     no defer - so a shorter horizon reintroduces the permanent proxy-wide
//     deadlock pinned by TestRatelimitMissingBucketWritePanics*.
//
//   - the EXPIRY DIRECTION. A bucket is deleted when it is older than the
//     window and summed otherwise. Inverting that comparison deletes every live
//     bucket and sums only dead ones, which drives firewall.AccessIps to zero
//     permanently and stops the R2 per-IP ratelimit from ever firing again.
func TestRatelimitEvaluateRatelimitOnePass(t *testing.T) {
	report := rlRunEvaluateRatelimitChild(t)

	// --- prefill horizon: the current bucket plus eleven ahead of it --------
	wantPrefilled := []int{}
	for i := rlBase; i < rlBase+120; i += 10 {
		wantPrefilled = append(wantPrefilled, i)
	}
	for _, name := range []struct {
		label   string
		buckets []int
	}{
		{"WindowAccessIps", report.AccessBuckets},
		{"WindowAccessIpsCookie", report.CookieBuckets},
		{"WindowUnkFps", report.UnkFpBuckets},
	} {
		for _, want := range wantPrefilled {
			if !slices.Contains(name.buckets, want) {
				t.Errorf("%s is missing bucket %d (want the current bucket plus eleven ahead); got %v", name.label, want, name.buckets)
			}
		}
	}

	// --- expiry: only the out-of-window bucket is dropped -------------------
	for _, tc := range []struct {
		label   string
		buckets []int
	}{
		{"WindowAccessIps", report.AccessBuckets},
		{"WindowAccessIpsCookie", report.CookieBuckets},
		{"WindowUnkFps", report.UnkFpBuckets},
	} {
		if slices.Contains(tc.buckets, rlBase-1000) {
			t.Errorf("%s kept the out-of-window bucket %d: %v", tc.label, rlBase-1000, tc.buckets)
		}
		if !slices.Contains(tc.buckets, rlBase) {
			t.Errorf("%s dropped the CURRENT bucket %d: %v", tc.label, rlBase, tc.buckets)
		}
	}
	if !slices.Contains(report.AccessBuckets, rlBase-110) || !slices.Contains(report.AccessBuckets, rlBase-10) {
		t.Errorf("WindowAccessIps dropped an in-window past bucket: %v", report.AccessBuckets)
	}

	// --- summation: live buckets only ---------------------------------------
	if !maps.Equal(report.AccessIps, map[string]int{"1.1.1.1": 100, "2.2.2.2": 1}) {
		t.Errorf("AccessIps = %v, want map[1.1.1.1:100 2.2.2.2:1] (90+6+4 across live buckets, nothing from the expired one)", report.AccessIps)
	}
	if !maps.Equal(report.AccessIpsCookie, map[string]int{"1.1.1.1": 2}) {
		t.Errorf("AccessIpsCookie = %v, want map[1.1.1.1:2]", report.AccessIpsCookie)
	}
	if !maps.Equal(report.UnkFps, map[string]int{"deadbeef": 3}) {
		t.Errorf("UnkFps = %v, want map[deadbeef:3]", report.UnkFps)
	}
	for label, m := range map[string]map[string]int{
		"AccessIps":       report.AccessIps,
		"AccessIpsCookie": report.AccessIpsCookie,
		"UnkFps":          report.UnkFps,
	} {
		if _, ok := m[rlChildSentinel]; ok {
			t.Errorf("%s still holds the seeded sentinel: the published totals must be rebuilt, not accumulated into", label)
		}
		if _, ok := m["expired.example"]; ok {
			t.Errorf("%s counted an expired bucket: %v", label, m)
		}
		if _, ok := m["expired-fp"]; ok {
			t.Errorf("%s counted an expired bucket: %v", label, m)
		}
	}
}

// ---------------------------------------------------------------------------
// The missing-bucket panic (audit finding at core/server/middleware.go:96)
// ---------------------------------------------------------------------------

// This is the tripwire that matters most. middleware.go does, under a bare
// firewall.Mutex.Lock() with NO defer Unlock:
//
//	firewall.WindowAccessIps[int(proxy.Last10SecondTimestamp())][ip]++
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
	rlSetClock(rlBase)

	// No prefill has run: the bucket does not exist.
	if _, ok := firewall.WindowAccessIps[rlBase]; ok {
		t.Fatal("test setup wrong: bucket should be absent")
	}

	msg := rlMustPanic(t, func() {
		firewall.WindowAccessIps[int(proxy.Last10SecondTimestamp())]["1.1.1.1"]++
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
	rlSetClock(rlBase)
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
	rlSetClock(rlBase)

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
	rlSetClock(rlBase)
	rlPrefillWindows()

	firewall.WindowAccessIps[int(proxy.Last10SecondTimestamp())]["1.1.1.1"]++
	firewall.WindowAccessIps[int(proxy.Last10SecondTimestamp())]["1.1.1.1"]++

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
	// Unless the caller supplied one (see rlWebhookSettings), the webhook URL
	// stays empty: utils.SendWebhook returns immediately on an empty URL, so
	// checkAttack makes no network call.
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

// The cooldown gate is a three-term conjunction:
//
//	if !domainData.BypassAttack && !domainData.RawAttack && (domainData.BufferCooldown > 0)
//
// Dropping the !RawAttack term is a standard refactor slip and nothing else in
// this file notices it, because every other cooldown fixture has RawAttack
// false. It matters: the cooldown is the report window for an attack that is
// STILL RUNNING, so draining it mid-flood fires the "attack over" webhook and
// wipes PeakRequests* and RequestLogger while the flood continues.
//
// The fixture below holds a raw attack at exactly DisableRawStage2, where
// neither the raw trigger (`>`) nor the raw clear (`<`) fires, so RawAttack
// latches on across every tick (see
// TestMonitorCheckAttackRawAttackLatchesAtExactThreshold).
func TestMonitorCheckAttackCooldownDoesNotDrainDuringARawAttack(t *testing.T) {
	const name = "rl-raw-cooldown.test"
	rlRegisterDomain(t, name, rlThresholds())

	d := domains.DomainData{
		Name:                          name,
		Stage:                         1,
		RawAttack:                     true,
		BufferCooldown:                2,
		PeakRequestsPerSecond:         1500,
		PeakRequestsBypassedPerSecond: 7,
		RequestLogger:                 []domains.RequestLog{{Total: 1500, Allowed: 7}},
	}

	// Two ticks - enough for the cooldown to reach zero, fire the attack-over
	// webhook and wipe the report buffers, if it drained at all.
	d = rlTick(t, name, d, 1000, 0)
	d = rlTick(t, name, d, 1000, 0)

	if !d.RawAttack {
		t.Fatalf("fixture drifted: RawAttack = false, want true (1000 r/s is exactly DisableRawStage2, where the flag latches)")
	}
	if d.BypassAttack {
		t.Fatalf("fixture drifted: BypassAttack = true, want false")
	}
	if d.BufferCooldown != 2 {
		t.Errorf("BufferCooldown = %d, want 2: the cooldown must not drain while a raw attack is still in progress", d.BufferCooldown)
	}
	if d.PeakRequestsPerSecond != 1500 || d.PeakRequestsBypassedPerSecond != 7 {
		t.Errorf("peaks = %d / %d, want 1500 / 7: the report buffers must survive an ongoing raw attack", d.PeakRequestsPerSecond, d.PeakRequestsBypassedPerSecond)
	}
	// One sample per tick is appended on top of the seeded one.
	if len(d.RequestLogger) != 3 {
		t.Errorf("RequestLogger len = %d, want 3 (seed + one sample per tick, none wiped)", len(d.RequestLogger))
	}
}

// ---------------------------------------------------------------------------
// checkAttack's two webhook call sites
// ---------------------------------------------------------------------------
//
// checkAttack calls utils.SendWebhook from two places that differ only in the
// trailing literal: `int(0)` means "an attack started", `int(1)` means "the
// attack is over". Swapping one for the other is a one-character edit that
// makes operators get a fresh DDoS alert every time an attack ENDS, and never a
// resolution notice.
//
// SendWebhook is fire-and-forget (`go utils.SendWebhook(...)`) and its only
// observable is the POST it makes to the configured webhook URL, so these tests
// point that URL at a local server and read the payload. Note the asymmetry
// that shapes the assertions: the notificationType 0 branch builds its payload
// locally and posts immediately, while the notificationType 1 branch first
// renders a chart through quickchart.io - and when that render fails it posts
// an empty webhook instead. So "a payload carrying the attack-START message
// arrived" is a fast, positive signal, and its absence is what a correct
// attack-over notification looks like from here either way.
//
// The cases run in a child process whose proxy environment points every
// non-loopback request at a closed port, so the notificationType 1 branch's
// quickchart.io call fails at once and this suite never touches the network.
// Go's ProxyFromEnvironment never proxies loopback, so the local sink below is
// unaffected - and the env has to be set before the process starts, which is
// what the child is for.

const rlWebhookChildEnv = "LANCARSEC_TEST_WEBHOOK_CHILD"

const (
	rlAttackStartMsg = "RL-WEBHOOK-ATTACK-STARTED"
	rlAttackStopMsg  = "RL-WEBHOOK-ATTACK-STOPPED"
	// Field name that appears only in the notificationType 0 payload.
	rlStartOnlyField = "Total requests per second"
)

// rlWebhookSink is a local stand-in for the Discord webhook endpoint.
type rlWebhookSink struct {
	srv    *httptest.Server
	bodies chan string
}

func rlNewWebhookSink(t *testing.T) *rlWebhookSink {
	t.Helper()
	sink := &rlWebhookSink{bodies: make(chan string, 8)}
	sink.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		select {
		case sink.bodies <- string(body):
		default:
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(sink.srv.Close)
	return sink
}

// rlWebhookSettings wires the sink into a domain's settings.
func rlWebhookSettings(url string) domains.DomainSettings {
	s := rlThresholds()
	s.DomainWebhooks = domains.WebhookSettings{
		URL:            url,
		Name:           "rl-webhook",
		AttackStartMsg: rlAttackStartMsg,
		AttackStopMsg:  rlAttackStopMsg,
	}
	return s
}

// rlAwaitWebhook waits up to d for a payload, returning ("", false) if none
// arrives.
func rlAwaitWebhook(sink *rlWebhookSink, d time.Duration) (string, bool) {
	select {
	case body := <-sink.bodies:
		return body, true
	case <-time.After(d):
		return "", false
	}
}

// TestMonitorCheckAttackWebhookNotificationTypes drives both webhook cases in a
// network-isolated child process.
func TestMonitorCheckAttackWebhookNotificationTypes(t *testing.T) {
	rlRunChild(t, "TestMonitorCheckAttackWebhookChild",
		rlWebhookChildEnv+"=1",
		"HTTP_PROXY=http://127.0.0.1:9", "HTTPS_PROXY=http://127.0.0.1:9",
		"http_proxy=http://127.0.0.1:9", "https_proxy=http://127.0.0.1:9",
		"NO_PROXY=", "no_proxy=",
	)
}

// TestMonitorCheckAttackWebhookChild is the child half of the test above.
func TestMonitorCheckAttackWebhookChild(t *testing.T) {
	if os.Getenv(rlWebhookChildEnv) != "1" {
		t.Skip("child-process helper, driven by TestMonitorCheckAttackWebhookNotificationTypes")
	}
	t.Run("attack start fires the attack-started notification", rlWebhookAttackStartCase)
	t.Run("cooldown expiry does not fire an attack-started notification", rlWebhookCooldownExpiryCase)
}

// Control: the attack-START site really does deliver a notificationType 0
// payload, and it does so promptly. Without this the absence assertion in the
// next case would be vacuous.
func rlWebhookAttackStartCase(t *testing.T) {
	const name = "rl-webhook-start.test"
	sink := rlNewWebhookSink(t)
	rlRegisterDomain(t, name, rlWebhookSettings(sink.srv.URL))

	d := domains.DomainData{Name: name, Stage: 1}
	got := rlTick(t, name, d, 60, 50) // bypassed 50 > BypassStage1 10

	if !got.BypassAttack {
		t.Fatalf("fixture drifted: BypassAttack = false, want true")
	}

	body, ok := rlAwaitWebhook(sink, 10*time.Second)
	if !ok {
		t.Fatal("no webhook payload arrived for the attack-start site")
	}
	if !strings.Contains(body, rlAttackStartMsg) {
		t.Errorf("attack-start payload does not carry AttackStartMsg:\n%s", body)
	}
	if !strings.Contains(body, rlStartOnlyField) {
		t.Errorf("attack-start payload does not carry %q:\n%s", rlStartOnlyField, body)
	}
	if strings.Contains(body, rlAttackStopMsg) {
		t.Errorf("attack-start payload carries AttackStopMsg:\n%s", body)
	}
}

// The cooldown-expiry site must report the attack as OVER. If it were switched
// to the attack-started notification type, the payload below would carry
// AttackStartMsg - and it would arrive immediately, because that branch does no
// chart rendering.
func rlWebhookCooldownExpiryCase(t *testing.T) {
	const name = "rl-webhook-stop.test"
	sink := rlNewWebhookSink(t)
	rlRegisterDomain(t, name, rlWebhookSettings(sink.srv.URL))

	// Quiet traffic, no attack flags, one tick left on the cooldown.
	// RequestLogger must be non-empty: utils.InitPlaceholders indexes
	// RequestLogger[0] unguarded for BOTH notification types.
	d := domains.DomainData{
		Name:                          name,
		Stage:                         1,
		BufferCooldown:                1,
		PeakRequestsPerSecond:         500,
		PeakRequestsBypassedPerSecond: 400,
		RequestLogger:                 []domains.RequestLog{{Time: time.Unix(rlBase, 0), Total: 500, Allowed: 400}},
	}

	got := rlTick(t, name, d, 1, 1)
	if got.BufferCooldown != 0 {
		t.Fatalf("fixture drifted: BufferCooldown = %d, want 0 (the cooldown must expire on this tick)", got.BufferCooldown)
	}

	body, ok := rlAwaitWebhook(sink, 15*time.Second)
	if !ok {
		// The attack-over branch renders a chart before it posts. With the
		// chart host unreachable that render fails fast and an empty webhook is
		// posted instead, so a payload normally does arrive - but if the
		// unreachable host stalls instead of refusing, "nothing inside the
		// window" is still a pass. What must never happen is an attack-STARTED
		// payload, which is built locally and lands in microseconds.
		return
	}
	if strings.Contains(body, rlAttackStartMsg) {
		t.Errorf("the cooldown-expiry webhook reports the attack as STARTING, not as over:\n%s", body)
	}
	if strings.Contains(body, rlStartOnlyField) {
		t.Errorf("the cooldown-expiry webhook carries the attack-start field %q:\n%s", rlStartOnlyField, body)
	}
}
