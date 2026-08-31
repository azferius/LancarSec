package proxy

// The request-path clock.
//
// Before wave 7 these values were plain package globals rewritten once per
// second by printStats, the terminal-rendering loop. That loop runs under
// PrintMutex and every write to stdout serialises against it, so a blocked
// stdout -- a full systemd journal pipe, a stopped console, a dead SSH client
// holding the tty -- froze the clock. With it froze the sliding window: every
// request kept incrementing the same 10-second bucket while the sweeper's
// "now" never advanced, so every client walked into a ratelimit that had no
// window to recover from, and sat there until stdout unblocked.
//
// The clock is now owned by atomics and published by a dedicated goroutine
// ("clock" in monitorJobs) whose only job is to call UpdateClock once per
// second. It prints nothing and blocks on nothing. The rendering loop, the
// request path and the sweeper are all just readers now, and they read without
// a lock.

import (
	"sync/atomic"
	"time"
)

// TrimTime floors a unix timestamp onto the 10-second bucket grid the
// sliding-window ratelimit is keyed on.
//
// It moved here from core/utils in wave 7 because the clock lives in this
// package and core/utils imports core/proxy (for MaxLogLength), so proxy
// cannot import utils back. core/utils.TrimTime remains as a delegating
// wrapper so the tests that pin its edge cases keep their import graph.
//
// NOTE, still true and still deliberate: this is integer division, which
// truncates TOWARD ZERO, not toward negative infinity. For negative
// timestamps (unreachable with real unix time) the bucket rounds up. The
// wave-3 tests pin that; do not "fix" it in passing.
func TrimTime(timestamp int) int {
	return timestamp - timestamp%10
}

var (
	lastSecondTimestamp    atomic.Int64 // unix seconds, second resolution
	last10SecondTimestamp  atomic.Int64 // TrimTime(lastSecondTimestamp)
	lastSecondTimeFormated atomic.Pointer[string]
)

func init() {
	// Publish a real clock at package init so a request served before Monitor
	// runs -- only possible in tests -- still reads a plausible clock rather
	// than the zero time. Monitor re-publishes synchronously before the first
	// listener opens, and the clock goroutine takes over from there.
	UpdateClock(time.Now())
}

// UpdateClock publishes `now` as the request-path clock: the second-resolution
// timestamp, its 10-second bucket and the "15:04:05" string the access-log
// rows carry.
//
// Called by the clock goroutine once per second, by Monitor once
// synchronously before the jobs start, and by tests to pin the clock. It is
// the ONLY writer; there is no other seam.
func UpdateClock(now time.Time) {
	unix := now.Unix()
	lastSecondTimestamp.Store(unix)
	last10SecondTimestamp.Store(int64(TrimTime(int(unix))))
	formatted := now.Format("15:04:05")
	lastSecondTimeFormated.Store(&formatted)
}

// LastSecondTimestamp returns the current second-resolution unix time as
// published by the clock goroutine.
func LastSecondTimestamp() int64 {
	return lastSecondTimestamp.Load()
}

// Last10SecondTimestamp returns the 10-second bucket the sliding-window
// ratelimit is currently writing into.
func Last10SecondTimestamp() int64 {
	return last10SecondTimestamp.Load()
}

// LastSecondTimeFormatted returns the clock formatted "15:04:05", as access-log
// rows carry it. Never nil: init and UpdateClock always publish a string
// before any reader can run.
func LastSecondTimeFormatted() string {
	if p := lastSecondTimeFormated.Load(); p != nil {
		return *p
	}
	return ""
}
