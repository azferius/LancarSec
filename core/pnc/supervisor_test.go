package pnc

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Supervision of long-lived background goroutines.
//
// The behaviour under test is the one that keeps the proxy's ratelimit clock
// alive: a panic inside a supervised worker must be written to crash.log and the
// worker restarted, instead of reaching the runtime (which kills the process) or
// simply ending the goroutine (which stops the clock with no trace).
//
// Every test drives superviseLoop directly with an injected sleep and clock, so
// hundreds of simulated restarts cost no wall time and the backoff schedule is
// observable rather than inferred from timing.
// ---------------------------------------------------------------------------

// crashLogIn points the package's crash.log at a fresh file in a temp directory
// and restores the previous one. InitHndl opens "crash.log" relative to the
// working directory, so this chdirs the way the real process is deployed.
func crashLogIn(t *testing.T) string {
	t.Helper()

	dir := t.TempDir()
	prev, err := os.Getwd()
	if err != nil {
		t.Fatalf("reading the working directory: %v", err)
	}

	logMu.Lock()
	prevFile := logFile
	logMu.Unlock()

	t.Cleanup(func() {
		logMu.Lock()
		if logFile != nil && logFile != prevFile {
			logFile.Close()
		}
		logFile = prevFile
		logMu.Unlock()
		if err := os.Chdir(prev); err != nil {
			t.Errorf("restoring the working directory: %v", err)
		}
	})

	if err := os.Chdir(dir); err != nil {
		t.Fatalf("entering the temp working directory: %v", err)
	}
	InitHndl()

	resolved, err := os.Getwd()
	if err != nil {
		t.Fatalf("reading the temp working directory: %v", err)
	}
	return filepath.Join(resolved, "crash.log")
}

func readCrashLog(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading crash.log: %v", err)
	}
	return string(b)
}

// fakeClock records every sleep the supervisor asks for and advances a virtual
// "now" by exactly that much, so a test can assert the backoff schedule and let
// a worker appear to run for a controlled length of time.
type fakeClock struct {
	mu     sync.Mutex
	now    time.Time
	slept  []time.Duration
	runFor time.Duration // advanced before each worker returns; set by the test
}

func newFakeClock() *fakeClock {
	return &fakeClock{now: time.Unix(1700000000, 0)}
}

func (c *fakeClock) sleep(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.slept = append(c.slept, d)
	c.now = c.now.Add(d)
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

func (c *fakeClock) sleeps() []time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]time.Duration(nil), c.slept...)
}

// testPolicy keeps the schedule small enough to read in an assertion while
// preserving the shape of the real one: double until a cap.
var testPolicy = RestartPolicy{
	InitialBackoff: 1 * time.Second,
	MaxBackoff:     8 * time.Second,
	HealthyRun:     1 * time.Minute,
}

// The core promise: a panicking worker comes back. Before wave 4,
// evaluateRatelimit was launched with a bare `go evaluateRatelimit()` and the
// first panic inside it ended the process.
func TestSuperviseRestartsAPanickingWorker(t *testing.T) {
	crashLogIn(t)

	runs := 0
	clock := newFakeClock()

	superviseLoop("worker", testPolicy, clock.sleep, clock.Now, func() {
		runs++
		if runs <= 3 {
			panic("boom")
		}
		// The fourth run returns cleanly, which is how this test terminates.
	})

	if runs != 4 {
		t.Errorf("worker ran %d times, want 4 (three panics, each restarted, then a clean return)", runs)
	}
}

// A panic must never escape the supervisor. This is the difference from
// PanicHndl, which re-raises on purpose: re-raising inside a goroutine is what
// kills the process.
func TestSupervisePanicDoesNotEscape(t *testing.T) {
	crashLogIn(t)

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("a supervised panic escaped the supervisor: %v", r)
		}
	}()

	first := true
	clock := newFakeClock()
	superviseLoop("worker", testPolicy, clock.sleep, clock.Now, func() {
		if first {
			first = false
			panic("boom")
		}
	})
}

// A worker that returns on its own has finished; restarting it would both
// second-guess it and, for a worker that returns immediately, spin.
func TestSuperviseDoesNotRestartACleanReturn(t *testing.T) {
	crashLogIn(t)

	runs := 0
	clock := newFakeClock()
	superviseLoop("worker", testPolicy, clock.sleep, clock.Now, func() { runs++ })

	if runs != 1 {
		t.Errorf("worker ran %d times, want 1 — a clean return must not be restarted", runs)
	}
	if got := clock.sleeps(); len(got) != 0 {
		t.Errorf("supervisor slept %v after a clean return, want no sleeps at all", got)
	}
}

// The restart-storm bound. A worker that panics the instant it starts must be
// retried on a doubling backoff capped at MaxBackoff, never in a tight loop.
func TestSuperviseBacksOffExponentiallyAndCaps(t *testing.T) {
	crashLogIn(t)

	runs := 0
	clock := newFakeClock()
	superviseLoop("worker", testPolicy, clock.sleep, clock.Now, func() {
		runs++
		if runs <= 6 {
			panic("boom")
		}
	})

	want := []time.Duration{
		1 * time.Second,
		2 * time.Second,
		4 * time.Second,
		8 * time.Second,
		8 * time.Second, // capped
		8 * time.Second, // capped
	}
	got := clock.sleeps()
	if len(got) != len(want) {
		t.Fatalf("backoff schedule = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("backoff[%d] = %s, want %s (full schedule %v)", i, got[i], want[i], got)
		}
	}
}

// The bound has to hold for a long crash loop too, and nothing may ever sleep
// for zero: a zero sleep IS the spin this test exists to rule out.
func TestSuperviseNeverSpinsOnAnImmediatePanicLoop(t *testing.T) {
	crashLogIn(t)

	const crashes = 500
	runs := 0
	clock := newFakeClock()
	superviseLoop("worker", testPolicy, clock.sleep, clock.Now, func() {
		runs++
		if runs <= crashes {
			panic("boom")
		}
	})

	got := clock.sleeps()
	if len(got) != crashes {
		t.Fatalf("supervisor slept %d times for %d crashes", len(got), crashes)
	}

	var total time.Duration
	for i, d := range got {
		if d < testPolicy.InitialBackoff {
			t.Fatalf("backoff[%d] = %s, below the %s floor — that is a spin", i, d, testPolicy.InitialBackoff)
		}
		if d > testPolicy.MaxBackoff {
			t.Fatalf("backoff[%d] = %s, above the %s cap", i, d, testPolicy.MaxBackoff)
		}
		total += d
	}

	// 500 immediate crashes must occupy at least (500-4) * MaxBackoff of
	// virtual time — i.e. the loop is rate-limited, not merely delayed once.
	if min := time.Duration(crashes-4) * testPolicy.MaxBackoff; total < min {
		t.Errorf("500 crashes took %s of backoff, want at least %s", total, min)
	}
}

// A worker that stayed up for a real shift and then died is not in a crash
// loop, so the next restart must be prompt rather than inheriting a capped
// backoff from an incident hours earlier.
func TestSuperviseResetsBackoffAfterAHealthyRun(t *testing.T) {
	crashLogIn(t)

	runs := 0
	clock := newFakeClock()
	superviseLoop("worker", testPolicy, clock.sleep, clock.Now, func() {
		runs++
		switch {
		case runs <= 4:
			// Four immediate crashes: 1s, 2s, 4s, 8s.
			panic("boom")
		case runs == 5:
			// This one worked for a full day before dying.
			clock.advance(24 * time.Hour)
			panic("boom")
		}
	})

	got := clock.sleeps()
	want := []time.Duration{
		1 * time.Second,
		2 * time.Second,
		4 * time.Second,
		8 * time.Second,
		1 * time.Second, // reset by the healthy run
	}
	if len(got) != len(want) {
		t.Fatalf("backoff schedule = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("backoff[%d] = %s, want %s (full schedule %v)", i, got[i], want[i], got)
		}
	}
}

// A run exactly at the HealthyRun boundary counts as healthy. Pinned because
// `>` versus `>=` here is a one-character mutation that nothing else notices.
func TestSuperviseTreatsExactlyHealthyRunAsHealthy(t *testing.T) {
	crashLogIn(t)

	runs := 0
	clock := newFakeClock()
	superviseLoop("worker", testPolicy, clock.sleep, clock.Now, func() {
		runs++
		if runs <= 2 {
			clock.advance(testPolicy.HealthyRun)
			panic("boom")
		}
	})

	got := clock.sleeps()
	want := []time.Duration{1 * time.Second, 1 * time.Second}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Errorf("backoff schedule = %v, want %v — a run of exactly HealthyRun must reset the backoff", got, want)
	}
}

// crash.log is the only trace an operator has of a restarted worker, so it has
// to name the worker, carry the panic value, carry a stack, and count the
// consecutive failures — that count is what separates one crash loop from four
// unrelated crashes.
func TestSuperviseWritesEveryPanicToCrashLog(t *testing.T) {
	path := crashLogIn(t)

	runs := 0
	clock := newFakeClock()
	superviseLoop("evaluateRatelimit", testPolicy, clock.sleep, clock.Now, func() {
		runs++
		if runs <= 2 {
			panic("the ratelimit clock fell over")
		}
	})

	log := readCrashLog(t, path)

	if n := strings.Count(log, "Supervised goroutine"); n != 2 {
		t.Errorf("crash.log holds %d supervisor entries, want 2:\n%s", n, log)
	}
	if !strings.Contains(log, `"evaluateRatelimit"`) {
		t.Errorf("crash.log does not name the worker:\n%s", log)
	}
	if !strings.Contains(log, "the ratelimit clock fell over") {
		t.Errorf("crash.log does not carry the panic value:\n%s", log)
	}
	if !strings.Contains(log, "consecutive failure 1") || !strings.Contains(log, "consecutive failure 2") {
		t.Errorf("crash.log does not count consecutive failures:\n%s", log)
	}
	// The stack has to be the worker's, captured at the panic site.
	if !strings.Contains(log, "core/pnc.runGuarded") && !strings.Contains(log, "runtime.gopanic") {
		t.Errorf("crash.log does not carry a goroutine stack:\n%s", log)
	}
}

// crash.log may not exist yet — InitHndl has not run, or it failed. Recording
// is best-effort; restarting the worker is not.
func TestSuperviseRestartsEvenWithoutACrashLog(t *testing.T) {
	logMu.Lock()
	prev := logFile
	logFile = nil
	logMu.Unlock()
	t.Cleanup(func() {
		logMu.Lock()
		logFile = prev
		logMu.Unlock()
	})

	runs := 0
	clock := newFakeClock()
	superviseLoop("worker", testPolicy, clock.sleep, clock.Now, func() {
		runs++
		if runs <= 2 {
			panic("boom")
		}
	})

	if runs != 3 {
		t.Errorf("worker ran %d times without a crash.log, want 3", runs)
	}
}

// A zero RestartPolicy must not configure a busy loop. Supervise's callers pass
// DefaultRestartPolicy, but SuperviseWithPolicy is exported and a zero struct is
// the easiest thing to pass by accident.
func TestRestartPolicyZeroValueFallsBackToTheDefaults(t *testing.T) {
	got := RestartPolicy{}.sane()
	if got != DefaultRestartPolicy {
		t.Errorf("RestartPolicy{}.sane() = %+v, want %+v", got, DefaultRestartPolicy)
	}
	if DefaultRestartPolicy.InitialBackoff <= 0 {
		t.Error("DefaultRestartPolicy.InitialBackoff must be positive — a zero backoff is a spin")
	}
	if DefaultRestartPolicy.MaxBackoff < DefaultRestartPolicy.InitialBackoff {
		t.Error("DefaultRestartPolicy.MaxBackoff must be at least InitialBackoff")
	}
}

// A MaxBackoff below InitialBackoff would otherwise make the cap shrink the
// first sleep. Clamp it up instead.
func TestRestartPolicySaneRaisesAnUndersizedMaxBackoff(t *testing.T) {
	got := RestartPolicy{
		InitialBackoff: 5 * time.Second,
		MaxBackoff:     1 * time.Second,
		HealthyRun:     time.Minute,
	}.sane()

	if got.MaxBackoff != 5*time.Second {
		t.Errorf("MaxBackoff = %s, want it clamped up to InitialBackoff (5s)", got.MaxBackoff)
	}
}

// The exported entry point really does run the worker on its own goroutine and
// really does restart it. Everything above drives superviseLoop directly, so
// without this the wiring in Supervise/SuperviseWithPolicy is untested.
func TestSuperviseWithPolicyRunsAndRestartsOnItsOwnGoroutine(t *testing.T) {
	crashLogIn(t)

	var mu sync.Mutex
	runs := 0
	done := make(chan struct{})

	SuperviseWithPolicy("worker", RestartPolicy{
		InitialBackoff: time.Millisecond,
		MaxBackoff:     time.Millisecond,
		HealthyRun:     time.Hour,
	}, func() {
		mu.Lock()
		runs++
		n := runs
		mu.Unlock()
		if n <= 2 {
			panic("boom")
		}
		close(done)
	})

	select {
	case <-done:
	case <-time.After(30 * time.Second):
		mu.Lock()
		n := runs
		mu.Unlock()
		t.Fatalf("the supervised worker never reached its third run (got %d)", n)
	}
}
