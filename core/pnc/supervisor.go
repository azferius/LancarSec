package pnc

import (
	"fmt"
	"runtime"
	"time"
)

// ---------------------------------------------------------------------------
// Supervision of long-lived background goroutines.
//
// An unrecovered panic in ANY goroutine takes the whole process down; that is
// Go's rule and there is no way to opt a single goroutine out of it from the
// outside. PanicHndl does not change that -- it records the panic and re-raises
// it -- so before wave 4 the proxy's background workers had exactly two
// outcomes: die with a crash.log entry (commands, clearProxyCache,
// generateOTPSecrets), or die without one (evaluateRatelimit, which had no
// handler at all).
//
// Neither is acceptable for evaluateRatelimit in particular. It is the
// ratelimit clock: it rebuilds the sliding-window totals every five seconds and
// prefills the buckets the request path writes into. If it stops, the whole
// proxy's ratelimiting stops with it.
//
// Supervise gives those goroutines a third outcome: record the panic and start
// the worker again.
// ---------------------------------------------------------------------------

// RestartPolicy bounds how hard a supervisor retries a worker that keeps dying.
type RestartPolicy struct {
	// InitialBackoff is how long to wait before the first restart, and the
	// value the backoff resets to after a healthy run.
	InitialBackoff time.Duration

	// MaxBackoff caps the exponential growth. This is what stops a restart
	// storm: a worker that panics the instant it starts is retried at most once
	// per MaxBackoff for as long as it keeps failing, instead of spinning the
	// CPU and filling crash.log as fast as the scheduler allows.
	MaxBackoff time.Duration

	// HealthyRun is how long a worker has to stay up before its next panic is
	// treated as a fresh incident rather than a continuing one. Below this, the
	// backoff keeps doubling; at or above it, the backoff resets. Every worker
	// Monitor supervises is an infinite loop that is meant to run for the life
	// of the process, so anything under a minute is a crash loop.
	HealthyRun time.Duration
}

// DefaultRestartPolicy is what Supervise uses.
//
// The bound on restart storms is the MaxBackoff cap, not a give-up count. A
// supervised worker here is load-bearing -- abandoning the ratelimit clock
// after N tries would be a silent, permanent outage, which is precisely the
// failure this supervisor exists to prevent -- so it retries forever, but at a
// rate that cannot exceed twice a minute no matter how fast it fails. A worker
// wedged in a crash loop therefore costs ~2 crash.log entries per minute and
// effectively no CPU, and the entries carry a consecutive-failure counter so an
// operator reading crash.log can tell a crash loop from four unrelated crashes
// at a glance.
var DefaultRestartPolicy = RestartPolicy{
	InitialBackoff: 1 * time.Second,
	MaxBackoff:     30 * time.Second,
	HealthyRun:     1 * time.Minute,
}

// sane replaces non-positive fields with the defaults, so a zero RestartPolicy
// is usable and a caller cannot accidentally configure a busy loop.
func (p RestartPolicy) sane() RestartPolicy {
	if p.InitialBackoff <= 0 {
		p.InitialBackoff = DefaultRestartPolicy.InitialBackoff
	}
	if p.MaxBackoff <= 0 {
		p.MaxBackoff = DefaultRestartPolicy.MaxBackoff
	}
	// An explicit cap below the floor would otherwise shrink the very first
	// sleep; raise it rather than silently shortening the backoff.
	if p.MaxBackoff < p.InitialBackoff {
		p.MaxBackoff = p.InitialBackoff
	}
	if p.HealthyRun <= 0 {
		p.HealthyRun = DefaultRestartPolicy.HealthyRun
	}
	return p
}

// Supervise runs fn in its own goroutine and keeps it running under
// DefaultRestartPolicy.
//
// A panic inside fn is recorded in crash.log and fn is started again after a
// backoff. A normal return from fn is treated as a deliberate exit and the
// supervisor stops -- that is what keeps a function which returns immediately
// from becoming a hot loop.
//
// name is what appears in crash.log; use the worker's function name.
//
// Caveat worth knowing before adding a worker here: restarting a function that
// panicked while holding a mutex it unlocks with a plain statement rather than
// a defer will deadlock on the next acquisition instead of crashing. Three of
// the four workers Monitor supervises are in that shape today (firewall.Mutex
// in clearProxyCache and evaluateRatelimit, PrintMutex in commands). The
// supervisor writes crash.log BEFORE it restarts, so such a wedge is always
// preceded by a named entry rather than being silent -- but converting those
// unlocks to defers is the real fix and is still outstanding.
func Supervise(name string, fn func()) {
	SuperviseWithPolicy(name, DefaultRestartPolicy, fn)
}

// SuperviseWithPolicy is Supervise with an explicit RestartPolicy.
func SuperviseWithPolicy(name string, policy RestartPolicy, fn func()) {
	go superviseLoop(name, policy, time.Sleep, time.Now, fn)
}

// superviseLoop is the supervisor body, with the clock and the sleep injected so
// tests can drive many simulated restarts without waiting for real time.
func superviseLoop(name string, policy RestartPolicy, sleep func(time.Duration), now func() time.Time, fn func()) {
	policy = policy.sane()

	backoff := policy.InitialBackoff
	consecutive := 0

	for {
		startedAt := now()
		recovered, stack := runGuarded(fn)
		if recovered == nil {
			// fn chose to return. Restarting it would be second-guessing the
			// worker, and for a worker that returns immediately it would be a
			// busy loop.
			return
		}

		if now().Sub(startedAt) >= policy.HealthyRun {
			// It did real work before it died, so this is a new incident and
			// not a continuing crash loop.
			backoff = policy.InitialBackoff
			consecutive = 0
		}
		consecutive++

		writeCrashLog(fmt.Sprintf(
			"[ %s ]: Supervised goroutine %q panicked (consecutive failure %d, restarting in %s): %v\n\n%s\n",
			time.Now().Format("15:04:05"), name, consecutive, backoff, recovered, stack,
		))

		sleep(backoff)

		backoff *= 2
		if backoff > policy.MaxBackoff {
			backoff = policy.MaxBackoff
		}
	}
}

// runGuarded calls fn and converts a panic into a return value plus the stack
// captured at the panic site. It deliberately does NOT re-raise, which is the
// one behavioural difference from PanicHndl.
func runGuarded(fn func()) (recovered any, stack []byte) {
	defer func() {
		if r := recover(); r != nil {
			recovered = r
			// 64 KiB, not PanicHndl's 4 MiB: this runs on every restart of a
			// crash-looping worker, and a goroutine-local stack that does not
			// fit in 64 KiB is already unreadable.
			buf := make([]byte, 64<<10)
			stack = buf[:runtime.Stack(buf, false)]
		}
	}()

	fn()
	return nil, nil
}
