package server

import (
	"reflect"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/azferius/lancarsec/core/firewall"
)

// ---------------------------------------------------------------------------
// Monitor's background workers.
//
// Before wave 4 these were four bare `go f()` statements. Three carried
// `defer pnc.PanicHndl()`, which records the panic and then RE-RAISES it, so a
// panic still killed the process; evaluateRatelimit carried nothing at all, so
// a panic there killed the process with no record. Either way the ratelimit
// clock stopped.
//
// They are now a table that Monitor hands to pnc.Supervise. The table is the
// thing worth pinning: it is what makes an unsupervised launch visible in
// review, and a row whose name and function have drifted apart would send an
// operator reading crash.log to the wrong function.
// ---------------------------------------------------------------------------

// funcName returns the unqualified name of the function value f points at.
func funcName(t *testing.T, f any) string {
	t.Helper()

	full := runtime.FuncForPC(reflect.ValueOf(f).Pointer()).Name()
	if i := strings.LastIndex(full, "."); i >= 0 {
		return full[i+1:]
	}
	return full
}

func TestMonitorJobsCoverEveryBackgroundWorker(t *testing.T) {
	// Exactly these five, in this order. A sixth worker added as a bare
	// `go f()` inside Monitor would leave this list unchanged and go
	// unsupervised, which is why the count is asserted and not just the
	// membership. (Wave 7 added `clock`: the dedicated ticker goroutine that
	// publishes the ratelimit clock even when the TUI stdout is blocked.)
	want := []string{
		"commands",
		"clearProxyCache",
		"generateOTPSecrets",
		"evaluateRatelimit",
		"clock",
	}

	if len(monitorJobs) != len(want) {
		t.Fatalf("monitorJobs has %d entries, want %d: %+v", len(monitorJobs), len(want), monitorJobs)
	}

	seen := map[string]bool{}
	for i, job := range monitorJobs {
		if job.name != want[i] {
			t.Errorf("monitorJobs[%d].name = %q, want %q", i, job.name, want[i])
		}
		if job.run == nil {
			t.Fatalf("monitorJobs[%d] (%q) has a nil run — Supervise would panic on it immediately", i, job.name)
		}
		if seen[job.name] {
			t.Errorf("monitorJobs[%d] repeats the name %q; crash.log entries would be ambiguous", i, job.name)
		}
		seen[job.name] = true

		// The name is what lands in crash.log. If it does not match the
		// function actually being supervised, the log points at the wrong code.
		if got := funcName(t, job.run); got != job.name {
			t.Errorf("monitorJobs[%d] is named %q but runs %s — crash.log would name the wrong worker", i, job.name, got)
		}
	}
}

// evaluateRatelimit is singled out because it is the one that had no panic
// handler at all, and the one whose death silently freezes ratelimiting for
// every domain. If a future edit drops it from the table it must fail loudly
// here rather than only shifting an index in the test above.
func TestMonitorJobsSuperviseTheRatelimitClock(t *testing.T) {
	for _, job := range monitorJobs {
		if job.name == "evaluateRatelimit" {
			if funcName(t, job.run) != "evaluateRatelimit" {
				t.Fatalf("the evaluateRatelimit row runs %s instead", funcName(t, job.run))
			}
			return
		}
	}
	t.Fatal("evaluateRatelimit is not supervised: a panic in the ratelimit clock would stop ratelimiting for every domain with no restart")
}

// The TUI's `add` command runs config.AddDomain through this hook. Wave 4
// deleted core/utils/domain.go, a second copy of the wizard that omitted the
// Stage2Difficulty question and so gave every runtime-added domain a difficulty
// of 0. The hook is nil until main wires it, and the `add` case checks for that
// rather than dereferencing it.
func TestAddDomainHookDefaultsToNil(t *testing.T) {
	if AddDomain != nil {
		t.Errorf("server.AddDomain points at %s in a fresh process, want nil until main wires config.AddDomain", funcName(t, AddDomain))
	}
}

// WAVE 8: pins the count-based eviction gate that replaced the unreachable
// Alloc/Sys heuristic (AUDIT.md:4822): a cache over its cap is dumped, one
// under its cap is left alone.
func TestEvictCachesCountGate(t *testing.T) {
	oldIps := maxIpsCacheEntries
	maxIpsCacheEntries = 0
	t.Cleanup(func() { maxIpsCacheEntries = oldIps })

	firewall.CacheIps = sync.Map{}
	firewall.CacheIps.Store("over-cap", "v")

	evictCaches()

	if _, ok := firewall.CacheIps.Load("over-cap"); ok {
		t.Fatal("CacheIps over its cap was not evicted")
	}
}
