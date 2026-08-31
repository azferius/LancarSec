package proxy

// The system-usage gauges: CPU utilisation and heap-use percentage as the
// terminal renderer publishes them.
//
// Before wave 7 these were two plain string globals written by printStats --
// the TUI rendering loop, holding nothing but PrintMutex -- and read from
// three other goroutines synchronised by something else: the cache sweeper
// held firewall.Mutex around its reads, and the admin API handlers and the
// Discord webhook builder held no lock at all. Different mutexes on the
// writer and the readers means there was no synchronisation at all; a Go
// string is two machine words, so a reader could observe the pointer of one
// value beside the length of another. That race is documented in
// docs/AUDIT.md.
//
// The gauges now follow the clock pattern (clock.go): one atomic.Pointer per
// gauge, published by the one legitimate production writer -- printStats --
// and read lock-free everywhere else. Each publish is a single pointer swap,
// so a reader sees one whole string or the previous one, never a mix.
//
// The two gauges are independent atomics rather than one published pair, on
// purpose: nothing ties a CPU reading to a RAM reading. They are taken from
// two different sources microseconds apart, and a reader (an admin JSON
// response, a webhook template) that straddles a frame boundary sees two
// adjacent frames' gauges -- a cosmetic one-second skew, not a correctness
// break, and unlike the OTP set there is no invariant that a torn pair would
// violate.

import "sync/atomic"

var (
	cpuUsage atomic.Pointer[string]
	ramUsage atomic.Pointer[string]
)

func init() {
	// Publish a real value at package init so a reader before Monitor runs --
	// only possible in tests -- sees "0" rather than nil. printStats
	// republishes once per rendering frame.
	idle := "0"
	cpuUsage.Store(&idle)
	ramUsage.Store(&idle)
}

// SetCpuUsage publishes the CPU-usage string. printStats (the TUI rendering
// loop) is the only production writer; tests use it to pin what the admin API
// and webhook templates render.
func SetCpuUsage(s string) { cpuUsage.Store(&s) }

// SetRamUsage publishes the RAM-usage string, same single-writer contract as
// SetCpuUsage.
func SetRamUsage(s string) { ramUsage.Store(&s) }

// CpuUsage returns the currently published CPU-usage string, lock-free. Never
// empty: init and SetCpuUsage always publish before any reader can run.
func CpuUsage() string {
	if p := cpuUsage.Load(); p != nil {
		return *p
	}
	return "0"
}

// RamUsage returns the currently published RAM-usage string, lock-free. Same
// never-empty contract as CpuUsage.
func RamUsage() string {
	if p := ramUsage.Load(); p != nil {
		return *p
	}
	return "0"
}
