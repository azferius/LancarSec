package domains

import (
	"sync"
	"sync/atomic"
)

// DomainCounters carries the per-domain counters that middleware increments
// on every request. Pulled out of DomainData (which is the full per-domain
// struct, copied under DataMu) so we can update them without any lock: the
// middleware hot path just does Total.Add(1) / Bypassed.Add(1).
//
// The monitor/dashboards periodically diff Total vs prev to compute r/s.
type DomainCounters struct {
	Total    atomic.Int64
	Bypassed atomic.Int64
}

// CountersFor returns the *DomainCounters for a domain, creating and
// registering one atomically on first call. Missing domains on reload get
// fresh counters — prior in-flight requests that saved a pointer keep
// writing into the old object, which is harmless because it's no longer
// read.
var domainCounters sync.Map // string -> *DomainCounters

func CountersFor(domain string) *DomainCounters {
	if v, ok := domainCounters.Load(domain); ok {
		return v.(*DomainCounters)
	}
	c := &DomainCounters{}
	actual, _ := domainCounters.LoadOrStore(domain, c)
	return actual.(*DomainCounters)
}

// ResetCounters wipes the registry so a reload can start fresh. Existing
// pointers remain valid; future lookups get new ones.
func ResetCounters() {
	domainCounters = sync.Map{}
}
