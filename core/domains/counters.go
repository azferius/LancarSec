package domains

// WAVE 12 (task B): the per-domain request counters moved out of DomainData
// onto lock-free atomics.
//
// TotalRequests and BypassedRequests were plain struct fields incremented ONCE
// PER REQUEST behind firewall.Mutex, with the whole DomainData value copied in
// and back out of the DomainsData map to reach them. That increment was half
// of every request's global write-lock traffic, so it now lives in a parallel
// map of atomic counters: the request path takes NO lock to count a request,
// and the monitor folds the atomics into the DomainsData struct once a second
// (checkAttack) where the per-second rates and peaks are derived.
//
// The counters are deliberately NOT fields of DomainData: an atomic.Int64 is
// noCopy, so a struct containing one can no longer be copied - and
// DomainData values are copied everywhere (map reads, checkAttack's by-value
// parameter, mergeDomainData, the tests' reflect.DeepEqual) - which is
// CONC-06's empirical finding from wave 9.

import (
	"sync"
	"sync/atomic"
)

type domainCounters struct {
	total    atomic.Int64
	bypassed atomic.Int64
}

// domainCountersMap is map[string]*domainCounters. Entries are created lazily
// by the request path (LoadOrStore), so a request naming a domain never
// allocates under a lock; the map is read-mostly after warmup and sync.Map's
// read path is lock-free.
var domainCountersMap sync.Map

func countersFor(name string) *domainCounters {
	if c, ok := domainCountersMap.Load(name); ok {
		return c.(*domainCounters)
	}
	c, _ := domainCountersMap.LoadOrStore(name, &domainCounters{})
	return c.(*domainCounters)
}

// AddDomainTotal counts one request for the domain. Called once per request
// from the middleware; lock-free.
func AddDomainTotal(name string) {
	countersFor(name).total.Add(1)
}

// AddDomainBypassed counts one challenge-passing request for the domain.
// Called once per request from the middleware; lock-free.
func AddDomainBypassed(name string) {
	countersFor(name).bypassed.Add(1)
}

// DomainTotal returns the domain's total request count, or 0 for a domain
// that has never served a request.
func DomainTotal(name string) int64 {
	if c, ok := domainCountersMap.Load(name); ok {
		return c.(*domainCounters).total.Load()
	}
	return 0
}

// DomainBypassed returns the domain's challenge-passing request count, or 0
// for a domain that has never served a request.
func DomainBypassed(name string) int64 {
	if c, ok := domainCountersMap.Load(name); ok {
		return c.(*domainCounters).bypassed.Load()
	}
	return 0
}

// DeleteDomainCounters forgets a domain's counters. The config converge loop
// calls it under firewall.Mutex when a domain is removed from config.json, so
// re-adding the domain later starts from zero - the same reset the old
// struct-field counters got when reload deleted their DomainsData row.
func DeleteDomainCounters(name string) {
	domainCountersMap.Delete(name)
}

// ResetCounters forgets every domain's counters. Test-only: the map is
// package-global and outlives DomainsData, so a test binary that reuses a
// domain name would otherwise inherit the previous test's totals.
func ResetCounters() {
	domainCountersMap.Clear()
}
