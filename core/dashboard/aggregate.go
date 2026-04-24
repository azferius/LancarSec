package dashboard

import (
	"sort"
	"strconv"

	"lancarsec/core/domains"
	"lancarsec/core/firewall"
	"lancarsec/core/proxy"
)

// AllDomainsSentinel is the domain name the dashboard uses when the operator
// selects the global view. Domain list lookups pick this up and switch to
// aggregate math instead of per-domain.
const AllDomainsSentinel = "__all"

// IsGlobal reports whether the dashboard domain param is the aggregate view.
func IsGlobal(domain string) bool { return domain == AllDomainsSentinel }

// aggregateStats returns a cross-domain rollup: summed counters, per-domain
// breakdown rows, and the last few requests across every configured domain
// merged by timestamp. Shape mirrors statsFor so the frontend can render the
// same card skeleton with only numbers swapped in.
func aggregateStats(list []string) map[string]any {
	if list == nil {
		list = domainList()
	}
	breakdown := make([]map[string]any, 0, len(list))

	var (
		totalRPS        int
		bypassedRPS     int
		totalReq        int64
		bypassedReq     int64
		peakRPS         int
		domainsAttacked int
		allLogs         []domainLogEntry
	)

	for _, name := range list {
		firewall.DataMu.RLock()
		d, ok := domains.DomainsData[name]
		logs := append([]domains.DomainLog(nil), d.LastLogs...)
		firewall.DataMu.RUnlock()
		if !ok {
			continue
		}

		ctr := domains.CountersFor(name)
		t := ctr.Total.Load()
		b := ctr.Bypassed.Load()

		totalRPS += d.RequestsPerSecond
		bypassedRPS += d.RequestsBypassedPerSecond
		totalReq += t
		bypassedReq += b
		if d.PeakRequestsPerSecond > peakRPS {
			peakRPS = d.PeakRequestsPerSecond
		}
		if d.BypassAttack || d.RawAttack {
			domainsAttacked++
		}

		for _, l := range logs {
			allLogs = append(allLogs, domainLogEntry{domain: name, log: l})
		}

		breakdown = append(breakdown, map[string]any{
			"domain":        name,
			"stage":         d.Stage,
			"stage_locked":  d.StageManuallySet,
			"rps":           d.RequestsPerSecond,
			"rps_bypassed":  d.RequestsBypassedPerSecond,
			"total":         t,
			"bypassed":      b,
			"peak_rps":      d.PeakRequestsPerSecond,
			"bypass_attack": d.BypassAttack,
			"raw_attack":    d.RawAttack,
		})
	}

	// Sort breakdown by current RPS desc so the hottest domain lands first.
	sort.Slice(breakdown, func(i, j int) bool {
		return breakdown[i]["rps"].(int) > breakdown[j]["rps"].(int)
	})

	// Mixed log tail across all domains, newest first (we sorted by time but
	// the underlying buffer is time-sorted ascending per-domain — a merge is
	// enough for the visible tail).
	merged := mergeLogs(allLogs, 50)

	return map[string]any{
		"domain":           AllDomainsSentinel,
		"is_global":        true,
		"rps":              totalRPS,
		"rps_bypassed":     bypassedRPS,
		"rps_blocked":      totalRPS - bypassedRPS,
		"peak_rps":         peakRPS,
		"total":            totalReq,
		"bypassed":         bypassedReq,
		"domains_count":    len(breakdown),
		"domains_attacked": domainsAttacked,
		"cpu":              proxy.GetCPUUsage(),
		"ram":              proxy.GetRAMUsage(),
		"l4_connections":   firewall.ActiveConnectionCount(),
		"breakdown":        breakdown,
		"logs":             merged,
	}
}

type domainLogEntry struct {
	domain string
	log    domains.DomainLog
}

// mergeLogs picks the newest n entries across all domains. The per-domain
// log buffers are already chronological, so a stable sort on the end of
// each buffer is enough.
func mergeLogs(entries []domainLogEntry, n int) []map[string]any {
	// Sort descending by time string (HH:MM:SS lexicographic = chronological
	// within the same hour, good enough for a rolling tail).
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].log.Time > entries[j].log.Time
	})
	if len(entries) > n {
		entries = entries[:n]
	}
	out := make([]map[string]any, 0, len(entries))
	for _, e := range entries {
		out = append(out, map[string]any{
			"time":        e.log.Time,
			"ip":          e.log.IP,
			"country":     e.log.Country,
			"engine":      e.log.BrowserFP,
			"bot":         e.log.BotFP,
			"fingerprint": e.log.TLSFP,
			"ja3":         e.log.JA3,
			"ja4":         e.log.JA4,
			"ja4_r":       e.log.JA4R,
			"ja4_o":       e.log.JA4O,
			"ja4h":        e.log.JA4H,
			"user_agent":  e.log.Useragent,
			"method":      e.log.Method,
			"path":        e.log.Path,
			"protocol":    e.log.Protocol,
			"status":      e.log.Status,
			"size":        e.log.Size,
			"domain":      e.domain,
		})
	}
	return out
}

// aggregateAnalytics combines RequestLogger samples across all domains into
// one stream, summing Total/Allowed per matching timestamp. Used by the
// analytics page when viewing global.
func aggregateAnalytics(list []string) map[string]any {
	if list == nil {
		list = domainList()
	}
	// Keyed by "HH:MM:SS" — coarse but matches the per-domain granularity.
	byTime := map[string]*aggSample{}
	var peakRPS, peakBypassed int
	var bypassAttack, rawAttack bool

	for _, name := range list {
		firewall.DataMu.RLock()
		d, ok := domains.DomainsData[name]
		samples := append([]domains.RequestLog(nil), d.RequestLogger...)
		firewall.DataMu.RUnlock()
		if !ok {
			continue
		}

		if d.PeakRequestsPerSecond > peakRPS {
			peakRPS = d.PeakRequestsPerSecond
		}
		if d.PeakRequestsBypassedPerSecond > peakBypassed {
			peakBypassed = d.PeakRequestsBypassedPerSecond
		}
		bypassAttack = bypassAttack || d.BypassAttack
		rawAttack = rawAttack || d.RawAttack

		for _, s := range samples {
			t := s.Time.Format("15:04:05")
			existing := byTime[t]
			cpuF, _ := strconv.ParseFloat(s.CpuUsage, 64)
			if existing == nil {
				byTime[t] = &aggSample{t: t, total: s.Total, allowed: s.Allowed, cpu: cpuF, count: 1}
			} else {
				existing.total += s.Total
				existing.allowed += s.Allowed
				// CPU is host-wide, not per-domain, so average across samples
				// that fell in the same bucket.
				existing.cpu = (existing.cpu*float64(existing.count) + cpuF) / float64(existing.count+1)
				existing.count++
			}
		}
	}

	times := make([]string, 0, len(byTime))
	for t := range byTime {
		times = append(times, t)
	}
	sort.Strings(times)
	samples := make([]map[string]any, 0, len(times))
	for _, t := range times {
		s := byTime[t]
		samples = append(samples, map[string]any{
			"t":       s.t,
			"total":   s.total,
			"allowed": s.allowed,
			"cpu":     s.cpu,
		})
	}
	return map[string]any{
		"domain":        AllDomainsSentinel,
		"is_global":     true,
		"samples":       samples,
		"peak_rps":      peakRPS,
		"peak_bypassed": peakBypassed,
		"bypass_attack": bypassAttack,
		"raw_attack":    rawAttack,
	}
}

type aggSample struct {
	t       string
	total   int
	allowed int
	cpu     float64
	count   int
}
