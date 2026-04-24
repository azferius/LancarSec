package firewall

import (
	"net"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"lancarsec/core/domains"
)

// BlockDecision is the outcome of a blocklist evaluation. Hit reports whether
// the request matched any entry; Entry names the matched row so the middleware
// can log the reason and the UI can surface it.
type BlockDecision struct {
	Hit   bool
	Entry domains.BlockEntry
}

// compiledBlocklist is the hot-path shape of the blocklist: CIDR ranges are
// pre-parsed, regexes pre-compiled, UA-contains kept lowercased. A read-only
// snapshot is published via atomic.Pointer so middleware can evaluate without
// taking a lock in the hot path.
type compiledBlocklist struct {
	ips     map[string]domains.BlockEntry // exact IP (v4 or v6)
	cidrs   []cidrRow
	asnSet  map[string]domains.BlockEntry // ASN number as string
	uaSubs  []uaSub
	uaRegex []uaRegex
}

type cidrRow struct {
	net   *net.IPNet
	entry domains.BlockEntry
}
type uaSub struct {
	needle string // lowercased
	entry  domains.BlockEntry
}
type uaRegex struct {
	re    *regexp.Regexp
	entry domains.BlockEntry
}

// Global and per-domain compiled blocklists. Published atomically on each
// config reload so middleware reads are lock-free.
var (
	globalBlock  atomic.Pointer[compiledBlocklist]
	domainBlocks sync.Map // domain string -> *compiledBlocklist
)

// RebuildBlocklists is called by config.Apply after a (re)load. It re-parses
// every BlockEntry from the live configuration and publishes fresh pointers.
// Expired entries are dropped at compile time — a nightly eviction isn't
// needed because each reload does the sweep.
func RebuildBlocklists(globalEntries []domains.BlockEntry, perDomain map[string][]domains.BlockEntry) {
	globalBlock.Store(compile(globalEntries))
	// Clear stale domain entries from the last config, then install new ones.
	domainBlocks.Range(func(k, _ any) bool { domainBlocks.Delete(k); return true })
	for dom, entries := range perDomain {
		domainBlocks.Store(dom, compile(entries))
	}
}

func compile(entries []domains.BlockEntry) *compiledBlocklist {
	now := time.Now().Unix()
	cb := &compiledBlocklist{
		ips:    map[string]domains.BlockEntry{},
		asnSet: map[string]domains.BlockEntry{},
	}
	for _, e := range entries {
		if e.Expires > 0 && e.Expires < now {
			continue
		}
		switch e.Type {
		case "ip":
			ip := net.ParseIP(strings.TrimSpace(e.Value))
			if ip == nil {
				continue
			}
			cb.ips[ip.String()] = e
		case "cidr":
			_, n, err := net.ParseCIDR(strings.TrimSpace(e.Value))
			if err != nil {
				continue
			}
			cb.cidrs = append(cb.cidrs, cidrRow{net: n, entry: e})
		case "asn":
			v := strings.TrimPrefix(strings.TrimSpace(e.Value), "AS")
			if v == "" {
				continue
			}
			cb.asnSet[v] = e
		case "ua_contains":
			needle := strings.ToLower(strings.TrimSpace(e.Value))
			if needle == "" {
				continue
			}
			cb.uaSubs = append(cb.uaSubs, uaSub{needle: needle, entry: e})
		case "ua_regex":
			re, err := regexp.Compile(e.Value)
			if err != nil {
				continue
			}
			cb.uaRegex = append(cb.uaRegex, uaRegex{re: re, entry: e})
		}
	}
	return cb
}

// Evaluate runs the full blocklist check for one request: IP first (cheapest),
// then CIDR, then ASN (if we can resolve), then UA patterns. Returns the first
// hit or a no-hit zero value.
//
// Checks both the global list and the per-domain list. Domain is passed so
// per-domain entries can apply only to the relevant hostname.
func Evaluate(ip, userAgent, asn, domain string) BlockDecision {
	if d := evaluateOne(globalBlock.Load(), ip, userAgent, asn); d.Hit {
		return d
	}
	if v, ok := domainBlocks.Load(domain); ok {
		return evaluateOne(v.(*compiledBlocklist), ip, userAgent, asn)
	}
	return BlockDecision{}
}

func evaluateOne(cb *compiledBlocklist, ip, userAgent, asn string) BlockDecision {
	if cb == nil {
		return BlockDecision{}
	}
	if ip != "" {
		if e, ok := cb.ips[ip]; ok {
			return BlockDecision{Hit: true, Entry: e}
		}
		if parsed := net.ParseIP(ip); parsed != nil {
			for _, row := range cb.cidrs {
				if row.net.Contains(parsed) {
					return BlockDecision{Hit: true, Entry: row.entry}
				}
			}
		}
	}
	if asn != "" {
		if e, ok := cb.asnSet[asn]; ok {
			return BlockDecision{Hit: true, Entry: e}
		}
	}
	if userAgent != "" {
		ualow := strings.ToLower(userAgent)
		for _, s := range cb.uaSubs {
			if strings.Contains(ualow, s.needle) {
				return BlockDecision{Hit: true, Entry: s.entry}
			}
		}
		for _, r := range cb.uaRegex {
			if r.re.MatchString(userAgent) {
				return BlockDecision{Hit: true, Entry: r.entry}
			}
		}
	}
	return BlockDecision{}
}
