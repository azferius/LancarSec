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
	// TLS / HTTP fingerprint deny sets. Exact-match maps for O(1) lookup;
	// case-insensitive on the wire because intel feeds publish them in
	// mixed cases. Empty maps cost almost nothing for domains that don't
	// use them.
	tlsFP map[string]domains.BlockEntry // legacy hex-list fingerprint
	ja3   map[string]domains.BlockEntry
	ja4   map[string]domains.BlockEntry
	ja4r  map[string]domains.BlockEntry
	ja4o  map[string]domains.BlockEntry
	ja4h  map[string]domains.BlockEntry
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
		tlsFP:  map[string]domains.BlockEntry{},
		ja3:    map[string]domains.BlockEntry{},
		ja4:    map[string]domains.BlockEntry{},
		ja4r:   map[string]domains.BlockEntry{},
		ja4o:   map[string]domains.BlockEntry{},
		ja4h:   map[string]domains.BlockEntry{},
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
		case "tls_fp":
			v := strings.TrimSpace(e.Value)
			if v == "" {
				continue
			}
			cb.tlsFP[v] = e
		case "ja3":
			v := strings.ToLower(strings.TrimSpace(e.Value))
			if v == "" {
				continue
			}
			cb.ja3[v] = e
		case "ja4":
			v := strings.TrimSpace(e.Value)
			if v == "" {
				continue
			}
			cb.ja4[v] = e
		case "ja4_r":
			v := strings.TrimSpace(e.Value)
			if v == "" {
				continue
			}
			cb.ja4r[v] = e
		case "ja4_o":
			v := strings.TrimSpace(e.Value)
			if v == "" {
				continue
			}
			cb.ja4o[v] = e
		case "ja4h":
			v := strings.TrimSpace(e.Value)
			if v == "" {
				continue
			}
			cb.ja4h[v] = e
		}
	}
	return cb
}

// EvalContext bundles the per-request signals the blocklist evaluates.
// Zero-valued fields are skipped — passing only the IP gives the legacy
// behaviour. New code should populate the fingerprint fields so JA3 / JA4
// / JA4H entries can fire.
type EvalContext struct {
	IP        string
	UserAgent string
	ASN       string
	Domain    string

	TLSFP string // legacy hex-list fingerprint
	JA3   string
	JA4   string
	JA4R  string
	JA4O  string
	JA4H  string
}

// Evaluate runs the full blocklist check for one request: IP first (cheapest),
// then CIDR, then ASN, UA patterns, then TLS / HTTP fingerprints. Returns the
// first hit or a no-hit zero value. Checks both the global list and the
// per-domain list — global is checked first so a wildcard ban applies even
// to domains without their own list.
func Evaluate(ctx EvalContext) BlockDecision {
	if d := evaluateOne(globalBlock.Load(), ctx); d.Hit {
		return d
	}
	if v, ok := domainBlocks.Load(ctx.Domain); ok {
		return evaluateOne(v.(*compiledBlocklist), ctx)
	}
	return BlockDecision{}
}

func evaluateOne(cb *compiledBlocklist, ctx EvalContext) BlockDecision {
	if cb == nil {
		return BlockDecision{}
	}
	if ctx.IP != "" {
		if e, ok := cb.ips[ctx.IP]; ok {
			return BlockDecision{Hit: true, Entry: e}
		}
		if parsed := net.ParseIP(ctx.IP); parsed != nil {
			for _, row := range cb.cidrs {
				if row.net.Contains(parsed) {
					return BlockDecision{Hit: true, Entry: row.entry}
				}
			}
		}
	}
	if ctx.ASN != "" {
		if e, ok := cb.asnSet[ctx.ASN]; ok {
			return BlockDecision{Hit: true, Entry: e}
		}
	}
	if ctx.UserAgent != "" {
		ualow := strings.ToLower(ctx.UserAgent)
		for _, s := range cb.uaSubs {
			if strings.Contains(ualow, s.needle) {
				return BlockDecision{Hit: true, Entry: s.entry}
			}
		}
		for _, r := range cb.uaRegex {
			if r.re.MatchString(ctx.UserAgent) {
				return BlockDecision{Hit: true, Entry: r.entry}
			}
		}
	}
	if ctx.TLSFP != "" {
		if e, ok := cb.tlsFP[ctx.TLSFP]; ok {
			return BlockDecision{Hit: true, Entry: e}
		}
	}
	if ctx.JA3 != "" {
		if e, ok := cb.ja3[strings.ToLower(ctx.JA3)]; ok {
			return BlockDecision{Hit: true, Entry: e}
		}
	}
	if ctx.JA4 != "" {
		if e, ok := cb.ja4[ctx.JA4]; ok {
			return BlockDecision{Hit: true, Entry: e}
		}
	}
	if ctx.JA4R != "" {
		if e, ok := cb.ja4r[ctx.JA4R]; ok {
			return BlockDecision{Hit: true, Entry: e}
		}
	}
	if ctx.JA4O != "" {
		if e, ok := cb.ja4o[ctx.JA4O]; ok {
			return BlockDecision{Hit: true, Entry: e}
		}
	}
	if ctx.JA4H != "" {
		if e, ok := cb.ja4h[ctx.JA4H]; ok {
			return BlockDecision{Hit: true, Entry: e}
		}
	}
	return BlockDecision{}
}
