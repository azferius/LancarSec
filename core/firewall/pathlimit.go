package firewall

import (
	"regexp"
	"strings"
	"sync"
	"sync/atomic"

	"lancarsec/core/domains"
)

// Compiled path-scoped rate limits. The slice is evaluated in order for each
// request; first match wins. Matching is designed to be allocation-free on
// the hot path: prefix / exact are plain string ops; regex is precompiled;
// glob expands into a segment-match state machine at compile time.
type compiledPathLimit struct {
	method        string // uppercase, empty = any
	matchKind     pathMatchKind
	literal       string // prefix or exact
	re            *regexp.Regexp
	segments      []globSeg // for "path:" glob
	limit         int
	windowSeconds int
	burstBypass   int
	action        string // "block" | "challenge"
	ruleID        string // stable ID used in the window key so paths stay separate
}

type pathMatchKind uint8

const (
	kindPrefix pathMatchKind = iota
	kindExact
	kindRegex
	kindGlob
)

type globSeg struct {
	literal  string
	wildcard bool // true = any single segment
}

var domainPathLimits sync.Map // domain -> []*compiledPathLimit

// RebuildPathLimits is called by config.Apply after a reload. Fresh compiled
// rulesets are published atomically; in-flight requests still holding a
// reference to the old slice keep working against it safely because the
// slice is never mutated after publication.
func RebuildPathLimits(perDomain map[string][]domains.PathRateLimit) {
	domainPathLimits.Range(func(k, _ any) bool { domainPathLimits.Delete(k); return true })
	for dom, entries := range perDomain {
		compiled := make([]*compiledPathLimit, 0, len(entries))
		for i, e := range entries {
			c := compilePathLimit(e, dom, i)
			if c == nil {
				continue
			}
			compiled = append(compiled, c)
		}
		ptr := &atomic.Pointer[[]*compiledPathLimit]{}
		ptr.Store(&compiled)
		domainPathLimits.Store(dom, ptr)
	}
}

func compilePathLimit(e domains.PathRateLimit, domain string, idx int) *compiledPathLimit {
	c := &compiledPathLimit{
		method:        strings.ToUpper(e.Method),
		limit:         e.Limit,
		windowSeconds: e.WindowSeconds,
		burstBypass:   e.BurstBypass,
		action:        e.Action,
		ruleID:        domain + "#" + itoa(idx),
	}
	if c.limit <= 0 {
		return nil
	}
	if c.action == "" {
		c.action = "block"
	}
	switch {
	case strings.HasPrefix(e.Match, "prefix:"):
		c.matchKind = kindPrefix
		c.literal = strings.TrimPrefix(e.Match, "prefix:")
	case strings.HasPrefix(e.Match, "exact:"):
		c.matchKind = kindExact
		c.literal = strings.TrimPrefix(e.Match, "exact:")
	case strings.HasPrefix(e.Match, "regex:"):
		c.matchKind = kindRegex
		re, err := regexp.Compile(strings.TrimPrefix(e.Match, "regex:"))
		if err != nil {
			return nil
		}
		c.re = re
	case strings.HasPrefix(e.Match, "path:"):
		c.matchKind = kindGlob
		c.segments = parseGlob(strings.TrimPrefix(e.Match, "path:"))
	default:
		// Unknown / free-form literal string treated as a prefix match.
		c.matchKind = kindPrefix
		c.literal = e.Match
	}
	return c
}

// parseGlob splits "/api/*/users" into [api, *, users]. Only a single "*"
// wildcard per segment; no "**" recursive glob.
func parseGlob(pattern string) []globSeg {
	parts := strings.Split(strings.Trim(pattern, "/"), "/")
	out := make([]globSeg, len(parts))
	for i, p := range parts {
		if p == "*" {
			out[i] = globSeg{wildcard: true}
		} else {
			out[i] = globSeg{literal: p}
		}
	}
	return out
}

func matchGlob(segments []globSeg, path string) bool {
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) != len(segments) {
		return false
	}
	for i, seg := range segments {
		if seg.wildcard {
			continue
		}
		if parts[i] != seg.literal {
			return false
		}
	}
	return true
}

// PathLimitDecision is what middleware acts on: either an allow (no match,
// fast path) or a hit with the action to take.
type PathLimitDecision struct {
	Hit     bool
	Action  string // "block" | "challenge"
	Reason  string
	RuleID  string
	Current int
	Limit   int
}

// EvaluatePath runs the per-path rate limit for one request against one
// domain. Hot path: O(N) over compiled rules until first match; each rule's
// literal/regex check is O(len(path)) worst case. For a typical 5-10 rules
// config this is well under a microsecond.
func EvaluatePath(domain, method, path, ip string, now int, windowDefault int) PathLimitDecision {
	v, ok := domainPathLimits.Load(domain)
	if !ok {
		return PathLimitDecision{}
	}
	ruleset := v.(*atomic.Pointer[[]*compiledPathLimit]).Load()
	if ruleset == nil {
		return PathLimitDecision{}
	}
	for _, rule := range *ruleset {
		if rule.method != "" && rule.method != method {
			continue
		}
		if !pathMatches(rule, path) {
			continue
		}
		// Match — count the hit against the per-rule sliding window.
		window := rule.windowSeconds
		if window <= 0 {
			window = windowDefault
		}
		key := ip + "|" + rule.ruleID
		// Read current count first (hot path: most requests will not hit
		// the cap and the increment will happen regardless).
		CountersMu.RLock()
		current := SumWindow(WindowAccessIps, key, window, now)
		CountersMu.RUnlock()
		// Bump the bucket. Even over-cap requests get counted so the
		// window stays honest.
		Incr(WindowAccessIps, now-(now%10), key)

		if current+1 > rule.limit+rule.burstBypass {
			return PathLimitDecision{
				Hit:     true,
				Action:  rule.action,
				Reason:  "path rate limit " + itoa(rule.limit) + "/" + itoa(window) + "s exceeded",
				RuleID:  rule.ruleID,
				Current: current + 1,
				Limit:   rule.limit,
			}
		}
		return PathLimitDecision{} // matched but under cap
	}
	return PathLimitDecision{}
}

func pathMatches(c *compiledPathLimit, path string) bool {
	switch c.matchKind {
	case kindExact:
		return path == c.literal
	case kindPrefix:
		return strings.HasPrefix(path, c.literal)
	case kindRegex:
		return c.re.MatchString(path)
	case kindGlob:
		return matchGlob(c.segments, path)
	}
	return false
}

// itoa is a minimal helper to avoid pulling in strconv at the firewall-hot
// path allocation surface.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	pos := len(buf)
	negative := n < 0
	if negative {
		n = -n
	}
	for n > 0 {
		pos--
		buf[pos] = byte('0' + n%10)
		n /= 10
	}
	if negative {
		pos--
		buf[pos] = '-'
	}
	return string(buf[pos:])
}
