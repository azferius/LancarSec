// Package trusted answers one question, on every request: may this socket peer
// be believed when it tells us who the real client is?
//
// # The hole this closes
//
// Before wave 6, core/server/middleware.go read Cf-Connecting-Ip from any peer
// that sent it. A header is client-supplied data. Taking the subject IP from
// one, unconditionally, means the entire identity of a client is whatever the
// client claims, so a single attacker walks through every per-IP defence the
// proxy has:
//
//   - Per-IP ratelimits count a different bucket on every request.
//   - Per-IP and per-fingerprint bans never match the sender.
//   - Challenge tokens are bound to (domain, ip, fingerprint, UA, hour, susLv);
//     control of `ip` lets an attacker mint a clearance for an address that is
//     not theirs, or park abuse under someone else's.
//
// The fix is not to stop reading the header — behind Cloudflare the header is
// the only place the real client IP exists — but to read it only from a peer
// that is known to set it honestly. That set of peers is what this package
// holds.
//
// # Fail closed, in both directions
//
// The allowlist starts EMPTY, and an empty allowlist trusts nobody: IsTrusted
// returns false for every address until Load has run. Fail-open here would be
// catastrophic and silent — every deployment would accept forged identity from
// the internet while looking healthy. Fail-closed is loud instead: behind
// Cloudflare, an unloaded set makes every visitor read as one of ~20 Cloudflare
// addresses, the shared ratelimit bucket saturates within seconds, and the
// operator finds out immediately. An availability failure that announces itself
// beats an authentication failure that does not.
//
// The same reasoning is why the bundled Cloudflare ranges are not installed as
// a default at init. A security decision must not depend on nobody having
// forgotten to wire the call; if the config pipeline does not call Load, the
// answer to "may I believe this peer" should be no, not "yes, if it happens to
// be Cloudflare".
//
// # What trust here does and does not grant
//
// A trusted peer gets to name the subject IP. It gets nothing else. Every
// request, from a trusted peer or not, still runs the full firewall, ratelimit,
// challenge and ban stack against whatever address it ends up with. This
// package is an input filter on identity, not a bypass.
//
// # Cost
//
// IsTrusted is on the hot path and is allocation-free: it reads one atomic
// pointer and linearly scans the prefixes of the address's own family — 15 IPv4
// and 7 IPv6 as bundled — held as pre-masked integers. The worst case is a
// miss, which walks the whole family, and measures 18.7 ns for IPv4 and 14.4 ns
// for IPv6 on an AMD Ryzen 7 5700X, zero allocations, against the 429 ns/op
// whole-middleware baseline in core/server/BENCHMARK_BASELINE.md. So the check
// costs about 4% of a request.
//
// A linear scan is the right shape at this size, and the numbers say it stays
// so well past it: the prefixes are contiguous in one cache line's worth of
// memory and each test is an AND and a compare, so a tree or a hash of the
// leading octet would trade a handful of branch-predictable compares for a
// pointer chase and a likely cache miss. That was measured rather than assumed
// — the comparison against the obvious stdlib implementation is on the `set`
// type below, and the benchmarks that produced it are in this package.
package trusted

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"sync/atomic"

	trustedips "github.com/azferius/lancarsec/global/trusted"
)

// set is one published allowlist, split by address family so a lookup never
// walks prefixes it cannot possibly match.
//
// A set is immutable once stored. Load builds a new one and swaps it, so a
// reload can never be observed half-applied by a request in flight.
//
// # Why the prefixes are not netip.Prefix here
//
// Parsing and validation use netip.Prefix, which is the right tool for them.
// The lookup does not, because netip.Prefix.Contains is far more general than
// this scan needs: it re-derives the address family, checks validity and checks
// for a zone on every call, over data that was normalised once at load and
// cannot have changed since.
//
// Measured over the bundled 15 IPv4 + 7 IPv6 prefixes, mean of 5 runs on an AMD
// Ryzen 7 5700X, go1.25.14 windows/amd64, ns/op, zero allocations either way.
// The reference column is the obvious implementation — one flat slice, a family
// guard, netip.Prefix.Contains — and is kept as the Benchmark*Netip* functions
// so the claim can be re-measured rather than believed:
//
//	                          netip.Prefix.Contains   masked ints   speedup
//	IPv4 hit, 2nd of 15                19.6               7.7        2.6x
//	IPv4 hit, 12th of 15               85.6              15.5        5.5x
//	IPv4 miss, all 15 tested          114.6              18.7        6.1x
//	IPv6 hit, 2nd of 7                 32.3              10.6        3.1x
//	IPv6 miss, all 7 tested            72.5              14.4        5.0x
//
// The miss is the number that matters, because it is what every request from a
// client that is not behind the trusted proxy pays, and under the direct-to-origin
// attack this proxy exists to survive that is all of them. Splitting the netip
// version by family first — a fairer, less naive reference — brings its IPv4
// miss to 82 ns; the masked scan is still 4.4x faster than that, and 4% rather
// than 19% of a whole request.
//
// Reducing a test to `v&mask == net` also removed the reason to order the
// prefixes. With Contains, a hit on the 12th range cost 4.4x a hit on the 2nd,
// so sorting widest-first bought something real. At 15 ns versus 8 ns it no
// longer does, so the set keeps load order and there is one less invariant to
// maintain.
//
// What this costs is hand-rolled bit arithmetic, in which an off-by-one silently
// grants trust to a neighbour's address space — an operator who allowlists their
// load balancer's /24 would hand the next /24 the right to forge client identity,
// and nothing would look wrong. That is paid for by TestMaskedScanAgreesWithNetip,
// which cross-checks both edges of every prefix and their neighbours, plus a
// 200k-address pseudo-random sweep, against netip.Prefix.Contains. Mutating the
// IPv4 mask by one bit, the IPv6 /64 word boundary by one bit, and the zero-bit
// guard in build were each verified to fail it.
type set struct {
	v4 []prefix4
	v6 []prefix6
}

// prefix4 is one IPv4 CIDR as a pre-masked network and its mask.
type prefix4 struct {
	net  uint32
	mask uint32
}

func (p prefix4) contains(v uint32) bool { return v&p.mask == p.net }

// prefix6 is one IPv6 CIDR as a pre-masked 128-bit network and its mask, each
// held as a high and a low uint64.
type prefix6 struct {
	netHi, netLo   uint64
	maskHi, maskLo uint64
}

func (p prefix6) contains(hi, lo uint64) bool {
	return hi&p.maskHi == p.netHi && lo&p.maskLo == p.netLo
}

// current is the published allowlist. Read on every request, written by Load.
//
// Its zero value — nil, no set published — is the pre-Load state, and it denies
// everyone. That is deliberately not `bundled`: see the package doc, trust must
// be an act rather than a default. Leaving it as the zero value also keeps the
// package free of any initialisation order to get wrong.
var current atomic.Pointer[set]

// bundled is everything compiled into the binary: Cloudflare's two published
// lists plus global/trusted/extra.txt. Parsed once, here, so that a corrupt or
// swapped data file stops the process at startup rather than quietly producing
// a shorter allowlist at request time. That mirrors global/fingerprints, and
// for the same reason: this is build-time data, so a defect in it is a build
// defect, not a runtime condition to be recovered from.
var bundled = mustParseBundled()

// IsTrusted reports whether addr is inside a configured trusted-proxy range.
//
// It is false for every address until Load has been called, false for an
// invalid address, and false for the unspecified address (0.0.0.0 / ::), which
// is never a real socket peer and must not be allowed to match a wide operator
// prefix.
//
// Two normalisations happen first. Both are things netip gets wrong for this
// purpose if you skip them, and both were verified against netip rather than
// assumed — see TestIPv4MappedMatchesIPv4Prefix and TestZoneIsStrippedBeforeMatching,
// which fail if a future Go release changes either:
//
//   - An IPv6 zone is stripped. netip.Prefix.Contains rejects any zoned address
//     outright, whatever the prefix, so a link-local peer arriving as
//     fe80::1%eth0 would never match fe80::/10. A zone names a local interface;
//     it is not part of the peer's identity.
//   - An IPv4-mapped address is unmapped. Contains compares bit lengths, so
//     ::ffff:104.16.0.1 (128 bits) does not match 104.16.0.0/13 (32 bits) even
//     though they are the same host. A dual-stack listener hands out exactly
//     that form, so without the unmap the entire IPv4 allowlist would be dead
//     on any deployment with an IPv6 socket — Cloudflare's whole IPv4 edge
//     would read as untrusted and every visitor's real IP would be lost.
//
// Loopback, link-local and private addresses are NOT special-cased. They are
// not in the bundled ranges, so they are untrusted by default, but an operator
// who lists 127.0.0.1/32 — the right thing to do when a local nginx or Caddy
// terminates TLS in front — gets exactly what they asked for.
func IsTrusted(addr netip.Addr) bool {
	if !addr.IsValid() {
		return false
	}
	addr = addr.WithZone("").Unmap()
	if addr.IsUnspecified() {
		return false
	}

	s := current.Load()
	if s == nil {
		return false // Load has not run: the allowlist is empty, so nobody is trusted.
	}

	if addr.Is4() {
		b := addr.As4()
		v := binary.BigEndian.Uint32(b[:])
		for _, p := range s.v4 {
			if p.contains(v) {
				return true
			}
		}
		return false
	}

	b := addr.As16()
	hi := binary.BigEndian.Uint64(b[:8])
	lo := binary.BigEndian.Uint64(b[8:])
	for _, p := range s.v6 {
		if p.contains(hi, lo) {
			return true
		}
	}
	return false
}

// Load replaces the trusted set. Called once from the config pipeline.
// Returns the number of prefixes loaded.
//
// The result is always the bundled ranges plus extra, which carries the
// operator's list from config.json. Each entry is a CIDR prefix ("203.0.113.0/24",
// "2001:db8::/32") or a bare address taken as a single host. Load is a full
// replace, not an accumulate, so calling it again on a config reload converges
// on the file rather than growing without bound.
//
// Nothing is published unless everything parses. On error the previously
// published set is left exactly as it was and the returned count is zero, so a
// bad reload degrades to "keep enforcing the policy that was already working"
// instead of to "trust nobody" or, worse, "trust a half-applied list".
//
// The count is of the effective set after duplicates are removed, so it can be
// lower than len(bundled)+len(extra) when an operator re-lists a range that is
// already bundled.
//
// Load is safe to call concurrently with IsTrusted. It is not safe to call
// concurrently with itself; the config pipeline is the single caller.
func Load(extra []string) (int, error) {
	all := make([]netip.Prefix, 0, len(bundled)+len(extra))
	all = append(all, bundled...)

	for i, entry := range extra {
		p, err := parseEntry(strings.TrimSpace(entry))
		if err != nil {
			return 0, fmt.Errorf("trusted proxy entry %d: %w", i+1, err)
		}
		all = append(all, p)
	}

	s := build(all)
	current.Store(s)
	return len(s.v4) + len(s.v6), nil
}

// build turns a flat list of validated prefixes into the immutable set that
// IsTrusted scans: duplicates dropped, split by family, each converted to a
// pre-masked network and mask. Load order is preserved.
func build(all []netip.Prefix) *set {
	s := &set{}
	seen := make(map[netip.Prefix]struct{}, len(all))
	for _, p := range all {
		// A zero-bit prefix must never reach the masks below: `^uint64(0) << 64`
		// is defined as 0 in Go, so it would produce an all-zero mask, and an
		// all-zero mask matches every address on the internet. parseEntry already
		// rejects /0, and this is the second lock on that door.
		if !p.IsValid() || p.Bits() <= 0 {
			continue
		}
		if _, dup := seen[p]; dup {
			continue
		}
		seen[p] = struct{}{}

		if p.Addr().Is4() {
			b := p.Addr().As4()
			mask := ^uint32(0) << (32 - p.Bits())
			s.v4 = append(s.v4, prefix4{
				net:  binary.BigEndian.Uint32(b[:]) & mask,
				mask: mask,
			})
			continue
		}

		b := p.Addr().As16()
		var maskHi, maskLo uint64
		if bits := p.Bits(); bits <= 64 {
			maskHi = ^uint64(0) << (64 - bits)
		} else {
			maskHi = ^uint64(0)
			maskLo = ^uint64(0) << (128 - bits)
		}
		s.v6 = append(s.v6, prefix6{
			netHi:  binary.BigEndian.Uint64(b[:8]) & maskHi,
			netLo:  binary.BigEndian.Uint64(b[8:]) & maskLo,
			maskHi: maskHi,
			maskLo: maskLo,
		})
	}
	return s
}

// parseEntry validates and normalises one allowlist entry.
//
// Normalisation is what makes the hot path cheap and correct: every prefix that
// reaches build is masked, is in its canonical family, and has a non-zero
// length, so build can reduce it to two integers and IsTrusted can do nothing
// but compare them.
func parseEntry(entry string) (netip.Prefix, error) {
	if entry == "" {
		return netip.Prefix{}, errors.New("is empty; remove the entry rather than leaving a blank one")
	}

	var p netip.Prefix
	if strings.ContainsRune(entry, '/') {
		var err error
		if p, err = netip.ParsePrefix(entry); err != nil {
			return netip.Prefix{}, fmt.Errorf("%q is not a CIDR prefix: %w", entry, err)
		}
	} else {
		addr, err := netip.ParseAddr(entry)
		if err != nil {
			return netip.Prefix{}, fmt.Errorf("%q is neither an IP address nor a CIDR prefix: %w", entry, err)
		}
		if addr.Zone() != "" {
			return netip.Prefix{}, fmt.Errorf("%q carries an IPv6 zone; a zone names a local "+
				"interface, not a peer, and cannot be part of an allowlist", entry)
		}
		// A bare address is the single host it names.
		addr = addr.Unmap()
		p = netip.PrefixFrom(addr, addr.BitLen())
	}

	// An IPv4-mapped prefix is rewritten to its IPv4 form, because IsTrusted
	// unmaps before it scans and would otherwise never reach this entry.
	if p.Addr().Is4In6() {
		if p.Bits() < 96 {
			return netip.Prefix{}, fmt.Errorf("%q is an IPv4-mapped prefix shorter than /96, so it "+
				"spans real IPv6 space as well as the mapped IPv4 range; write it as an IPv4 CIDR "+
				"or as a plain IPv6 CIDR, whichever you meant", entry)
		}
		p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96)
	}

	if p.Bits() == 0 {
		return netip.Prefix{}, fmt.Errorf("%q is a default route: it would let any peer on the "+
			"internet claim to be any client, which is the exact hole this allowlist exists to "+
			"close. List the proxy's actual ranges instead", entry)
	}

	return p.Masked(), nil
}

// parseList parses one embedded data file: one entry per line, blank lines
// ignored, '#' starting a comment either at the start of a line or after an
// entry.
func parseList(name, body string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for i, raw := range strings.Split(body, "\n") {
		line := raw
		if hash := strings.IndexByte(line, '#'); hash >= 0 {
			line = line[:hash]
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		p, err := parseEntry(line)
		if err != nil {
			return nil, fmt.Errorf("%s line %d: %w", name, i+1, err)
		}
		out = append(out, p)
	}
	return out, nil
}

// parseBundled parses the three compiled-in files and returns their union.
//
// The checks here are about the failures that would leave a plausible-looking
// but wrong allowlist: an empty Cloudflare list (a truncated fetch during a
// refresh, which would silently drop the ranges the whole deployment depends
// on) and a file holding the wrong address family (the two curl commands in the
// README swapped, which would produce a working build with an IPv4 allowlist
// containing no IPv4).
func parseBundled() ([]netip.Prefix, error) {
	cf4, err := parseVendorList("global/trusted/cloudflare_ipv4.txt", trustedips.CloudflareIPv4(), true)
	if err != nil {
		return nil, err
	}

	cf6, err := parseVendorList("global/trusted/cloudflare_ipv6.txt", trustedips.CloudflareIPv6(), false)
	if err != nil {
		return nil, err
	}

	site, err := parseList("global/trusted/extra.txt", trustedips.Extra())
	if err != nil {
		return nil, err
	}

	out := make([]netip.Prefix, 0, len(cf4)+len(cf6)+len(site))
	out = append(out, cf4...)
	out = append(out, cf6...)
	out = append(out, site...)
	return out, nil
}

// parseVendorList parses one of the two Cloudflare files and rejects the two
// ways a refresh goes wrong without looking wrong.
//
// An empty list is a truncated download: the build succeeds, the allowlist is
// quietly short by a whole address family, and the deployment loses the real
// client IP for every visitor arriving over it. A list holding the other family
// is the two curl commands in the README swapped, which produces an "IPv4"
// allowlist containing no IPv4 — same outcome, even less obvious.
//
// Both are build defects, so both stop the process at init rather than
// degrading at request time.
func parseVendorList(name, body string, wantV4 bool) ([]netip.Prefix, error) {
	out, err := parseList(name, body)
	if err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%s holds no prefixes; a truncated refresh would silently strip "+
			"every range in it from the allowlist", name)
	}
	for _, p := range out {
		if p.Addr().Is4() != wantV4 {
			family, other := "IPv4", "IPv6"
			if !wantV4 {
				family, other = "IPv6", "IPv4"
			}
			return nil, fmt.Errorf("%s is the %s list but holds the %s prefix %s; the two "+
				"Cloudflare files look swapped", name, family, other, p)
		}
	}
	return out, nil
}

func mustParseBundled() []netip.Prefix {
	out, err := parseBundled()
	if err != nil {
		panic("trusted: bundled data is unusable: " + err.Error())
	}
	return out
}
