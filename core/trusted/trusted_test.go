package trusted

import (
	"net/netip"
	"strings"
	"sync"
	"testing"

	trustedips "github.com/azferius/lancarsec/global/trusted"
)

// The tests share the package-level `current` pointer, so every one of them
// that calls Load restores the pre-Load state on the way out. reset also gives
// a test the empty-allowlist state explicitly, which is the state the package
// is in before the config pipeline runs.
func reset(t *testing.T) {
	t.Helper()
	prev := current.Load()
	current.Store(nil)
	t.Cleanup(func() { current.Store(prev) })
}

func mustLoad(t *testing.T, extra ...string) int {
	t.Helper()
	n, err := Load(extra)
	if err != nil {
		t.Fatalf("Load(%q) returned error: %v", extra, err)
	}
	return n
}

// Addresses used throughout. The Cloudflare ones are inside ranges that appear
// in the bundled files; if a refresh ever drops one of those ranges these tests
// fail, which is the point — a refresh that shrinks the allowlist should not be
// silent.
const (
	cfV4      = "104.16.0.1"     // inside 104.16.0.0/13
	cfV4Last  = "104.23.255.255" // last address of 104.16.0.0/13
	cfV4Next  = "104.24.0.0"     // first address past it, but inside 104.24.0.0/14
	cfV6      = "2606:4700::1"   // inside 2606:4700::/32
	cfV6Last  = "2606:4700:ffff:ffff:ffff:ffff:ffff:ffff"
	cfV6Next  = "2606:4701::1" // first address past 2606:4700::/32
	outsideV4 = "198.51.100.7" // TEST-NET-2, never routable to Cloudflare
	outsideV6 = "2001:db8::1"  // documentation range
)

func addr(t *testing.T, s string) netip.Addr {
	t.Helper()
	a, err := netip.ParseAddr(s)
	if err != nil {
		t.Fatalf("test fixture %q is not an address: %v", s, err)
	}
	return a
}

// --- the empty set -------------------------------------------------------

// TestEmptySetTrustsNobody pins the single most important property of this
// package. Before Load runs there is no allowlist, and no allowlist must mean
// no trust. A fail-open default here would let any peer on the internet forge
// Cf-Connecting-Ip and walk past every per-IP ratelimit, ban and token binding
// in the proxy, on every deployment that forgot to wire the call.
func TestEmptySetTrustsNobody(t *testing.T) {
	reset(t)

	for _, s := range []string{cfV4, cfV6, outsideV4, outsideV6, "127.0.0.1", "::1"} {
		if IsTrusted(addr(t, s)) {
			t.Errorf("IsTrusted(%s) = true with no allowlist loaded; the empty set must trust nobody", s)
		}
	}
}

// TestEmptySetIsNotTheBundledSet pins that the bundled Cloudflare ranges are
// not silently installed as a default. Trust has to be an act. If this ever
// starts failing because someone made `bundled` the initial value, the question
// to answer is not "is Cloudflare safe to trust" but "should a security
// decision apply when nobody asked for it".
func TestEmptySetIsNotTheBundledSet(t *testing.T) {
	reset(t)

	if len(bundled) == 0 {
		t.Fatal("bundled is empty; the embedded data files did not parse")
	}
	if IsTrusted(addr(t, cfV4)) {
		t.Error("a Cloudflare address is trusted before Load; the bundled set leaked into the default")
	}
}

// --- the bundled Cloudflare data ----------------------------------------

func TestLoadDefaultsToTheBundledRanges(t *testing.T) {
	reset(t)

	n := mustLoad(t)
	if n != len(bundled) {
		t.Errorf("Load(nil) = %d prefixes, want %d (the bundled set holds no duplicates)", n, len(bundled))
	}
	// 15 IPv4 + 7 IPv6 as fetched on 2026-08-31. A refresh may legitimately
	// change this; the assertion exists so that it changes visibly.
	if n < 20 {
		t.Errorf("Load(nil) = %d prefixes, which is fewer than the Cloudflare lists have ever "+
			"published; check global/trusted/*.txt for a truncated refresh", n)
	}
}

func TestRealCloudflareIPv4IsTrusted(t *testing.T) {
	reset(t)
	mustLoad(t)

	if !IsTrusted(addr(t, cfV4)) {
		t.Errorf("IsTrusted(%s) = false; that address is inside Cloudflare's published 104.16.0.0/13", cfV4)
	}
}

func TestRealCloudflareIPv6IsTrusted(t *testing.T) {
	reset(t)
	mustLoad(t)

	if !IsTrusted(addr(t, cfV6)) {
		t.Errorf("IsTrusted(%s) = false; that address is inside Cloudflare's published 2606:4700::/32", cfV6)
	}
}

func TestNonCloudflareAddressesAreNotTrusted(t *testing.T) {
	reset(t)
	mustLoad(t)

	for _, s := range []string{outsideV4, outsideV6, "8.8.8.8", "2001:4860:4860::8888"} {
		if IsTrusted(addr(t, s)) {
			t.Errorf("IsTrusted(%s) = true; only the configured proxy ranges may be trusted", s)
		}
	}
}

// --- boundaries ----------------------------------------------------------

// TestRangeBoundaries walks the edges of a bundled prefix. An off-by-one in the
// prefix maths is the kind of defect that grants trust to a neighbour's address
// space, so both the last address inside a range and the first outside it are
// pinned. 104.24.0.0 is deliberately covered by a *different* Cloudflare range
// (104.24.0.0/14), so the "outside" case uses an address past both.
func TestRangeBoundaries(t *testing.T) {
	reset(t)
	mustLoad(t)

	if !IsTrusted(addr(t, cfV4Last)) {
		t.Errorf("IsTrusted(%s) = false; it is the last address of 104.16.0.0/13", cfV4Last)
	}
	if !IsTrusted(addr(t, cfV4Next)) {
		t.Errorf("IsTrusted(%s) = false; it is the first address of 104.16.0.0/13's neighbour "+
			"104.24.0.0/14, which Cloudflare also publishes", cfV4Next)
	}
	// 104.28.0.0/14 ends at 104.27.255.255; 104.28.0.0 is past every bundled
	// 104.x range.
	if IsTrusted(addr(t, "104.28.0.0")) {
		t.Error("IsTrusted(104.28.0.0) = true; that is past the end of every bundled 104.x range")
	}

	if !IsTrusted(addr(t, cfV6Last)) {
		t.Errorf("IsTrusted(%s) = false; it is the last address of 2606:4700::/32", cfV6Last)
	}
	if IsTrusted(addr(t, cfV6Next)) {
		t.Errorf("IsTrusted(%s) = true; it is the first address past 2606:4700::/32", cfV6Next)
	}
}

// TestBoundaryOfAnOperatorPrefix uses a range with no neighbours so both edges
// are unambiguous, which the bundled Cloudflare ranges cannot give us.
func TestBoundaryOfAnOperatorPrefix(t *testing.T) {
	reset(t)
	mustLoad(t, "198.51.100.0/24", "2001:db8:1::/48")

	cases := []struct {
		ip   string
		want bool
	}{
		{"198.51.99.255", false},
		{"198.51.100.0", true},
		{"198.51.100.255", true},
		{"198.51.101.0", false},
		{"2001:db8:0:ffff:ffff:ffff:ffff:ffff", false},
		{"2001:db8:1::", true},
		{"2001:db8:1:ffff:ffff:ffff:ffff:ffff", true},
		{"2001:db8:2::", false},
	}
	for _, c := range cases {
		if got := IsTrusted(addr(t, c.ip)); got != c.want {
			t.Errorf("IsTrusted(%s) = %v, want %v", c.ip, got, c.want)
		}
	}
}

// --- IPv4-mapped IPv6 ----------------------------------------------------

// TestIPv4MappedMatchesIPv4Prefix is the correctness detail netip does not hand
// you. netip.Prefix.Contains compares bit lengths, so ::ffff:104.16.0.1 (128
// bits) does not match 104.16.0.0/13 (32 bits) even though they name the same
// host. A dual-stack listener hands out exactly that form, so without the unmap
// in IsTrusted the whole IPv4 allowlist would be dead on any deployment with an
// IPv6 socket — Cloudflare's IPv4 edge would read as untrusted and every
// visitor's real IP would be lost.
func TestIPv4MappedMatchesIPv4Prefix(t *testing.T) {
	reset(t)
	mustLoad(t)

	mapped := addr(t, "::ffff:"+cfV4)
	if !mapped.Is4In6() {
		t.Fatalf("fixture %s is not IPv4-mapped; the test is not testing what it says", mapped)
	}

	// Pin the netip behaviour this code exists to compensate for, so that if a
	// future Go release starts matching across families the workaround can be
	// retired knowingly rather than left as cargo.
	if netip.MustParsePrefix("104.16.0.0/13").Contains(mapped) {
		t.Error("netip.Prefix.Contains now matches an IPv4-mapped address against an IPv4 prefix; " +
			"the Unmap in IsTrusted may no longer be needed")
	}

	if !IsTrusted(mapped) {
		t.Errorf("IsTrusted(%s) = false; it is the same host as %s, which is trusted", mapped, cfV4)
	}
}

func TestIPv4MappedOutsideRangeIsNotTrusted(t *testing.T) {
	reset(t)
	mustLoad(t)

	if IsTrusted(addr(t, "::ffff:"+outsideV4)) {
		t.Errorf("IsTrusted(::ffff:%s) = true; unmapping must not widen what matches", outsideV4)
	}
}

// TestIPv4MappedPrefixInExtrasIsRewritten covers the mirror image: an operator
// who writes the mapped form as a *prefix*. Stored as-is it could never match,
// because IsTrusted unmaps before scanning, so it would be a silently dead
// allowlist entry — the worst kind, since the operator believes it is in force.
func TestIPv4MappedPrefixInExtrasIsRewritten(t *testing.T) {
	reset(t)
	mustLoad(t, "::ffff:198.51.100.0/120")

	if !IsTrusted(addr(t, "198.51.100.7")) {
		t.Error("::ffff:198.51.100.0/120 did not become 198.51.100.0/24; the entry is dead weight")
	}
	if !IsTrusted(addr(t, "::ffff:198.51.100.7")) {
		t.Error("the mapped form of an address in the entry's own range is not trusted")
	}
	if IsTrusted(addr(t, "198.51.101.1")) {
		t.Error("the rewritten prefix is wider than /24")
	}
}

func TestIPv4MappedPrefixShorterThanSlash96IsRejected(t *testing.T) {
	reset(t)

	if _, err := Load([]string{"::ffff:0.0.0.0/64"}); err == nil {
		t.Fatal("Load accepted ::ffff:0.0.0.0/64; a mapped prefix shorter than /96 spans real " +
			"IPv6 space too and its meaning is ambiguous")
	} else if !strings.Contains(err.Error(), "/96") {
		t.Errorf("error does not explain the /96 rule: %v", err)
	}
}

// --- invalid input -------------------------------------------------------

// TestInvalidAddressIsNotTrusted pins the zero netip.Addr, which is what a
// caller gets from a failed netip.ParseAddr. Middleware that ignores the parse
// error must not accidentally hand an attacker trust.
func TestInvalidAddressIsNotTrusted(t *testing.T) {
	reset(t)
	mustLoad(t, "0.0.0.0/1", "128.0.0.0/1", "::/1", "8000::/1") // half the internet, twice over

	var zero netip.Addr
	if zero.IsValid() {
		t.Fatal("the zero netip.Addr reports valid; fixture assumption broken")
	}
	if IsTrusted(zero) {
		t.Error("IsTrusted(invalid addr) = true even against near-total coverage; an unparsed " +
			"address must never be trusted")
	}
}

// TestUnspecifiedAddressIsNotTrusted pins 0.0.0.0 and ::, in both plain and
// mapped form. They are never a real socket peer — they are what an uninitialised
// or failed lookup produces — so they must not be able to fall into a wide
// operator prefix.
func TestUnspecifiedAddressIsNotTrusted(t *testing.T) {
	reset(t)
	mustLoad(t, "0.0.0.0/1", "::/1")

	for _, s := range []string{"0.0.0.0", "::", "::ffff:0.0.0.0"} {
		if IsTrusted(addr(t, s)) {
			t.Errorf("IsTrusted(%s) = true; the unspecified address is not a peer", s)
		}
	}
}

func TestUnparseableExtrasAreRejected(t *testing.T) {
	reset(t)

	cases := []struct {
		entry string
		want  string // substring the message must carry
	}{
		{"", "is empty"},
		{"   ", "is empty"},
		{"not-an-ip", "neither an IP address nor a CIDR"},
		{"104.16.0.0/99", "not a CIDR prefix"},
		{"104.16.0.256", "neither an IP address nor a CIDR"},
		{"104.16.0.0-104.16.0.9", "neither an IP address nor a CIDR"},
		{"2001:db8::/129", "not a CIDR prefix"},
		{"fe80::1%eth0", "zone"},
		// '#' introduces a comment in the embedded data files, but a config
		// entry is one value, not a line of a file, so it stays a syntax error.
		{"203.0.113.0/24 # office", "not a CIDR prefix"},
		{"203.0.113.7 # office", "neither an IP address nor a CIDR"},
	}
	for _, c := range cases {
		_, err := Load([]string{c.entry})
		if err == nil {
			t.Errorf("Load([%q]) succeeded; it is not a valid allowlist entry", c.entry)
			continue
		}
		if !strings.Contains(err.Error(), c.want) {
			t.Errorf("Load([%q]) error = %q, want it to mention %q", c.entry, err, c.want)
		}
	}
}

// TestDefaultRouteIsRejected pins the refusal to accept 0.0.0.0/0 or ::/0. A
// default route is not an allowlist, it is the absence of one, and configuring
// it reinstates the exact header-spoofing hole this package closes. The
// operator who genuinely wants it can say so range by range.
func TestDefaultRouteIsRejected(t *testing.T) {
	reset(t)

	for _, entry := range []string{"0.0.0.0/0", "::/0", "::ffff:0.0.0.0/96"} {
		_, err := Load([]string{entry})
		if err == nil {
			t.Errorf("Load([%q]) succeeded; a default route trusts every peer on the internet", entry)
			continue
		}
		if !strings.Contains(err.Error(), "default route") {
			t.Errorf("Load([%q]) error = %q, want it to name the default route", entry, err)
		}
	}
}

// TestFailedLoadLeavesThePreviousSetInPlace pins the wave-4 rule that nothing
// is published unless everything validates. A config reload with one typo must
// not drop the allowlist that was already working — that would turn a typo into
// either an outage or, if the code had been written to keep partial results, a
// half-applied trust policy.
func TestFailedLoadLeavesThePreviousSetInPlace(t *testing.T) {
	reset(t)
	mustLoad(t, "198.51.100.0/24")

	n, err := Load([]string{"198.51.100.0/24", "definitely not an ip"})
	if err == nil {
		t.Fatal("Load accepted an invalid entry")
	}
	if n != 0 {
		t.Errorf("failed Load returned count %d, want 0", n)
	}
	if !strings.Contains(err.Error(), "entry 2") {
		t.Errorf("error %q does not identify which entry failed", err)
	}
	if !IsTrusted(addr(t, "198.51.100.7")) {
		t.Error("the previously published allowlist was dropped by a failed Load")
	}
}

// --- operator extras -----------------------------------------------------

func TestOperatorExtrasAreTrusted(t *testing.T) {
	reset(t)
	mustLoad(t, "198.51.100.0/24", "2001:db8::/32", "203.0.113.9", "2001:db8:cafe::9")

	for _, s := range []string{"198.51.100.1", "2001:db8::5", "203.0.113.9", "2001:db8:cafe::9"} {
		if !IsTrusted(addr(t, s)) {
			t.Errorf("IsTrusted(%s) = false; it is covered by an operator entry", s)
		}
	}
	// A bare address is one host, not its whole subnet.
	if IsTrusted(addr(t, "203.0.113.10")) {
		t.Error("IsTrusted(203.0.113.10) = true; the bare entry 203.0.113.9 is a /32, not a subnet")
	}
}

func TestExtrasDoNotReplaceTheBundledRanges(t *testing.T) {
	reset(t)
	mustLoad(t, "198.51.100.0/24")

	if !IsTrusted(addr(t, cfV4)) {
		t.Error("supplying an operator range dropped the bundled Cloudflare ranges; " +
			"Load merges, it does not substitute")
	}
}

// TestLoadIsAReplaceNotAnAccumulate pins that a reload converges on the config
// rather than growing without bound. An accumulating Load would make a removed
// range impossible to actually remove without a restart.
func TestLoadIsAReplaceNotAnAccumulate(t *testing.T) {
	reset(t)

	first := mustLoad(t, "198.51.100.0/24")
	if !IsTrusted(addr(t, "198.51.100.7")) {
		t.Fatal("first Load did not take effect")
	}

	second := mustLoad(t, "203.0.113.0/24")
	if IsTrusted(addr(t, "198.51.100.7")) {
		t.Error("a range removed from the config is still trusted after reload")
	}
	if !IsTrusted(addr(t, "203.0.113.7")) {
		t.Error("the reloaded range is not trusted")
	}
	if first != second {
		t.Errorf("counts differ across two one-entry loads: %d then %d", first, second)
	}
}

func TestDuplicateEntriesAreCountedOnce(t *testing.T) {
	reset(t)

	base := mustLoad(t)
	// Re-listing a bundled range, plus a duplicate pair among the extras, plus
	// an unmasked spelling of the same network.
	n := mustLoad(t, "104.16.0.0/13", "198.51.100.0/24", "198.51.100.0/24", "198.51.100.77/24")
	if n != base+1 {
		t.Errorf("Load counted %d prefixes, want %d; duplicates must collapse", n, base+1)
	}
}

// TestUnmaskedPrefixIsMasked pins that 198.51.100.77/24 means the /24, matching
// what every other CIDR tool does, rather than being stored unmasked and then
// comparing unequal to the same network written properly.
func TestUnmaskedPrefixIsMasked(t *testing.T) {
	reset(t)
	mustLoad(t, "198.51.100.77/24")

	if !IsTrusted(addr(t, "198.51.100.0")) {
		t.Error("198.51.100.77/24 was not masked to 198.51.100.0/24")
	}
}

// --- addresses the package deliberately does not special-case -------------

// TestLoopbackIsUntrustedByDefaultAndTrustableOnRequest documents the decision.
// Auto-trusting loopback would be convenient for the local-reverse-proxy
// deployment and wrong everywhere else: on a shared host any local process, and
// anything with an SSRF, would inherit the right to forge client identity. So
// loopback gets no special treatment in either direction — untrusted unless the
// operator lists it, fully trusted when they do.
func TestLoopbackIsUntrustedByDefaultAndTrustableOnRequest(t *testing.T) {
	reset(t)
	mustLoad(t)

	for _, s := range []string{"127.0.0.1", "::1", "::ffff:127.0.0.1"} {
		if IsTrusted(addr(t, s)) {
			t.Errorf("IsTrusted(%s) = true with only the bundled ranges loaded", s)
		}
	}

	mustLoad(t, "127.0.0.1/32", "::1/128")
	for _, s := range []string{"127.0.0.1", "::1", "::ffff:127.0.0.1"} {
		if !IsTrusted(addr(t, s)) {
			t.Errorf("IsTrusted(%s) = false after the operator listed loopback explicitly", s)
		}
	}
}

// TestZoneIsStrippedBeforeMatching pins the second netip trap. Prefix.Contains
// returns false for *any* zoned address, whatever the prefix, so a link-local
// peer arriving as fe80::1%eth0 would never match fe80::/10. A zone names a
// local interface; it is not part of the peer's identity.
func TestZoneIsStrippedBeforeMatching(t *testing.T) {
	reset(t)
	mustLoad(t, "fe80::/10")

	zoned := addr(t, "fe80::1").WithZone("eth0")
	if netip.MustParsePrefix("fe80::/10").Contains(zoned) {
		t.Error("netip.Prefix.Contains now matches a zoned address; the WithZone(\"\") in " +
			"IsTrusted may no longer be needed")
	}
	if !IsTrusted(zoned) {
		t.Errorf("IsTrusted(%s) = false; the zone must not change which prefix the address is in", zoned)
	}
	// fe80::/10 runs to febf:ffff:…, so the nearest genuinely outside address
	// is in fec0::/10 — fe81::1 would still be inside and would not test this.
	if IsTrusted(addr(t, "fec0::1").WithZone("eth0")) {
		t.Error("stripping the zone must not widen what matches")
	}
}

// TestPrivateRangesAreNotTrustedByDefault: RFC1918 is not an allowlist either.
// A container network is shared with every other workload on the host.
func TestPrivateRangesAreNotTrustedByDefault(t *testing.T) {
	reset(t)
	mustLoad(t)

	for _, s := range []string{"10.0.0.1", "172.16.0.1", "192.168.1.1", "fd00::1", "169.254.1.1"} {
		if IsTrusted(addr(t, s)) {
			t.Errorf("IsTrusted(%s) = true; private and link-local space is not trusted by default", s)
		}
	}
}

// --- the bundled data itself ---------------------------------------------

// TestBundledDataIsWellFormed re-runs the init-time validation as a test, so a
// bad refresh names its problem in a test failure instead of only in a startup
// panic.
func TestBundledDataIsWellFormed(t *testing.T) {
	if _, err := parseBundled(); err != nil {
		t.Fatalf("bundled data does not parse: %v", err)
	}

	var v4, v6 int
	for _, p := range bundled {
		if p.Addr().Is4() {
			v4++
		} else {
			v6++
		}
		if p != p.Masked() {
			t.Errorf("bundled prefix %s is not masked; parseEntry should have normalised it", p)
		}
		if p.Addr().Is4In6() {
			t.Errorf("bundled prefix %s is still IPv4-mapped; it would never match", p)
		}
		if p.Bits() == 0 {
			t.Errorf("bundled prefix %s is a default route", p)
		}
	}
	if v4 == 0 || v6 == 0 {
		t.Errorf("bundled set has %d IPv4 and %d IPv6 prefixes; both families must be present", v4, v6)
	}
}

// TestBundledExtraFileIsEmptyByDefault pins that global/trusted/extra.txt ships
// with no entries. A range that appears there is compiled into every build, so
// one arriving by accident — a debugging line left behind, a copy-paste — is a
// standing grant of trust that no config review would ever surface.
func TestBundledExtraFileIsEmptyByDefault(t *testing.T) {
	got, err := parseList("extra.txt", trustedips.Extra())
	if err != nil {
		t.Fatalf("extra.txt does not parse: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("global/trusted/extra.txt ships %d prefix(es) (%v); it must be empty by default, "+
			"and anything site-local belongs in config.json", len(got), got)
	}
}

// TestParseListSkipsCommentsAndBlanks covers the file syntax extra.txt
// documents, without depending on extra.txt having any entries.
func TestParseListSkipsCommentsAndBlanks(t *testing.T) {
	body := "" +
		"# a leading comment\n" +
		"\n" +
		"   \n" +
		"198.51.100.0/24\n" +
		"203.0.113.0/24   # trailing comment\n" +
		"\t2001:db8::/32\t\n" +
		"# 192.0.2.0/24 commented out\n" +
		"203.0.113.7\r\n" // CRLF, in case the file is ever edited on Windows

	got, err := parseList("test", body)
	if err != nil {
		t.Fatalf("parseList: %v", err)
	}
	want := []string{"198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32", "203.0.113.7/32"}
	if len(got) != len(want) {
		t.Fatalf("parseList returned %v, want %v", got, want)
	}
	for i := range want {
		if got[i].String() != want[i] {
			t.Errorf("prefix %d = %s, want %s", i, got[i], want[i])
		}
	}
}

// TestVendorListGuards drives the two checks that stand between a bad refresh
// of the Cloudflare files and a proxy that boots with a plausible-looking but
// wrong allowlist. They cannot be exercised through the embedded files without
// corrupting them, so they are tested through the same function the embedded
// files go through.
func TestVendorListGuards(t *testing.T) {
	cases := []struct {
		name   string
		body   string
		wantV4 bool
		want   string // substring the error must carry, "" for success
	}{
		{"good v4", "104.16.0.0/13\n172.64.0.0/13\n", true, ""},
		{"good v6", "2606:4700::/32\n", false, ""},

		// A truncated download. The build would otherwise succeed with a whole
		// address family missing from the allowlist.
		{"empty v4", "", true, "holds no prefixes"},
		{"empty v6", "\n\n", false, "holds no prefixes"},
		{"comments only", "# nothing here\n", true, "holds no prefixes"},

		// The two curl commands swapped.
		{"v6 in the v4 file", "104.16.0.0/13\n2606:4700::/32\n", true, "look swapped"},
		{"v4 in the v6 file", "2606:4700::/32\n104.16.0.0/13\n", false, "look swapped"},

		// A malformed line still reports its position.
		{"bad line", "104.16.0.0/13\nnope\n", true, "line 2"},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := parseVendorList("testfile.txt", c.body, c.wantV4)
			switch {
			case c.want == "" && err != nil:
				t.Errorf("parseVendorList rejected valid data: %v", err)
			case c.want != "" && err == nil:
				t.Errorf("parseVendorList accepted %q; want an error mentioning %q", c.body, c.want)
			case c.want != "" && !strings.Contains(err.Error(), c.want):
				t.Errorf("error = %q, want it to mention %q", err, c.want)
			case err != nil && !strings.Contains(err.Error(), "testfile.txt"):
				t.Errorf("error %q does not name the file", err)
			}
		})
	}
}

func TestParseListReportsTheOffendingLine(t *testing.T) {
	_, err := parseList("somefile.txt", "# header\n198.51.100.0/24\nnonsense\n")
	if err == nil {
		t.Fatal("parseList accepted a broken line")
	}
	if !strings.Contains(err.Error(), "line 3") || !strings.Contains(err.Error(), "somefile.txt") {
		t.Errorf("error %q should name the file and the line", err)
	}
}

// --- the hand-rolled bit arithmetic --------------------------------------

// TestMaskedScanAgreesWithNetip is what pays for storing prefixes as integers
// instead of netip.Prefix. The scan is ~7x faster on its worst case (the
// numbers are on the `set` type), and the price is masking code where a single
// off-by-one silently grants trust to a neighbour's address space — an operator
// who allowlists their load balancer's /24 would hand the next /24 the right to
// forge client identity, and nothing would look wrong.
//
// So every prefix in the set is checked against netip.Prefix.Contains, the
// stdlib implementation this replaced, at the addresses where masking goes
// wrong: the network address, the last address in the range, and the addresses
// immediately either side of both. Then a deterministic pseudo-random sweep for
// breadth.
func TestMaskedScanAgreesWithNetip(t *testing.T) {
	reset(t)

	// A spread of widths, including the extremes (/1 and /32, /1 and /128) and
	// the /64 word boundary where the IPv6 mask switches halves.
	prefixes := []netip.Prefix{}
	for _, s := range []string{
		"0.0.0.0/1", "10.0.0.0/8", "104.16.0.0/13", "172.16.0.0/12", "192.0.2.0/24",
		"198.51.100.128/25", "203.0.113.7/32", "128.0.0.0/1", "255.255.255.254/31",
		"::/1", "2001:db8::/32", "2606:4700::/48", "2a06:98c0::/29", "fe80::/10",
		"2001:db8:abcd::/63", "2001:db8:abcd::/64", "2001:db8:abcd::/65",
		"2001:db8::1/128", "8000::/1", "::/127",
	} {
		prefixes = append(prefixes, netip.MustParsePrefix(s).Masked())
	}
	current.Store(build(prefixes))

	// netipTrusted is the reference: the straightforward implementation, using
	// the stdlib, with the same normalisation IsTrusted does.
	netipTrusted := func(a netip.Addr) bool {
		if !a.IsValid() {
			return false
		}
		a = a.WithZone("").Unmap()
		if a.IsUnspecified() {
			return false
		}
		for _, p := range prefixes {
			if p.Contains(a) {
				return true
			}
		}
		return false
	}

	check := func(a netip.Addr) {
		t.Helper()
		if got, want := IsTrusted(a), netipTrusted(a); got != want {
			t.Errorf("IsTrusted(%s) = %v, netip.Prefix.Contains says %v", a, got, want)
		}
	}

	// Boundaries. For each prefix: the network address, the last address in the
	// range, and their neighbours one step outside.
	for _, p := range prefixes {
		first := p.Addr()
		last := lastAddrOf(p)
		check(first)
		check(last)
		if prev := first.Prev(); prev.IsValid() {
			check(prev)
		}
		if next := last.Next(); next.IsValid() {
			check(next)
		}
		// A middle address, to catch a mask that is right at the edges only.
		check(first.Next())
	}

	// Breadth. xorshift64* rather than math/rand, which wave 5 removed from
	// every non-vendored file, and rather than crypto/rand, because a failure
	// here must be reproducible from the seed alone.
	rng := uint64(0x9E3779B97F4A7C15)
	next := func() uint64 {
		rng ^= rng >> 12
		rng ^= rng << 25
		rng ^= rng >> 27
		return rng * 0x2545F4914F6CDD1D
	}
	for i := 0; i < 200_000; i++ {
		var b4 [4]byte
		v := next()
		b4[0], b4[1], b4[2], b4[3] = byte(v), byte(v>>8), byte(v>>16), byte(v>>24)
		check(netip.AddrFrom4(b4))

		var b16 [16]byte
		hi, lo := next(), next()
		for j := 0; j < 8; j++ {
			b16[j] = byte(hi >> (8 * j))
			b16[8+j] = byte(lo >> (8 * j))
		}
		check(netip.AddrFrom16(b16))

		if t.Failed() {
			t.Fatalf("stopping after first disagreement (iteration %d)", i)
		}
	}
}

// lastAddrOf returns the highest address inside p.
func lastAddrOf(p netip.Prefix) netip.Addr {
	a := p.Masked().Addr()
	if a.Is4() {
		b := a.As4()
		v := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
		v |= ^(^uint32(0) << (32 - p.Bits()))
		return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
	}
	b := a.As16()
	for i := p.Bits(); i < 128; i++ {
		b[i/8] |= 1 << (7 - i%8)
	}
	return netip.AddrFrom16(b)
}

// TestBuildRejectsAZeroBitPrefix pins build's second lock on the default route.
// parseEntry already refuses /0, but if a future change ever let one through,
// `^uint64(0) << 64` is 0 in Go, the mask would be all zeroes, and an all-zero
// mask matches every address on the internet. That is the single worst outcome
// this package can produce, so it is guarded twice.
func TestBuildRejectsAZeroBitPrefix(t *testing.T) {
	reset(t)
	current.Store(build([]netip.Prefix{
		netip.PrefixFrom(netip.MustParseAddr("0.0.0.0"), 0),
		netip.PrefixFrom(netip.MustParseAddr("::"), 0),
		netip.MustParsePrefix("198.51.100.0/24"),
	}))

	for _, s := range []string{"8.8.8.8", cfV4, "2001:4860:4860::8888", cfV6} {
		if IsTrusted(addr(t, s)) {
			t.Errorf("IsTrusted(%s) = true; a /0 reached build and produced an all-zero mask", s)
		}
	}
	if !IsTrusted(addr(t, "198.51.100.7")) {
		t.Error("dropping the /0 also dropped the valid prefix beside it")
	}
}

func TestBuildSplitsByFamilyAndDeduplicates(t *testing.T) {
	s := build([]netip.Prefix{
		netip.MustParsePrefix("198.51.100.0/24"),
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("198.51.100.0/24"), // duplicate
		netip.MustParsePrefix("2001:db8::/48"),
		netip.MustParsePrefix("2001:db8::/32"),
	})
	if len(s.v4) != 2 || len(s.v6) != 2 {
		t.Errorf("build produced %d v4 and %d v6, want 2 and 2", len(s.v4), len(s.v6))
	}
}

// --- concurrency ---------------------------------------------------------

// TestConcurrentLoadAndLookup is the -race test. IsTrusted runs on every
// request while a config reload calls Load; the atomic pointer swap is what
// keeps a request from ever observing a half-built set.
func TestConcurrentLoadAndLookup(t *testing.T) {
	reset(t)
	mustLoad(t)

	const readers = 8
	stop := make(chan struct{})
	var wg sync.WaitGroup

	for i := 0; i < readers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			a := netip.MustParseAddr(cfV4)
			for {
				select {
				case <-stop:
					return
				default:
					// A bundled range is trusted under every one of the loads
					// below, so the answer must never flicker.
					if !IsTrusted(a) {
						t.Errorf("IsTrusted(%s) = false during a reload", cfV4)
						return
					}
				}
			}
		}()
	}

	for i := 0; i < 200; i++ {
		if _, err := Load([]string{"198.51.100.0/24", "2001:db8::/32"}); err != nil {
			t.Errorf("Load: %v", err)
			break
		}
		if _, err := Load(nil); err != nil {
			t.Errorf("Load: %v", err)
			break
		}
	}
	close(stop)
	wg.Wait()
}

// --- benchmarks ----------------------------------------------------------
//
// IsTrusted runs once per request, so the numbers that matter are the miss
// cases (a full scan of one family) and the allocation count, which must be
// zero. Recorded on the dev machine, go1.25.14 windows/amd64, in
// global/trusted/README.md.

func benchSetup(b *testing.B) {
	b.Helper()
	prev := current.Load()
	if _, err := Load(nil); err != nil {
		b.Fatalf("Load: %v", err)
	}
	b.Cleanup(func() { current.Store(prev) })
}

var benchSink bool

func benchLookup(b *testing.B, ip string) {
	b.Helper()
	benchSetup(b)
	a := netip.MustParseAddr(ip)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		benchSink = IsTrusted(a)
	}
}

// Hit on the 12th of the 15 bundled IPv4 ranges, in load order.
func BenchmarkIsTrustedHitIPv4Late(b *testing.B) { benchLookup(b, cfV4) }

// Hit on the 2nd of the 15 bundled IPv4 ranges, in load order.
func BenchmarkIsTrustedHitIPv4Early(b *testing.B) { benchLookup(b, "103.21.244.1") }

// Worst case: every IPv4 prefix tested and none matches. This is the number the
// hot path actually pays for untrusted traffic, which is most traffic.
func BenchmarkIsTrustedMissIPv4(b *testing.B) { benchLookup(b, outsideV4) }

func BenchmarkIsTrustedHitIPv6(b *testing.B)  { benchLookup(b, cfV6) }
func BenchmarkIsTrustedMissIPv6(b *testing.B) { benchLookup(b, outsideV6) }

// The dual-stack form, to confirm Unmap costs nothing measurable.
func BenchmarkIsTrustedMappedIPv4(b *testing.B) { benchLookup(b, "::ffff:"+cfV4) }

// The pre-Load state, i.e. one atomic load and a nil check.
func BenchmarkIsTrustedNotLoaded(b *testing.B) {
	prev := current.Load()
	current.Store(nil)
	b.Cleanup(func() { current.Store(prev) })

	a := netip.MustParseAddr(cfV4)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		benchSink = IsTrusted(a)
	}
}

// The Netip* benchmarks are the control for the design choice on the `set`
// type: the same scan, over the same prefixes in the same order, using
// netip.Prefix.Contains instead of pre-masked integers. That is the
// straightforward implementation this package chose not to use, so keeping it
// here means the claim can be re-measured on any machine rather than taken on
// trust — and if a future Go release closes the gap, the argument for the
// hand-rolled masking goes away and these numbers will say so.
func netipTrustedForBench(prefixes []netip.Prefix, a netip.Addr) bool {
	if !a.IsValid() {
		return false
	}
	a = a.WithZone("").Unmap()
	if a.IsUnspecified() {
		return false
	}
	for _, p := range prefixes {
		if p.Addr().Is4() == a.Is4() && p.Contains(a) {
			return true
		}
	}
	return false
}

func benchNetip(b *testing.B, ip string) {
	b.Helper()
	prefixes := make([]netip.Prefix, len(bundled))
	copy(prefixes, bundled)
	a := netip.MustParseAddr(ip)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		benchSink = netipTrustedForBench(prefixes, a)
	}
}

func BenchmarkNetipHitIPv4Early(b *testing.B) { benchNetip(b, "103.21.244.1") }
func BenchmarkNetipHitIPv4Late(b *testing.B)  { benchNetip(b, cfV4) }
func BenchmarkNetipMissIPv4(b *testing.B)     { benchNetip(b, outsideV4) }
func BenchmarkNetipHitIPv6(b *testing.B)      { benchNetip(b, cfV6) }
func BenchmarkNetipMissIPv6(b *testing.B)     { benchNetip(b, outsideV6) }

// Load is not on the hot path, but a config reload should not stall the process.
func BenchmarkLoad(b *testing.B) {
	prev := current.Load()
	b.Cleanup(func() { current.Store(prev) })

	extra := []string{"198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32"}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := Load(extra); err != nil {
			b.Fatal(err)
		}
	}
}
