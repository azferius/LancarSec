package server

// Client identity and the two request limits that do not depend on the domain,
// the client or the challenge stage. Split out of middleware.go (wave 9 W2,
// QUAL-03): this file owns WHO a request is from; middleware.go owns what is
// DECIDED about it.

import (
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync/atomic"

	"github.com/azferius/lancarsec/core/trusted"
)

// ---------------------------------------------------------------------------
// client identity (wave 6)
// ---------------------------------------------------------------------------

// ipv6RateBits is the prefix length IPv6 ratelimit counters aggregate to.
//
// A residential IPv6 customer is handed a /64 at the very least, and often a
// /56 or /48. Every address in that allocation is free for the holder to use
// and costs nothing to rotate, so per-address ratelimiting of IPv6 is not a
// ratelimit at all: one host can present 2^64 distinct "clients" without a
// single packet leaving its own subnet, and each one starts with a fresh
// counter. Counting at the /64 makes the smallest unit an ISP hands out the
// smallest unit the proxy can be attacked from.
//
// /64 rather than /56 or /48 because a /64 is the smallest allocation an
// operator can assume: aggregating further would put unrelated customers of the
// same ISP into one bucket, and one abuser would then ratelimit strangers.
const ipv6RateBits = 64

// MaxRequestBodyBytes caps the request body the proxy is willing to read from a
// client, in bytes. Zero or negative means unlimited.
//
// It is an atomic rather than a plain int64 because the config pipeline writes
// it on reload while requests are reading it.
//
// The default is 10 MiB. The proxy sits in front of ordinary web backends, and
// the body is pure cost to it: on the stage-1, stage-2, stage-3 and block paths
// the body is never read at all, and on the hot path it is streamed to a
// backend that has its own limit. An unauthenticated, unchallenged client
// should not be able to make the proxy pump an unbounded stream at a customer
// origin, and 10 MiB is comfortably above ordinary form and image uploads while
// being small enough that a flood of them is bounded work. Operators fronting a
// large-upload endpoint raise it in config; there is no per-domain field to
// hang this on yet (the config agent owns core/domains), so it is process-wide
// for now - see the note in the wave-6 handoff.
var MaxRequestBodyBytes atomic.Int64

const defaultMaxRequestBodyBytes = 10 << 20

func init() {
	MaxRequestBodyBytes.Store(defaultMaxRequestBodyBytes)
}

// parseClientAddr parses one candidate client address into a comparable
// netip.Addr, returning the zero Addr when it is not an address at all.
//
// It exists because every source of a client address in HTTP is a different
// shape: RemoteAddr is "host:port" with IPv6 hosts bracketed, an
// X-Forwarded-For element is normally a bare address but real proxies emit
// bracketed and port-suffixed forms too, and Cf-Connecting-Ip is bare.
//
// The result is canonicalised in two ways that matter for keying:
//
//   - 4-in-6 mapped addresses are unmapped. A dual-stack listener reports a v4
//     client as ::ffff:203.0.113.7; without unmapping, that client would occupy
//     a different ratelimit bucket from the same client arriving on a v4-only
//     listener, and could hold both at once.
//   - The zone is dropped. A zone is a local interface name and is not part of
//     the peer's identity, but netip.Addr compares and formats it, so leaving
//     it on would let "fe80::1%eth0" and "fe80::1%eth1" be two buckets.
func parseClientAddr(candidate string) netip.Addr {
	host, ok := hostOf(strings.TrimSpace(candidate))
	if !ok {
		return netip.Addr{}
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}
	}
	return addr.Unmap().WithZone("")
}

// hostOf strips an optional port and optional brackets from an address
// candidate, without allocating and without deciding whether what is left is a
// valid address.
//
// It exists instead of net.SplitHostPort because BOTH orderings of the obvious
// "try one, fall back to the other" allocate on the hot path: netip.ParseAddr
// and net.SplitHostPort each box an error value on failure, and every request
// takes the failing branch of one of them (RemoteAddr is always "host:port", an
// X-Forwarded-For element usually is not). Measured at one extra alloc per
// request on BenchmarkMiddlewareDecisionPath.
//
// Accepted shapes: "1.2.3.4", "1.2.3.4:80", "2001:db8::1", "fe80::1%eth0",
// "[2001:db8::1]", "[2001:db8::1]:443".
func hostOf(candidate string) (string, bool) {
	if candidate == "" {
		return "", false
	}

	if candidate[0] == '[' {
		end := strings.IndexByte(candidate, ']')
		if end < 0 {
			return "", false
		}
		return candidate[1:end], true
	}

	last := strings.LastIndexByte(candidate, ':')
	if last < 0 {
		// No colon at all: a bare IPv4 literal, or junk.
		return candidate, true
	}
	if strings.IndexByte(candidate, ':') != last {
		// More than one colon and no brackets: an unbracketed IPv6 literal
		// cannot carry a port, so the whole string is the host.
		return candidate, true
	}
	return candidate[:last], true
}

// peerAddr is the address of the socket this request actually arrived on.
//
// This replaces strings.Split(request.RemoteAddr, ":")[0], which was correct
// only for IPv4. For an IPv6 peer, RemoteAddr is "[2001:db8::1]:443", and
// splitting on ':' and taking element 0 yields the literal string "[2001".
// Every IPv6 client whose address begins with the same hextet therefore shared
// one ratelimit bucket, one encryption-cache key and one log identity - so an
// attacker on a single /64 could not be counted at all, while a legitimate
// visitor could be blocked for traffic he never sent.
func peerAddr(remoteAddr string) netip.Addr {
	return parseClientAddr(remoteAddr)
}

// forwardedForClient picks the client address out of an X-Forwarded-For chain.
//
// XFF is append-only and every hop trusts the hop before it, so the list reads
// left to right as "client, first proxy, second proxy, ...". The LEFTMOST
// element is therefore the one nobody verified: it is whatever the original
// client wrote, and a client that sends its own "X-Forwarded-For: 1.2.3.4"
// simply gets that value prepended to the chain. Taking the leftmost element -
// the obvious reading, and the one most naive implementations use - hands the
// attacker his own ratelimit bucket, his own cache key and his own log identity
// for free, which is the exact bug this wave exists to remove.
//
// The correct element is the rightmost one that is NOT itself a trusted proxy:
// walking in from the right, each entry was written by the hop to its right,
// and every hop we recognise as trusted is one whose word we accept. The first
// entry we do not recognise is the last one written by something we trust, and
// therefore the closest thing to a verified client address in the chain.
// Anything further left was written by a machine we have no reason to believe.
//
// Scanning forward and keeping the LAST untrusted element is the same value as
// scanning backward and taking the FIRST, and costs one pass with no allocation.
// If every element is a trusted proxy - the whole chain is our own
// infrastructure - the leftmost is the best answer available.
func forwardedForClient(headers []string) netip.Addr {
	var leftmost, lastUntrusted netip.Addr

	for _, header := range headers {
		for element := range strings.SplitSeq(header, ",") {
			addr := parseClientAddr(element)
			if !addr.IsValid() {
				continue
			}
			if !leftmost.IsValid() {
				leftmost = addr
			}
			if !trusted.IsTrusted(addr) {
				lastUntrusted = addr
			}
		}
	}

	if lastUntrusted.IsValid() {
		return lastUntrusted
	}
	return leftmost
}

// realClientIP is the single source of truth for the subject IP of a request.
// Every ratelimit key, cache key, log row, backend identity header and
// challenge-token component derives from its return value; nothing else in this
// file reads request.RemoteAddr or a forwarding header for an identity.
//
// A forwarding header is a claim, not a fact: anyone who can open a socket to
// this proxy can write any value into Cf-Connecting-Ip. The claim is worth
// something only when the machine that made it is one we put there, so the
// headers are consulted ONLY when the socket peer is inside a configured
// trusted-proxy range. From any other peer the peer address itself is the
// answer, because it is the one thing in the request the client cannot forge.
//
// Before this wave the Cloudflare branch read Cf-Connecting-Ip unconditionally,
// so a single header defeated every ratelimit, every ban and the binding of
// every challenge token: an attacker who found the origin address sent a fresh
// Cf-Connecting-Ip per request and got a fresh counter per request. It also
// meant a request arriving with no such header keyed on the empty string, so
// all of that traffic shared one bucket and one cache entry.
//
// The header order is Cf-Connecting-Ip, X-Real-Ip, X-Forwarded-For: most
// specific first. The first two carry exactly one address and cannot be
// ambiguous; X-Forwarded-For is a chain and is resolved by forwardedForClient.
func realClientIP(r *http.Request) netip.Addr {
	peer := peerAddr(r.RemoteAddr)
	if !trusted.IsTrusted(peer) {
		return peer
	}

	if addr := parseClientAddr(r.Header.Get("Cf-Connecting-Ip")); addr.IsValid() {
		return addr
	}
	if addr := parseClientAddr(r.Header.Get("X-Real-Ip")); addr.IsValid() {
		return addr
	}
	if addr := forwardedForClient(r.Header.Values("X-Forwarded-For")); addr.IsValid() {
		return addr
	}

	// A trusted proxy that forwarded nothing usable. Its own address is still
	// better than an empty key.
	return peer
}

// ratelimitKey is the bucket a request is COUNTED in.
//
// It is deliberately not the same string as ipString, and the split is the
// point of task 2:
//
//   - The ratelimit key is a measure of volume, so it must match the unit of
//     address space an attacker actually controls: the full address for IPv4,
//     where an address costs money, and the /64 for IPv6, where an address
//     costs nothing. Aggregating v6 here means rotating source addresses inside
//     an allocation no longer resets the counter.
//
//   - The identity value (ipString) is a credential and a record, so it must be
//     exact. Binding a challenge token to the /64 would let one host in a
//     residential block solve one captcha and hand the clearance cookie to
//     every other address in it - 2^64 hosts sharing one token - and a log row
//     or an x-real-ip naming "2001:db8::/64" instead of the address destroys
//     the evidence an operator needs to act on an abuse report.
//
// Coarse for counting, exact for identifying.
func ratelimitKey(addr netip.Addr) string {
	if !addr.IsValid() {
		return ""
	}
	if addr.Is4() {
		return addr.String()
	}
	prefix, err := addr.Prefix(ipv6RateBits)
	if err != nil {
		// Unreachable: 64 <= BitLen for every valid v6 address. Fall back to
		// per-address counting rather than dropping the request's accounting.
		return addr.String()
	}
	return prefix.String()
}

// hasRequestBody reports whether there is anything to cap.
//
// ContentLength is 0 only when the request genuinely carries no body; a body of
// unknown length (chunked, or HTTP/2 without a length) is -1, so it is capped.
func hasRequestBody(r *http.Request) bool {
	return r.Body != nil && r.Body != http.NoBody && r.ContentLength != 0
}

// ratelimitKeyFor derives the counting key when the exact address string has
// already been rendered.
//
// For IPv4 - the overwhelming majority of requests - the key IS that string, so
// this saves a second netip.Addr.String() allocation on every request. Only an
// IPv6 client pays for building the /64.
func ratelimitKeyFor(addr netip.Addr, rendered string) string {
	if !addr.IsValid() || addr.Is4() {
		return rendered
	}
	return ratelimitKey(addr)
}

// ipString renders the subject address for the places that need an exact
// identity: the access key, the stage-3 cookie name, the access log, the
// backend identity headers and the gated /_bProxy/fingerprint report.
//
// An invalid address renders as "" rather than netip's "invalid IP", so a
// request whose peer could not be parsed does not put that literal into a
// cookie name and a log row.
func ipString(addr netip.Addr) string {
	if !addr.IsValid() {
		return ""
	}
	return addr.String()
}

// stripClientIdentityHeaders removes every inbound header a backend might read
// as "who is this", so the only values it can see are the ones set immediately
// afterwards.
//
// The four identity headers used to be applied with Header.Add, which APPENDS.
// A client sending its own "x-real-ip: 10.0.0.1" therefore arrived at the
// backend as "X-Real-Ip: 10.0.0.1, 203.0.113.7" - and Header.Get, the way
// almost every backend reads a header, returns the FIRST value. The attacker's
// value won. Every access-control decision, audit log and geo lookup on the
// backend was spoofable through the proxy by sending one header.
//
// Set alone is not enough, because it only fixes the four names we happen to
// write. Forwarded (RFC 7239) and X-Forwarded-For say the same thing under
// different names, and a client can invent "Proxy-Real-Ip" or "Proxy-Tls-Fp"
// himself. Everything in that family is deleted first, unconditionally,
// including inbound Proxy-Secret - the admin API header, which a backend has no
// business seeing.
//
// X-Forwarded-For is deleted and NOT re-set: httputil.ReverseProxy appends the
// socket peer to it on the way out, which is the honest value for that header
// (the peer really is the machine it is talking to). Backends read the real
// client from X-Real-Ip.
//
// One pass over the header map rather than three Header.Del calls plus a
// range: the keys net/http parses are already canonical, so comparing them
// directly skips three CanonicalMIMEHeaderKey calls and three map lookups on
// the hot path. Deleting from a map being ranged is defined behaviour in Go -
// an entry removed before it is reached is not produced.
func stripClientIdentityHeaders(header http.Header) {
	for name := range header {
		switch name {
		case "X-Forwarded-For", "X-Real-Ip", "Forwarded":
			delete(header, name)
		default:
			if strings.HasPrefix(name, "Proxy-") {
				delete(header, name)
			}
		}
	}
}

// accessKeyFor renders the identity that a challenge token is minted against.
//
// It replaces `ip + tlsFp + reqUa + CurrHourStr`, an unseparated
// concatenation of attacker-controlled strings with two distinct holes in it:
//
//  1. No delimiter, so components bleed into each other. The hour used to be
//     a bare decimal ("0".."23"), which means a client sending the user
//     agent "Mozilla1" during hour 3 mints exactly the token that a client
//     sending "Mozilla" is issued during hour 13. Choosing a user agent is
//     free, so an attacker can pre-mint clearance for a future hour and walk
//     straight through the hourly OTP rotation that is supposed to expire it.
//
//  2. No domain and no stage. One proxy serves many domains from one set of
//     OTP secrets, so a token minted against an idle endpoint - a domain
//     sitting at stage 1 that nobody is attacking - was equally valid on a
//     different domain that had escalated to stage 1 under a flood.
//
// Each component is length-prefixed as "<len>:<value>". That encoding is
// injective: a reader takes the decimal length up to the first ':' and then
// exactly that many bytes, so no two distinct component tuples can render to
// the same key no matter what bytes a client puts in its user agent. The
// leading "v1" is an encoding version tag - change it in the same commit as
// any change to this layout, so cached keys from the old layout can never be
// reinterpreted under the new one.
func accessKeyFor(domainName, ip, tlsFp, userAgent, hour string, susLv int) string {
	parts := [...]string{"v1", domainName, ip, tlsFp, userAgent, hour, strconv.Itoa(susLv)}

	size := 0
	for _, part := range parts {
		size += len(part) + 4
	}

	var key strings.Builder
	key.Grow(size)
	for _, part := range parts {
		key.WriteString(strconv.Itoa(len(part)))
		key.WriteByte(':')
		key.WriteString(part)
	}
	return key.String()
}
