package server

import (
	"bytes"
	"crypto/subtle"
	"encoding/base64"
	"github.com/azferius/lancarsec/core/api"
	"github.com/azferius/lancarsec/core/domains"
	"github.com/azferius/lancarsec/core/firewall"
	"github.com/azferius/lancarsec/core/proxy"
	"github.com/azferius/lancarsec/core/trusted"
	"github.com/azferius/lancarsec/core/utils"
	"image"
	"image/color"
	"image/draw"
	"image/png"
	"math"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync/atomic"

	"github.com/azferius/lancarsec/core/gofilter"
)

// proxyCookieSuffix is the shared suffix of every challenge cookie the proxy
// issues: "_1"+suffix for stage 1, "_2"+suffix for stage 2 and
// "<ip>_3"+suffix for stage 3. Renaming this token is wave 10's job - it
// invalidates every clearance cookie in flight - so it stays spelled exactly
// as it is on the wire today.
const proxyCookieSuffix = "__bProxy_v"

func SendResponse(str string, buffer *bytes.Buffer, writer http.ResponseWriter) {
	buffer.WriteString(str)
	writer.Write(buffer.Bytes())
}

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
// It replaces `ip + tlsFp + reqUa + proxy.CurrHourStr`, an unseparated
// concatenation of attacker-controlled strings with two distinct holes in it:
//
//  1. No delimiter, so components bleed into each other. proxy.CurrHourStr is
//     a bare decimal hour ("0".."23"), which means a client sending the user
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

// challengeCookieName is the name of the cookie a client is expected to
// present for a given suspicion level. Levels with no challenge (0, and
// anything from 4 up, which is a hard block) have no cookie and return "".
func challengeCookieName(susLv int, ip string) string {
	switch susLv {
	case 1:
		return "_1" + proxyCookieSuffix
	case 2:
		return "_2" + proxyCookieSuffix
	case 3:
		// The stage-3 page writes this name from JavaScript; see the
		// document.cookie call in the captcha template below.
		return ip + "_3" + proxyCookieSuffix
	default:
		return ""
	}
}

// requestCookie returns the value of the request cookie whose name is exactly
// `name`. It is deliberately NOT a substring test over the raw Cookie header.
func requestCookie(request *http.Request, name string) (string, bool) {
	if cookie, err := request.Cookie(name); err == nil {
		return cookie.Value, true
	}

	// net/http silently drops any cookie pair whose NAME is not a valid HTTP
	// token, and the stage-3 cookie name embeds the client IP - an IPv6
	// address contains ':' and '[', neither of which is a token character. So
	// fall back to walking the header ourselves rather than making stage 3
	// permanently unsolvable for those clients. This is still an exact name
	// match on a properly split header, never a substring test.
	for _, header := range request.Header.Values("Cookie") {
		for _, pair := range strings.Split(header, ";") {
			cookieName, cookieValue, found := strings.Cut(strings.TrimSpace(pair), "=")
			if found && cookieName == name {
				return cookieValue, true
			}
		}
	}
	return "", false
}

// stripProxyCookies removes every challenge cookie from the request before it
// is forwarded upstream. The backend has no use for the proxy's clearance
// token, and handing it over means an XSS bug or a verbose access log on the
// backend leaks a working bypass for the entire proxy.
func stripProxyCookies(request *http.Request) {
	headers := request.Header.Values("Cookie")
	if len(headers) == 0 {
		return
	}

	rewritten := make([]string, 0, len(headers))
	changed := false
	for _, header := range headers {
		if !strings.Contains(header, proxyCookieSuffix) {
			rewritten = append(rewritten, header)
			continue
		}

		changed = true
		pairs := strings.Split(header, ";")
		kept := make([]string, 0, len(pairs))
		for _, pair := range pairs {
			pair = strings.TrimSpace(pair)
			cookieName, _, _ := strings.Cut(pair, "=")
			// Matched on the suffix, not on equality: "_1__bProxy_v",
			// "<ip>_3__bProxy_v" and any other prefix an attacker invents all
			// carry the same token and all have to go.
			if strings.Contains(cookieName, proxyCookieSuffix) {
				continue
			}
			kept = append(kept, pair)
		}
		if len(kept) != 0 {
			rewritten = append(rewritten, strings.Join(kept, "; "))
		}
	}

	if !changed {
		return
	}
	if len(rewritten) == 0 {
		request.Header.Del("Cookie")
		return
	}
	request.Header["Cookie"] = rewritten
}

// authorisedProxyEndpoint reports whether a request carries the API secret in
// the same header core/api reads.
//
// /_bProxy/stats reports live bypassed-requests-per-second, which is direct
// feedback to an attacker on whether his flood is getting through, plus the
// build fingerprint; /_bProxy/fingerprint reports the caller's ratelimit
// counters and the proxy's view of his TLS fingerprint, which is a free oracle
// for tuning an evasion. Both used to be served to anyone who cleared the
// challenge.
func authorisedProxyEndpoint(request *http.Request) bool {
	secret := proxy.APISecret
	if secret == "" {
		// An unset secret must not turn into "everyone matches the empty
		// string".
		return false
	}
	return subtle.ConstantTimeCompare([]byte(request.Header.Get("Proxy-Secret")), []byte(secret)) == 1
}

// proxyEndpointNotFound answers an unauthorised proxy endpoint with a plain
// 404 instead of 401/403, so probing cannot tell "this endpoint exists and you
// do not have the secret" apart from "there is no such endpoint".
func proxyEndpointNotFound(writer http.ResponseWriter, buffer *bytes.Buffer) {
	writer.Header().Set("Content-Type", "text/plain")
	writer.WriteHeader(http.StatusNotFound)
	SendResponse("404 Not Found", buffer, writer)
}

func Middleware(writer http.ResponseWriter, request *http.Request) {

	// defer pnc.PanicHndl() we wont do this during prod, to avoid overhead

	buffer := bufferPool.Get().(*bytes.Buffer)
	defer bufferPool.Put(buffer)
	buffer.Reset()

	// --- two hard limits, before any bookkeeping -----------------------------
	//
	// Both are here rather than further down because neither depends on the
	// domain, the client or the stage, and a request that is going to be
	// refused on protocol grounds should not first be counted, keyed, logged
	// or challenged.

	// CONNECT asks a proxy to open a tunnel to an arbitrary host and splice the
	// socket to it. httputil.ReverseProxy will happily be driven that way -
	// upstream forwards the method verbatim - which turns a DDoS front end into
	// an open relay: an attacker points it at any address and port he likes,
	// and the traffic leaves from the proxy's IP with the proxy's reputation.
	// Nothing this proxy fronts is a CONNECT endpoint, so it is refused
	// outright rather than filtered.
	if request.Method == http.MethodConnect {
		writer.Header().Set("Content-Type", "text/plain")
		writer.WriteHeader(http.StatusMethodNotAllowed)
		SendResponse("405 Method Not Allowed", buffer, writer)
		return
	}

	// Cap the body. Without this the only limit on what an unchallenged client
	// can push through to a customer origin is the write timeout, and the
	// proxy's own read of the body is unbounded.
	//
	// hasRequestBody is not a micro-optimisation. net/http hands a bodyless
	// request http.NoBody, which is NOT nil, so a plain `Body != nil` test
	// wraps every GET - and a maxBytesReader is a heap allocation per request
	// on the exact path a flood takes. Measured at 112 B/op and 1 alloc/op on
	// BenchmarkMiddlewareDecisionPath before this guard.
	if limit := MaxRequestBodyBytes.Load(); limit > 0 && hasRequestBody(request) {
		request.Body = http.MaxBytesReader(writer, request.Body, limit)
	}

	domainName := request.Host

	firewall.Mutex.RLock()
	domainData, domainFound := domains.DomainsData[domainName]
	firewall.Mutex.RUnlock()

	if !domainFound {
		writer.Header().Set("Content-Type", "text/plain")
		SendResponse("404 Not Found", buffer, writer)
		return
	}

	// The subject IP is resolved ONCE, here, for both deployment modes. The two
	// branches below now differ only in TLS fingerprinting, which is what
	// actually differs behind Cloudflare - the origin sees Cloudflare's
	// handshake, not the client's. Previously each branch derived its own idea
	// of the client address, one from an unvalidated header and one from a
	// broken RemoteAddr split.
	clientAddr := realClientIP(request)
	ip := ipString(clientAddr)
	rateKey := ratelimitKeyFor(clientAddr, ip)

	// Origin enforcement. In Cloudflare mode every legitimate request arrives
	// from a Cloudflare edge address, so a request from anywhere else is by
	// definition someone who found the origin IP and is talking to it directly
	// - which bypasses Cloudflare's own filtering entirely and leaves only this
	// proxy in the path.
	//
	// realClientIP already refuses to believe Cf-Connecting-Ip from an
	// untrusted peer, so identity cannot be forged either way. This is the
	// stronger statement: such a request is refused outright.
	//
	// Off by default, deliberately. Turning it on before DNS is fully cut over
	// to Cloudflare locks the operator out of their own origin, so it is the
	// operator's decision to make once they know their traffic only arrives
	// through the edge. See core/config/pipeline.go, which does not default it.
	if domains.Config.Proxy.Cloudflare && proxy.CloudflareEnforceOrigin {
		if peer := peerAddr(request.RemoteAddr); !peer.IsValid() || !trusted.IsTrusted(peer) {
			writer.Header().Set("Content-Type", "text/plain")
			writer.WriteHeader(http.StatusForbidden)
			SendResponse("403 Forbidden", buffer, writer)
			return
		}
	}

	var tlsFp string
	var browser string
	var botFp string

	var fpCount int
	var ipCount int
	var ipCountCookie int

	if domains.Config.Proxy.Cloudflare {

		tlsFp = "Cloudflare"
		browser = "Cloudflare"
		botFp = ""
		fpCount = 0

		firewall.Mutex.RLock()
		ipCount = firewall.AccessIps[rateKey]
		ipCountCookie = firewall.AccessIpsCookie[rateKey]
		firewall.Mutex.RUnlock()
	} else {
		//Retrieve information about the client. firewall.Connections is keyed
		//on the raw socket address, not on the subject IP: it is populated by
		//the TLS handshake for this exact connection, so it is the one lookup
		//that must NOT use realClientIP.
		firewall.Mutex.RLock()
		tlsFp = firewall.Connections[request.RemoteAddr]
		fpCount = firewall.UnkFps[tlsFp]
		ipCount = firewall.AccessIps[rateKey]
		ipCountCookie = firewall.AccessIpsCookie[rateKey]
		firewall.Mutex.RUnlock()

		//Read-Only IMPORTANT: Must be put in mutex if you add the ability to change indexed fingerprints while program is running
		browser = firewall.KnownFingerprints[tlsFp]
		botFp = firewall.BotFingerprints[tlsFp]
	}

	firewall.Mutex.Lock()
	// Leaving this here for future reference. When the monitor thread that's supposed to prefill these maps lags
	//behind for some reason, this will be come really messy. The mutex will be locked and never unlocked again,
	//freezing the entire proxy
	/*_, temp_found := firewall.WindowAccessIps[proxy.Last10SecondTimestamp]
	if !temp_found {
		log.Printf("Attempting To Set %s, %d but timestamp hasn't been set yet ?!?", ip, proxy.Last10SecondTimestamp)
	}*/
	firewall.WindowAccessIps[proxy.Last10SecondTimestamp][rateKey]++
	domainData = domains.DomainsData[domainName]
	domainData.TotalRequests++
	domains.DomainsData[domainName] = domainData
	firewall.Mutex.Unlock()

	writer.Header().Set("baloo-Proxy", "1.5")

	//SyncMap because semi-readonly
	settingsQuery, _ := domains.DomainsMap.Load(domainName)
	domainSettings, domainSettingsFound := settingsQuery.(domains.DomainSettings)
	if !domainSettingsFound {
		// DomainsData said this domain exists but DomainsMap has no settings for
		// it. The config pipeline now publishes both tables under one lock, so
		// this should be unreachable - but an unchecked assertion here took the
		// request handler down on a nil interface, which is not a failure mode
		// worth keeping for a lookup that has a perfectly good "unknown domain"
		// answer already.
		writer.Header().Set("Content-Type", "text/plain")
		writer.WriteHeader(http.StatusNotFound)
		SendResponse("404 Not Found", buffer, writer)
		return
	}

	reqUa := request.UserAgent()

	//Start the suspicious level where the stage currently is
	susLv := domainData.Stage

	//Demonstration of how to use "susLv". Essentially allows you to challenge specific requests with a higher challenge
	//
	// WAVE 6: the operator's rules are now evaluated BEFORE the ratelimits, not
	// after them. Under the old order an `action: 0` rule did not whitelist
	// anything: R1, R2 and R3 had already run and could already have answered
	// the request, so the one construct the DSL offers for "never block this"
	// could not express it. A health check, a payment callback or an office
	// range sharing a NAT address with a flood was refused with "you have been
	// ratelimited" no matter what the config said, and the operator had no way
	// to override it. Deciding the suspicion level first is what makes rule 0
	// mean what it reads as.
	if len(domainSettings.CustomRules) != 0 {
		requestVariables := gofilter.Message{
			// The exact client address, not the ratelimit bucket: a rule like
			// `ip.src in {2001:db8::1}` has to be able to name one host.
			"ip.src":    net.IP(clientAddr.AsSlice()),
			"ip.engine": browser,
			"ip.bot":    botFp,

			"ip.fingerprint": tlsFp,
			// These two are read out of the ratelimit counters, so for an IPv6
			// client they are now the /64's totals rather than the single
			// address's. That is the number the ratelimits themselves act on,
			// so a rule written against them stays consistent with R1/R2.
			"ip.http_requests":      ipCount,
			"ip.challenge_requests": ipCountCookie,

			"http.host":       domainName,
			"http.version":    request.Proto,
			"http.method":     request.Method,
			"http.url":        request.RequestURI,
			"http.query":      request.URL.RawQuery,
			"http.path":       request.URL.Path,
			"http.user_agent": strings.ToLower(reqUa),
			"http.cookie":     request.Header.Get("Cookie"),

			"proxy.stage":         domainData.Stage,
			"proxy.cloudflare":    domains.Config.Proxy.Cloudflare,
			"proxy.stage_locked":  domainData.StageManuallySet,
			"proxy.attack":        domainData.RawAttack,
			"proxy.bypass_attack": domainData.BypassAttack,
			"proxy.rps":           domainData.RequestsPerSecond,
			"proxy.rps_allowed":   domainData.RequestsBypassedPerSecond,
		}

		susLv = firewall.EvalFirewallRule(domainSettings, requestVariables, susLv)
	}

	// Whitelisted traffic (susLv 0, whether from `stage 0` or from a rule that
	// lowered it) skips all three ratelimits AND the unknown-fingerprint
	// counter. Skipping the checks is the whole point of a whitelist; skipping
	// the WindowUnkFps write matters just as much, because that counter is
	// shared by every client presenting the same TLS fingerprint. Letting
	// whitelisted traffic inflate it would mean an operator's own monitoring -
	// which by definition has one fingerprint and high volume - drove R3
	// against everybody else using the same browser build.
	if susLv > 0 {

		//Ratelimit faster if client repeatedly fails the verification challenge (feel free to play around with the threshhold)
		if ipCountCookie > proxy.FailChallengeRatelimit {
			writer.Header().Set("Content-Type", "text/plain")
			SendResponse("Blocked by BalooProxy.\nYou have been ratelimited. (R1)", buffer, writer)
			return
		}

		//Ratelimit spamming Ips (feel free to play around with the threshhold)
		if ipCount > proxy.IPRatelimit {
			writer.Header().Set("Content-Type", "text/plain")
			SendResponse("Blocked by BalooProxy.\nYou have been ratelimited. (R2)", buffer, writer)
			return
		}

		//Ratelimit fingerprints that don't belong to major browsers
		if browser == "" {
			if fpCount > proxy.FPRatelimit {
				writer.Header().Set("Content-Type", "text/plain")
				SendResponse("Blocked by BalooProxy.\nYou have been ratelimited. (R3)", buffer, writer)
				return
			}

			firewall.Mutex.Lock()
			firewall.WindowUnkFps[proxy.Last10SecondTimestamp][tlsFp]++
			firewall.Mutex.Unlock()
		}
	}

	//Block user-specified fingerprints
	//
	// This is NOT gated on susLv. The forbidden table is an explicit operator
	// deny-list of attack tooling, and a whitelist rule that accidentally
	// covered it - `http.path eq "/health"` matched by a flood tool hitting
	// /health - must not unblock it. Deny beats allow.
	forbiddenFp := firewall.ForbiddenFingerprints[tlsFp]
	if forbiddenFp != "" {
		writer.Header().Set("Content-Type", "text/plain")
		SendResponse("Blocked by BalooProxy.\nYour browser "+forbiddenFp+" is not allowed.", buffer, writer)
		return
	}

	//Check if encryption-result is already "cached" to prevent load on reverse proxy
	encryptedIP := ""
	hashedEncryptedIP := ""
	susLvStr := utils.StageToString(susLv)
	// The suspicion level is part of accessKey, so accessKey IS the cache key.
	// The old key was `accessKey + utils.StageToString(susLv)`, and
	// StageToString collapses 0 and everything from 5 up into "5+": a
	// whitelisted request and a blocked request shared one cache entry, and
	// the whitelisted one cached an empty token that then satisfied the
	// blocked one's cookie check.
	accessKey := accessKeyFor(domainName, ip, tlsFp, reqUa, proxy.CurrHourStr, susLv)
	encryptedCache, encryptedExists := firewall.CacheIps.Load(accessKey)

	if !encryptedExists {
		switch susLv {
		case 0:
			//whitelisted
		case 1:
			encryptedIP = utils.Encrypt(accessKey, proxy.CookieOTP)
		case 2:
			encryptedIP = utils.Encrypt(accessKey, proxy.JSOTP)
			hashedEncryptedIP = utils.EncryptSha(encryptedIP, "")
			firewall.CacheIps.Store(encryptedIP, hashedEncryptedIP)
		case 3:
			encryptedIP = utils.Encrypt(accessKey, proxy.CaptchaOTP)
		default:
			writer.Header().Set("Content-Type", "text/plain")
			SendResponse("Blocked by BalooProxy.\nSuspicious request of level "+susLvStr+" (base "+strconv.Itoa(domainData.Stage)+")", buffer, writer)
			return
		}
		firewall.CacheIps.Store(accessKey, encryptedIP)
	} else {
		encryptedIP = encryptedCache.(string)
		cachedHIP, foundCachedHIP := firewall.CacheIps.Load(encryptedIP)
		if foundCachedHIP {
			hashedEncryptedIP = cachedHIP.(string)
		}
	}

	//Check if client provided correct verification result
	//
	// The cookie is looked up BY NAME for the stage actually being enforced and
	// its whole value is compared in constant time. This used to be
	// strings.Contains(request.Header.Get("Cookie"), "__bProxy_v="+encryptedIP)
	// over the raw header, which accepted the token wherever it appeared: inside
	// an unrelated cookie's value ("junk=xx__bProxy_v=<token>"), under a cookie
	// name an attacker picked ("evil__bProxy_v=<token>"), or - when encryptedIP
	// was empty, as it is for a whitelisted or cache-collided request - on the
	// strength of any leftover proxy cookie at all.
	cookieName := challengeCookieName(susLv, ip)
	verified := false
	if cookieName != "" && encryptedIP != "" {
		if presented, found := requestCookie(request, cookieName); found {
			verified = subtle.ConstantTimeCompare([]byte(presented), []byte(encryptedIP)) == 1
		}
	}

	if !verified {

		// WAVE 6: only a request that was actually challenged counts as having
		// failed a challenge. A susLv-0 request has no cookie to present - the
		// proxy never issued one - so under the old unconditional increment
		// every whitelisted request incremented the challenge-failure window
		// that drives R1. Whitelisted traffic therefore ratelimited itself the
		// moment it exceeded FailChallengeRatelimit (40 requests per window by
		// default), which is the precise opposite of what `action: 0` means.
		if susLv > 0 {
			firewall.Mutex.Lock()
			firewall.WindowAccessIpsCookie[proxy.Last10SecondTimestamp][rateKey]++
			firewall.Mutex.Unlock()
		}

		//Respond with verification challenge if client didnt provide correct result/none
		switch susLv {
		case 0:
			//This request is not to be challenged (whitelist)
		case 1:
			// HttpOnly. Stage 1 is issued by the proxy and read back by the
			// proxy; no page ever needs it from script, so script - including
			// script injected into the backend - must not be able to read the
			// clearance token.
			//
			// Stages 2 and 3 CANNOT be HttpOnly and that is not an oversight:
			// both are written by the challenge page's own JavaScript with
			// document.cookie (see the templates below), and a browser refuses
			// to let script set an HttpOnly cookie. Adding the flag to those
			// two would make both challenges permanently unsolvable.
			writer.Header().Set("Set-Cookie", "_1"+proxyCookieSuffix+"="+encryptedIP+"; SameSite=Lax; path=/; Secure; HttpOnly")
			http.Redirect(writer, request, request.URL.RequestURI(), http.StatusFound)
			return
		case 2:
			publicSalt := encryptedIP[:len(encryptedIP)-domainData.Stage2Difficulty]
			writer.Header().Set("Content-Type", "text/html")
			writer.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0") // Prevent special(ed) browsers from caching the challenge
			SendResponse(`<!doctypehtml><html lang=en><meta charset=UTF-8><meta content="width=device-width,initial-scale=1"name=viewport><title>Completing challenge ...</title><style>body,html{height:100%;width:100%;margin:0;display:flex;flex-direction:column;justify-content:center;align-items:center;background-color:#f0f0f0;font-family:Arial,sans-serif}.loader{display:flex;justify-content:space-around;align-items:center;width:100px;height:100px}.loader div{width:20px;height:20px;background-color:#333;border-radius:50%;animation:bounce .6s infinite alternate}.loader div:nth-child(2){animation-delay:.2s}.loader div:nth-child(3){animation-delay:.4s}@keyframes bounce{to{transform:translateY(-30px)}}.message{text-align:center;margin-top:20px;color:#333}.subtext{text-align:center;color:#666;font-size:.9em;margin-top:5px}.placeholder-container{width:25%;text-align:center;margin:10px 0}.placeholder-label{font-weight:700;margin-bottom:5px}.placeholder{background-color:#e0e0e0;padding:10px;border-radius:5px;word-break:break-all;font-family:monospace;cursor:pointer;}</style><div class=loader><div></div><div></div><div></div></div><div class=message><p>Completing challenge ...<div class=subtext>The process is automatic and shouldn't take too long. Please be patient.</div></div><div class=placeholder-container><div class=placeholder-label>publicSalt:</div><div class=placeholder id=publicSalt onclick='ctc("publicSalt")'><span>`+publicSalt+`</span></div></div><div class=placeholder-container><div class=placeholder-label>challenge:</div><div class=placeholder id=challenge onclick='ctc("challenge")'><span>`+hashedEncryptedIP+`</span></div></div><script>function ctc(t){navigator.clipboard.writeText(document.getElementById(t).innerText)}</script><script src="https://cdn.jsdelivr.net/gh/41Baloo/balooPow@main/balooPow.min.js"></script><script src="https://cdnjs.cloudflare.com/ajax/libs/crypto-js/4.0.0/crypto-js.min.js"></script><script>function solved(e){document.cookie="_2__bProxy_v=`+publicSalt+`"+e.solution+"; SameSite=Lax; path=/; Secure",location.href=location.href}new BalooPow("`+publicSalt+`",`+strconv.Itoa(domainData.Stage2Difficulty)+`,"`+hashedEncryptedIP+`",!1).Solve().then(e=>{if(e.match == ""){solved(e)}else alert("Navigator Missmatch ("+e.match+"). Please contact @ddosmitigation")});</script>`, buffer, writer)
			return
		case 3:
			secretPart := encryptedIP[:6]
			publicPart := encryptedIP[6:]

			captchaData := ""
			maskData := ""
			captchaCache, captchaExists := firewall.CacheImgs.Load(secretPart)

			if !captchaExists {
				randomShift := utils.RandomIntN(50) - 25
				captchaImg := image.NewRGBA(image.Rect(0, 0, 100, 37))
				randomColor := uint8(utils.RandomIntN(255))
				utils.AddLabel(captchaImg, 0, 18, publicPart[6:], color.RGBA{61, 140, 64, 20})
				utils.AddLabel(captchaImg, utils.RandomIntN(90), utils.RandomIntN(30), publicPart[:6], color.RGBA{255, randomColor, randomColor, 100})
				utils.AddLabel(captchaImg, utils.RandomIntN(25), utils.RandomIntN(20)+10, secretPart, color.RGBA{61, 140, 64, 255})

				amplitude := float64(utils.RandomIntN(10)+10) / 10.0
				period := float64(37) / 5.0
				displacement := func(x, y int) (int, int) {
					dx := amplitude * math.Sin(float64(y)/period)
					dy := amplitude * math.Sin(float64(x)/period)
					return x + int(dx), y + int(dy)
				}
				captchaImg = utils.WarpImg(captchaImg, displacement)

				maskImg := image.NewRGBA(captchaImg.Bounds())
				draw.Draw(maskImg, maskImg.Bounds(), image.Transparent, image.Point{}, draw.Src)

				numTriangles := utils.RandomIntN(20) + 10

				blacklist := make(map[[2]int]bool) // We use this to keep track of already overwritten pixels.
				// it's slightly more performant to not do this but can lead to unsolvable captchas

				for range numTriangles {
					size := utils.RandomIntN(5) + 10
					x := utils.RandomIntN(captchaImg.Bounds().Dx() - size)
					y := utils.RandomIntN(captchaImg.Bounds().Dy() - size)
					blacklist = utils.DrawTriangle(blacklist, captchaImg, maskImg, x, y, size, randomShift)
				}

				var captchaBuf, maskBuf bytes.Buffer
				if err := png.Encode(&captchaBuf, captchaImg); err != nil {
					SendResponse("BalooProxy Error: Failed to encode captcha: "+err.Error(), buffer, writer)
					return
				}
				if err := png.Encode(&maskBuf, maskImg); err != nil {
					SendResponse("BalooProxy Error: Failed to encode captchaMask: "+err.Error(), buffer, writer)
					return
				}

				captchaData = base64.StdEncoding.EncodeToString(captchaBuf.Bytes())
				maskData = base64.StdEncoding.EncodeToString(maskBuf.Bytes())

				firewall.CacheImgs.Store(secretPart, [2]string{captchaData, maskData})
			} else {
				captchaDataTmp := captchaCache.([2]string)
				captchaData = captchaDataTmp[0]
				maskData = captchaDataTmp[1]
			}

			writer.Header().Set("Content-Type", "text/html")
			writer.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0") // Prevent special(ed) browsers from caching the challenge
			SendResponse(`<style>body{background-color:#f5f5f5;font-family:Arial,sans-serif}.center{display:flex;align-items:center;justify-content:center;height:100vh}.box{background-color:#fff;border:1px solid #ddd;border-radius:4px;padding:20px;width:500px}canvas{display:block;margin:0 auto;max-width:100%;width:100%;height:auto}input[type=text]{width:100%;padding:12px 20px;margin:8px 0;box-sizing:border-box;border:2px solid #ccc;border-radius:4px}button{width:100%;background-color:#4caf50;color:#fff;padding:14px 20px;margin:8px 0;border:none;border-radius:4px;cursor:pointer}button:hover{background-color:#45a049}.box{background-color:#fff;border:1px solid #ddd;border-radius:4px;padding:20px;width:500px;transition:height .1s;position:block}.box *{transition:opacity .1s}.success{background-color:#dff0d8;border:1px solid #d6e9c6;border-radius:4px;color:#3c763d;padding:20px}.failure{background-color:#f0d8d8;border:1px solid #e9c6c6;border-radius:4px;color:#763c3c;padding:20px}.collapsible{background-color:#f5f5f5;color:#444;cursor:pointer;padding:18px;width:100%;border:none;text-align:left;outline:0;font-size:15px}.collapsible:after{content:'\002B';color:#777;font-weight:700;float:right;margin-left:5px}.collapsible.active:after{content:"\2212"}.collapsible:hover{background-color:#e5e5e5}.collapsible-content{padding:0 18px;max-height:0;overflow:hidden;transition:max-height .2s ease-out;background-color:#f5f5f5}.captcha-wrapper{position:relative;width:100%;height:200px}.captcha-wrapper canvas{position:absolute}input[type=range]{-webkit-appearance:none;width:100%;height:25px;background:#ddd;outline:0;opacity:.7;transition:opacity .2s;border-radius:4px;margin:8px 0}input[type=range]:hover{opacity:1}input[type=range]::-webkit-slider-thumb{-webkit-appearance:none;appearance:none;width:25px;height:25px;background:#4caf50;cursor:pointer;border-radius:50%}input[type=range]::-moz-range-thumb{width:25px;height:25px;background:#4caf50;cursor:pointer;border-radius:50%}</style><div class=center id=center><div class=box id=box><h1>Drag the <b>slider</b> and enter the <b>green</b> text you see in the picture</h1><div class=captcha-wrapper><canvas height=37 id=captcha width=100></canvas><canvas height=37 id=mask width=100></canvas></div><input id=captcha-slider max=50 min=-50 type=range><form onsubmit="return checkAnswer(event)"><input id=text type=text maxlength=6 placeholder=Solution required> <button type=submit>Submit</button></form><div class=success id=successMessage style=display:none>Success! Redirecting ...</div><div class=failure id=failMessage style=display:none>Failed! Please try again.</div><button class=collapsible>Why am I seeing this page?</button><div class=collapsible-content><p>The website you are trying to visit needs to make sure that you are not a bot. This is a common security measure to protect websites from automated spam and abuse. By entering the characters you see in the picture, you are helping to verify that you are a real person.</div></div></div><script>let captcha_canvas=document.getElementById("captcha"),captcha_ctx=captcha_canvas.getContext("2d"),mask_canvas=document.getElementById("mask"),mask_ctx=mask_canvas.getContext("2d"),slider=document.getElementById("captcha-slider"),demo_slider=!1,demo_val=1;var i,captcha_image=new Image,mask_image=new Image;function checkAnswer(e){e.preventDefault();var a=document.getElementById("text").value;document.cookie="`+ip+`_3__bProxy_v="+a+"`+publicPart+`; SameSite=Lax; path=/; Secure",fetch("https://"+location.hostname+"/_bProxy/verified").then(function(e){return e.text()}).then(function(e){"verified"===e?(document.getElementById("successMessage").style.display="block",setInterval(function(){var e=document.getElementById("box"),a=e.offsetHeight,t=setInterval(function(){a-=20,e.style.height=a+"px";for(var c=e.children,s=0;s<c.length;s++)c[s].style.opacity=0;a<=0&&(e.style.height="0",e.remove(),clearInterval(t),location.href=location.href)},20)},1e3)):(document.getElementById("failMessage").style.display="block",setInterval(function(){location.href=location.href},1e3))}).catch(function(e){document.getElementById("failMessage").style.display="block",setInterval(function(){location.href=location.href},1e3)})}captcha_image.onload=function(){captcha_ctx.drawImage(captcha_image,(captcha_canvas.width-captcha_image.width)/2,(captcha_canvas.height-captcha_image.height)/2)},captcha_image.src="data:image/png;base64,`+captchaData+`",mask_image.onload=function(){mask_ctx.drawImage(mask_image,(mask_canvas.width-mask_image.width)/2,(mask_canvas.height-mask_image.height)/2)},mask_image.src="data:image/png;base64,`+maskData+`";let demo_int=setInterval(()=>{if(!demo_slider){clearInterval(demo_int);return}slider.value<=-50&&(demo_val=1),slider.value>=50&&(demo_val=-1),slider.value=parseInt(slider.value)+demo_val,updateCaptcha()},50);function updateCaptcha(){let e=parseInt(slider.value);mask_ctx.clearRect(0,0,mask_canvas.width,mask_canvas.height),mask_ctx.drawImage(mask_image,(mask_canvas.width-mask_image.width)/2+e,0)}slider.oninput=function(){demo_slider=!1,updateCaptcha()};var coll=document.getElementsByClassName("collapsible");for(i=0;i<coll.length;i++)coll[i].addEventListener("click",function(){this.classList.toggle("active");var e=this.nextElementSibling;e.style.maxHeight?e.style.maxHeight=null:e.style.maxHeight=e.scrollHeight+"px"});</script>`, buffer, writer)
			return
		default:
			writer.Header().Set("Content-Type", "text/plain")
			SendResponse("Blocked by BalooProxy.\nSuspicious request of level "+susLvStr, buffer, writer)
			return
		}
	}

	//Access logs of clients that passed the challenge
	firewall.Mutex.Lock()
	utils.AddLogs(domains.DomainLog{
		Time:      proxy.LastSecondTimeFormated,
		IP:        ip,
		BrowserFP: browser,
		BotFP:     botFp,
		TLSFP:     tlsFp,
		Useragent: reqUa,
		Path:      request.RequestURI,
	}, domainName)

	domainData = domains.DomainsData[domainName]
	domainData.BypassedRequests++
	domains.DomainsData[domainName] = domainData
	firewall.Mutex.Unlock()

	//Reserved proxy-paths

	switch request.URL.Path {
	case "/_bProxy/stats":
		if !authorisedProxyEndpoint(request) {
			proxyEndpointNotFound(writer, buffer)
			return
		}
		writer.Header().Set("Content-Type", "text/plain")
		SendResponse("Stage: "+utils.StageToString(domainData.Stage)+"\nTotal Requests: "+strconv.Itoa(domainData.TotalRequests)+"\nBypassed Requests: "+strconv.Itoa(domainData.BypassedRequests)+"\nTotal R/s: "+strconv.Itoa(domainData.RequestsPerSecond)+"\nBypassed R/s: "+strconv.Itoa(domainData.RequestsBypassedPerSecond)+"\nProxy Fingerprint: "+proxy.Fingerprint, buffer, writer)
		return
	case "/_bProxy/fingerprint":
		if !authorisedProxyEndpoint(request) {
			proxyEndpointNotFound(writer, buffer)
			return
		}
		writer.Header().Set("Content-Type", "text/plain")
		// "Ratelimit Key" is new in wave 6 and is not cosmetic: for an IPv6
		// client it is the /64 the counters below are actually kept under, so
		// an operator diagnosing "why is this address blocked" can see that the
		// answer is a neighbour in the same allocation rather than the address
		// named on the first line.
		SendResponse("IP: "+ip+"\nRatelimit Key: "+rateKey+"\nIP Requests: "+strconv.Itoa(ipCount)+"\nIP Challenge Requests: "+strconv.Itoa(ipCountCookie)+"\nSusLV: "+strconv.Itoa(susLv)+"\nFingerprint: "+tlsFp+"\nBrowser: "+browser+botFp, buffer, writer)
		return
	case "/_bProxy/verified":
		writer.Header().Set("Content-Type", "text/plain")
		SendResponse("verified", buffer, writer)
		return
	case "/_bProxy/" + proxy.AdminSecret + "/api/v1":
		result := api.Process(writer, request, domainData)
		if result {
			return
		}

	//Do not remove or modify this. It is required by the license
	case "/_bProxy/credits":
		writer.Header().Set("Content-Type", "text/plain")
		SendResponse("BalooProxy; Lightweight http reverse-proxy https://github.com/41Baloo/balooProxy. Protected by GNU GENERAL PUBLIC LICENSE Version 2, June 1991", buffer, writer)
		return
	}

	if strings.HasPrefix(request.URL.Path, "/_bProxy/api/v2") {
		result := api.ProcessV2(writer, request)
		if result {
			return
		}
	}

	//The backend never needs the proxy's own challenge cookies, and leaking
	//them to it hands out a bypass for every domain this proxy fronts.
	stripProxyCookies(request)

	//Allow backend to read client information.
	//
	//Del-then-Set, never Add: see stripClientIdentityHeaders. Add left the
	//client's own value in front of ours, and Header.Get returns the first.
	stripClientIdentityHeaders(request.Header)
	request.Header.Set("x-real-ip", ip)
	request.Header.Set("proxy-real-ip", ip)
	request.Header.Set("proxy-tls-fp", tlsFp)
	request.Header.Set("proxy-tls-name", browser+botFp)

	domainSettings.DomainProxy.ServeHTTP(writer, request)
}
