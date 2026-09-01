package server

// The decision pipeline. Wave 9 W2 (QUAL-03) split the former monolith into
// files with one owner each: identity.go owns WHO a request is from,
// response.go owns HOW the proxy answers, challenge.go owns what a challenged
// client is SENT. This file owns what is DECIDED about each request.

import (
	"bytes"
	"crypto/subtle"
	"net"
	"net/http"
	"strconv"
	"strings"

	"github.com/azferius/lancarsec/core/api"
	"github.com/azferius/lancarsec/core/domains"
	"github.com/azferius/lancarsec/core/firewall"
	"github.com/azferius/lancarsec/core/gofilter"
	"github.com/azferius/lancarsec/core/proxy"
	"github.com/azferius/lancarsec/core/trusted"
	"github.com/azferius/lancarsec/core/utils"
	"github.com/azferius/lancarsec/global/pow"
)

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
		SendResponseWithStatus(http.StatusMethodNotAllowed, "405 Method Not Allowed", buffer, writer)
		return
	}

	// WAVE 9: the vendored stage-2 proof-of-work scripts are served before ANY
	// bookkeeping - the counters, the domain lookup and above all the challenge
	// logic. A browser fetches them while it is being challenged, so the
	// request carries no clearance cookie; if this route were served after the
	// challenge logic the browser would receive a challenge page instead of
	// JavaScript and stage 2 would silently die. See servePowAsset.
	switch request.URL.Path {
	case powAssetPath:
		servePowAsset(writer, pow.BalooPow)
		return
	case powCryptoJSPath:
		servePowAsset(writer, pow.CryptoJS)
		return
	}

	// Cap the body. Without this the only limit on what an unchallenged client
	// can push through to a customer origin is the write timeout, and the
	// proxy's own read of the body is unbounded.
	//
	// WAVE 9 W4 (CONC-02/AUTHZ-05/CRYPTO-04): ONE config load per request.
	// Everything config-derived below reads through this snapshot, so a reload
	// swaps the whole set at once - never a new secret beside an old
	// threshold. The mirror globals (proxy.CookieSecret, thresholds,
	// proxy.Cloudflare) remain published for serve.go's startup wiring and
	// tests, but the request path must not read them.
	cfg := domains.Current()

	// hasRequestBody is not a micro-optimisation. net/http hands a bodyless
	// request http.NoBody, which is NOT nil, so a plain `Body != nil` test
	// wraps every GET - and a maxBytesReader is a heap allocation per request
	// on the exact path a flood takes. Measured at 112 B/op and 1 alloc/op on
	// BenchmarkMiddlewareDecisionPath before this guard.
	// WAVE 9 W3 (AUTHZ-06): the ceiling is wired from the published
	// configuration. normalise resolves the field: never zero at runtime, -1
	// means unlimited.
	if limit := cfg.Proxy.MaxBodySize; limit > 0 && hasRequestBody(request) {
		request.Body = http.MaxBytesReader(writer, request.Body, limit)
	}

	domainName := request.Host

	firewall.Mutex.RLock()
	domainData, domainFound := domains.DomainsData[domainName]
	firewall.Mutex.RUnlock()

	if !domainFound {
		writer.Header().Set("Content-Type", "text/plain")
		// WAVE 9: a real 404 with no-store; this body used to leave as a
		// cacheable 200 that merely said "404".
		SendResponseWithStatus(http.StatusNotFound, "404 Not Found", buffer, writer)
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
	if cfg.Proxy.Cloudflare && cfg.Proxy.CloudflareEnforceOrigin {
		if peer := peerAddr(request.RemoteAddr); !peer.IsValid() || !trusted.IsTrusted(peer) {
			writer.Header().Set("Content-Type", "text/plain")
			SendResponseWithStatus(http.StatusForbidden, "403 Forbidden", buffer, writer)
			return
		}
	}

	var tlsFp string
	var browser string
	var botFp string

	var fpCount int
	var ipCount int
	var ipCountCookie int

	if cfg.Proxy.Cloudflare {

		tlsFp = "Cloudflare"
		// WAVE 11 (AUDIT Cf-Ja3-Hash passthrough): behind Cloudflare every
		// connection used to collapse onto the one sentinel fingerprint, so
		// per-fingerprint deny-lists, bot lookups and token bindings never
		// saw the real client. Cf-Ja3-Hash is the JA3 md5 Cloudflare computes
		// on the client->edge TLS handshake, and like Cf-Connecting-Ip it is
		// believed only from a trusted peer. It feeds the tlsFp slot;
		// browser stays "Cloudflare", so the unknown-fingerprint path
		// (R3 + WindowUnkFps) never sees these values.
		if peer := peerAddr(request.RemoteAddr); peer.IsValid() && trusted.IsTrusted(peer) {
			if ja3 := request.Header.Get("Cf-Ja3-Hash"); ja3 != "" {
				tlsFp = ja3
			}
		}
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
	// CONC-01: bucket creation is lazy inside firewall.IncrWindow. The monitor
	// prefill is advisory; if it lags past the 120 s horizon this must not
	// panic on a nil inner map while holding the write lock (the lock would
	// never be released, freezing the whole proxy). CONC-04: new keys are
	// dropped once a bucket hits firewall.windowKeyCap.
	firewall.IncrWindow(firewall.WindowAccessIps, int(proxy.Last10SecondTimestamp()), rateKey)
	domainData = domains.DomainsData[domainName]
	domainData.TotalRequests++
	domains.DomainsData[domainName] = domainData
	firewall.Mutex.Unlock()

	// WAVE 10 (BRAND): the version header is hidden by default - a mitigation
	// product should not announce its exact build to the attacker probing it.
	// "hide_version_header": false in the config opts back in.
	if cfg.Proxy.ShowVersionHeader {
		writer.Header().Set("LancarSec-Proxy", "1.5")
	}

	//SyncMap because semi-readonly
	settingsQuery, _ := domains.DomainsMap.Load(domainName)
	domainSettings, domainSettingsFound := settingsQuery.(domains.DomainSettings)
	// WAVE 9 (HTTP-03): also refuse a settings row that has no backend. The
	// config pipeline registers the "debug" pseudo-domain with a zero
	// DomainSettings - DomainProxy nil - and a request naming it used to fall
	// all the way to DomainProxy.ServeHTTP below and panic on the nil pointer,
	// once per connection, with main.go's io.Discard swallowing the trace. A
	// host with no backend gets the same answer as a host with no config.
	if !domainSettingsFound || domainSettings.DomainProxy == nil {
		// DomainsData said this domain exists but DomainsMap has no usable
		// settings for it. The config pipeline now publishes both tables under
		// one lock, so this should be unreachable - but an unchecked assertion
		// here took the request handler down on a nil interface, which is not
		// a failure mode worth keeping for a lookup that has a perfectly good
		// "unknown domain" answer already.
		writer.Header().Set("Content-Type", "text/plain")
		SendResponseWithStatus(http.StatusNotFound, "404 Not Found", buffer, writer)
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
			"proxy.cloudflare":    cfg.Proxy.Cloudflare,
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
		if ipCountCookie > cfg.Proxy.Ratelimits["challengeFailures"] {
			writer.Header().Set("Content-Type", "text/plain")
			// WAVE 9: real 429s with Retry-After; these bodies used to leave
			// as cacheable 200s. 10 matches the 10-second window granularity
			// the counters above are kept in, which is the soonest the same
			// client's count can have drained.
			writer.Header().Set("Retry-After", "10")
			SendResponseWithStatus(http.StatusTooManyRequests, "Blocked by LancarSec.\nYou have been ratelimited. (R1)", buffer, writer)
			return
		}

		//Ratelimit spamming Ips (feel free to play around with the threshhold)
		if ipCount > cfg.Proxy.Ratelimits["requests"] {
			writer.Header().Set("Content-Type", "text/plain")
			writer.Header().Set("Retry-After", "10")
			SendResponseWithStatus(http.StatusTooManyRequests, "Blocked by LancarSec.\nYou have been ratelimited. (R2)", buffer, writer)
			return
		}

		//Ratelimit fingerprints that don't belong to major browsers
		if browser == "" {
			if fpCount > cfg.Proxy.Ratelimits["unknownFingerprint"] {
				writer.Header().Set("Content-Type", "text/plain")
				writer.Header().Set("Retry-After", "10")
				SendResponseWithStatus(http.StatusTooManyRequests, "Blocked by LancarSec.\nYou have been ratelimited. (R3)", buffer, writer)
				return
			}

			firewall.Mutex.Lock()
			// CONC-01/CONC-04: lazy creation + distinct-key cap, see IncrWindow.
			firewall.IncrWindow(firewall.WindowUnkFps, int(proxy.Last10SecondTimestamp()), tlsFp)
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
		// WAVE 9: a hard block answers 403, not a cacheable 200.
		SendResponseWithStatus(http.StatusForbidden, "Blocked by LancarSec.\nYour browser "+forbiddenFp+" is not allowed.", buffer, writer)
		return
	}

	//Check if encryption-result is already "cached" to prevent load on reverse proxy
	encryptedIP := ""
	hashedEncryptedIP := ""
	susLvStr := utils.StageToString(susLv)
	// The challenge secrets are read as ONE snapshot: the OTP set rotates
	// hourly, and accessKey, the encrypted tokens and the published bucket
	// string have to come from the same rotation or a token minted at the
	// boundary would not verify against anything.
	otp := proxy.LoadOTP()
	// The suspicion level is part of accessKey, so accessKey IS the cache key.
	// The old key was `accessKey + utils.StageToString(susLv)`, and
	// StageToString collapses 0 and everything from 5 up into "5+": a
	// whitelisted request and a blocked request shared one cache entry, and
	// the whitelisted one cached an empty token that then satisfied the
	// blocked one's cookie check.
	accessKey := accessKeyFor(domainName, ip, tlsFp, reqUa, otp.Hour, susLv)
	encryptedCache, encryptedExists := firewall.CacheIps.Load(accessKey)

	if !encryptedExists {
		switch susLv {
		case 0:
			//whitelisted
		case 1:
			encryptedIP = utils.Encrypt(accessKey, otp.Cookie)
		case 2:
			encryptedIP = utils.Encrypt(accessKey, otp.JS)
			hashedEncryptedIP = utils.EncryptSha(encryptedIP, "")
			firewall.CacheIps.Store(encryptedIP, hashedEncryptedIP)
		case 3:
			encryptedIP = utils.Encrypt(accessKey, otp.Captcha)
			// WAVE 11 (CRYPTO-03): stage 3 is a proof-of-work tier now, so its
			// page needs the same Challenge hash stage 2 publishes. Cached
			// under the token exactly like stage 2's, for the same reason.
			hashedEncryptedIP = utils.EncryptSha(encryptedIP, "")
			firewall.CacheIps.Store(encryptedIP, hashedEncryptedIP)
		default:
			writer.Header().Set("Content-Type", "text/plain")
			// WAVE 9: a hard block answers 403, not a cacheable 200.
			SendResponseWithStatus(http.StatusForbidden, "Blocked by LancarSec.\nSuspicious request of level "+susLvStr+" (base "+strconv.Itoa(domainData.Stage)+")", buffer, writer)
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
	cookieName := challengeCookieName(susLv)
	verified := false
	if cookieName != "" && encryptedIP != "" {
		if presented, found := requestCookie(request, cookieName); found {
			verified = subtle.ConstantTimeCompare([]byte(presented), []byte(encryptedIP)) == 1
		}
		// WAVE 10: one-release verify grace for the rebrand. A client still
		// carrying a pre-rebrand clearance cookie under the legacy name is
		// verified against the same token space and re-issued the current
		// name, so the cutover does not re-challenge every established client
		// at once. The legacy name is never issued again; remove with
		// legacyProxyCookieSuffix.
		if !verified {
			for _, legacyName := range legacyCookieNames(susLv, ip) {
				presented, found := requestCookie(request, legacyName)
				if !found {
					continue
				}
				if subtle.ConstantTimeCompare([]byte(presented), []byte(encryptedIP)) == 1 {
					verified = true
					reissueClearanceCookie(writer, susLv, encryptedIP)
				}
			}
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
			// CONC-01/CONC-04: lazy creation + distinct-key cap, see IncrWindow.
			firewall.IncrWindow(firewall.WindowAccessIpsCookie, int(proxy.Last10SecondTimestamp()), rateKey)
			firewall.Mutex.Unlock()
		}

		//Respond with verification challenge if client didnt provide correct result/none
		switch susLv {
		case 0:
			//This request is not to be challenged (whitelist)
		case 1:
			serveStage1Challenge(writer, request, buffer, encryptedIP)
			return
		case 2:
			publicSalt := encryptedIP[:len(encryptedIP)-domainData.Stage2Difficulty]
			serveStage2Challenge(writer, buffer, publicSalt, hashedEncryptedIP, domainData.Stage2Difficulty)
			return
		case 3:
			serveStage3Challenge(writer, buffer, encryptedIP, hashedEncryptedIP, domainData.Stage2Difficulty)
			return
		default:
			writer.Header().Set("Content-Type", "text/plain")
			// WAVE 9: a hard block answers 403, not a cacheable 200.
			SendResponseWithStatus(http.StatusForbidden, "Blocked by LancarSec.\nSuspicious request of level "+susLvStr, buffer, writer)
			return
		}
	}

	//Access logs of clients that passed the challenge
	// WAVE 10 moved the admin secret out of the URI into the Admin-Secret
	// header, and the API secret was always a header, so a well-behaved call
	// no longer puts a secret in the log line at all. The redaction stays for
	// the grace release: a legacy /_bProxy/<adminsecret>/api/v1 request still
	// carries the secret in its URI, and it is logged below (then 404'd by
	// the reserved switch). Empty secrets must not be replaced (an empty
	// needle would splice [redacted] between every character).
	loggedURI := request.RequestURI
	if adminSecret := cfg.Proxy.AdminSecret; adminSecret != "" {
		loggedURI = strings.ReplaceAll(loggedURI, adminSecret, "[redacted]")
	}
	if apiSecret := cfg.Proxy.APISecret; apiSecret != "" {
		loggedURI = strings.ReplaceAll(loggedURI, apiSecret, "[redacted]")
	}

	firewall.Mutex.Lock()
	utils.AddLogs(domains.DomainLog{
		Time:      proxy.LastSecondTimeFormatted(),
		IP:        ip,
		BrowserFP: browser,
		BotFP:     botFp,
		TLSFP:     tlsFp,
		Useragent: reqUa,
		Path:      loggedURI,
	}, domainName)

	domainData = domains.DomainsData[domainName]
	domainData.BypassedRequests++
	domains.DomainsData[domainName] = domainData
	firewall.Mutex.Unlock()

	//Reserved proxy-paths

	// WAVE 10: the legacy secret-in-path admin route is dead on arrival and is
	// NEVER proxied - a cutover-era bookmark cannot leak the old admin secret
	// to a customer backend. The secret is part of the path, so this is a
	// shape match rather than an exact one; any /_bProxy/.../api/v1 dies here.
	// It has already been logged redacted above.
	if strings.HasPrefix(request.URL.Path, "/_bProxy/") && strings.HasSuffix(request.URL.Path, "/api/v1") {
		proxyEndpointNotFound(writer, buffer)
		return
	}

	switch request.URL.Path {
	case "/_lancarsec/stats", "/_bProxy/stats":
		if !authorisedProxyEndpoint(request) {
			proxyEndpointNotFound(writer, buffer)
			return
		}
		writer.Header().Set("Content-Type", "text/plain")
		SendResponse("Stage: "+utils.StageToString(domainData.Stage)+"\nTotal Requests: "+strconv.Itoa(domainData.TotalRequests)+"\nBypassed Requests: "+strconv.Itoa(domainData.BypassedRequests)+"\nTotal R/s: "+strconv.Itoa(domainData.RequestsPerSecond)+"\nBypassed R/s: "+strconv.Itoa(domainData.RequestsBypassedPerSecond)+"\nProxy Fingerprint: "+proxy.Fingerprint, buffer, writer)
		return
	case "/_lancarsec/fingerprint", "/_bProxy/fingerprint":
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
	case "/_lancarsec/verified", "/_bProxy/verified":
		writer.Header().Set("Content-Type", "text/plain")
		SendResponse("verified", buffer, writer)
		return
	// WAVE 10: the admin API moved to a FIXED path; the secret travels in the
	// Admin-Secret header instead of the URL, where it landed in access logs,
	// browser history and Referer headers. api.Process still re-authenticates
	// with the Proxy-Secret/API secret in constant time, so both gates hold.
	case "/_lancarsec/api/v1":
		if !authorisedAdminEndpoint(request) {
			proxyEndpointNotFound(writer, buffer)
			return
		}
		result := api.Process(writer, request, domainData)
		if result {
			return
		}

	//Do not remove or modify this. It is required by the license
	case "/_bProxy/credits", "/_lancarsec/credits":
		writer.Header().Set("Content-Type", "text/plain")
		// WAVE 10: rebranded; upstream attribution kept and the license line
		// corrected to the GPL v3 this repository actually ships under.
		SendResponse("LancarSec; lightweight http reverse-proxy, based on BalooProxy by 41Baloo (https://github.com/41Baloo/balooProxy). Protected by GNU GENERAL PUBLIC LICENSE Version 3, 29 June 2007", buffer, writer)
		return
	}

	// WAVE 10: the API v2 prefix moved to /_lancarsec/api/v2; the legacy
	// spelling is honoured for one release. The rewrite is scoped INSIDE this
	// branch - the only caller of ProcessV2 - so api.go's TrimPrefix keeps
	// working for both spellings and no /_bProxy path is ever rewritten for
	// the backend.
	if path := request.URL.Path; strings.HasPrefix(path, "/_lancarsec/api/v2") || strings.HasPrefix(path, "/_bProxy/api/v2") {
		if strings.HasPrefix(path, "/_bProxy/") {
			request.URL.Path = "/_lancarsec" + strings.TrimPrefix(path, "/_bProxy")
		}
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
