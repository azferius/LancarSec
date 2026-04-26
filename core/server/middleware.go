package server

import (
	"bytes"
	"crypto/subtle"
	"encoding/base64"
	"image"
	"image/color"
	"image/draw"
	"image/png"
	"lancarsec/core/api"
	"lancarsec/core/dashboard"
	"lancarsec/core/domains"
	"lancarsec/core/firewall"
	"lancarsec/core/proxy"
	"lancarsec/core/trusted"
	"lancarsec/core/utils"
	"math"
	"net"
	"net/http"
	"strconv"
	"strings"

	"github.com/kor44/gofilter"
)

func SendResponse(str string, buffer *bytes.Buffer, writer http.ResponseWriter) {
	buffer.WriteString(str)
	writer.Write(buffer.Bytes())
}

// stripProxyCookies removes LancarSec challenge cookies from the request's
// Cookie header before it's proxied upstream. Everything else is preserved,
// so the backend's own session cookies still flow. Runs O(n) over Cookie
// entries once per forwarded request.
func stripProxyCookies(r *http.Request) {
	cookies := r.Cookies()
	if len(cookies) == 0 {
		return
	}
	r.Header.Del("Cookie")
	for _, c := range cookies {
		if strings.HasSuffix(c.Name, "__lSec_v") {
			continue
		}
		r.AddCookie(c)
	}
}

func peerHost(addr string) string {
	if host, _, err := net.SplitHostPort(addr); err == nil {
		return host
	}
	return addr
}

func isLoopbackHost(host string) bool {
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func validSecret(got, want string) bool {
	if want == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1
}

func rejectDirectOrigin(w http.ResponseWriter, r *http.Request, buffer *bytes.Buffer) bool {
	if !proxy.Cloudflare || !proxy.CloudflareEnforceOrigin {
		return false
	}
	peer := peerHost(r.RemoteAddr)
	if trusted.IsTrusted(peer) || isLoopbackHost(peer) {
		return false
	}
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusForbidden)
	SendResponse("Blocked by LancarSec.\nDirect origin access is not allowed; connect via Cloudflare.", buffer, w)
	return true
}

func requestProtocol(r *http.Request) string {
	if r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https") || strings.Contains(strings.ToLower(r.Header.Get("Cf-Visitor")), "https") {
		return "HTTPS"
	}
	return "HTTP"
}

// hasValidChallengeCookie checks the request's cookies for a LancarSec
// challenge token whose value exactly matches the stage-specific encryptedIP.
// Stage 1/2/3 use cookie names ending with "_1__lSec_v", "_2__lSec_v", or
// "_3__lSec_v" (stage 3 is prefixed with the client IP at issue time).
// Exact match replaces the old strings.Contains scan, which could match if an
// unrelated cookie happened to contain the token as a substring.
func hasValidChallengeCookie(r *http.Request, encryptedIP string) bool {
	if encryptedIP == "" {
		return false
	}
	for _, c := range r.Cookies() {
		if !strings.HasSuffix(c.Name, "__lSec_v") {
			continue
		}
		if subtle.ConstantTimeCompare([]byte(c.Value), []byte(encryptedIP)) == 1 {
			return true
		}
	}
	return false
}

// realClientIP returns the client IP for rule evaluation.
// Proxy-supplied headers (Cf-Connecting-Ip, X-Forwarded-For, X-Real-IP) are
// only honored when the socket peer is itself a trusted proxy. This never
// bypasses firewall/ratelimit decisions — it only resolves the subject IP.
func realClientIP(r *http.Request) string {
	remote := r.RemoteAddr
	peer := peerHost(remote)

	if trusted.IsTrusted(peer) {
		if cf := strings.TrimSpace(r.Header.Get("Cf-Connecting-Ip")); cf != "" {
			return cf
		}
		if xr := strings.TrimSpace(r.Header.Get("X-Real-Ip")); xr != "" {
			return xr
		}
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			if idx := strings.Index(xff, ","); idx >= 0 {
				return strings.TrimSpace(xff[:idx])
			}
			return strings.TrimSpace(xff)
		}
	}

	return peer
}

func Middleware(writer http.ResponseWriter, request *http.Request) {

	// defer pnc.PanicHndl() we wont do this during prod, to avoid overhead

	buffer := bufferPool.Get().(*bytes.Buffer)
	defer bufferPool.Put(buffer)
	buffer.Reset()

	domainName := request.Host

	if rejectDirectOrigin(writer, request, buffer) {
		return
	}

	firewall.DataMu.RLock()
	domainData, domainFound := domains.DomainsData[domainName]
	firewall.DataMu.RUnlock()

	// Dashboard + auth routes are served regardless of which configured
	// domain the Host resolves to. They live under /_lancarsec/login,
	// /_lancarsec/dashboard/*, and /_lancarsec/api/dashboard/*. Handled
	// before the 404 so the operator can hit the dashboard even on a Host
	// header that doesn't match any forwarded domain (e.g. the raw origin
	// IP).
	if strings.HasPrefix(request.URL.Path, "/_lancarsec/login") ||
		strings.HasPrefix(request.URL.Path, "/_lancarsec/logout") ||
		strings.HasPrefix(request.URL.Path, "/_lancarsec/dashboard") ||
		strings.HasPrefix(request.URL.Path, "/_lancarsec/api/dashboard") {
		if dashboard.Serve(writer, request) {
			return
		}
	}

	// Prometheus scrape endpoint — lives outside /api/dashboard so a scraper
	// can hit it without juggling the dashboard session/Bearer flow.
	if request.URL.Path == "/_lancarsec/metrics" {
		ServeMetrics(writer, request)
		return
	}

	if !domainFound {
		writer.Header().Set("Content-Type", "text/plain")
		SendResponse("404 Not Found", buffer, writer)
		return
	}

	IncrRequest()

	metrics := &responseMetricsWriter{ResponseWriter: writer}
	writer = metrics

	reqUa := request.UserAgent()
	logIP := peerHost(request.RemoteAddr)
	logTLSFP := ""
	logJA3 := ""
	logJA4 := ""
	logJA4R := ""
	logJA4O := ""
	logJA4H := ""
	logBrowser := ""
	logBot := ""
	logCountry := strings.ToUpper(strings.TrimSpace(request.Header.Get("Cf-Ipcountry")))
	if logCountry == "XX" {
		logCountry = ""
	}
	defer func() {
		entry := domains.DomainLog{
			Time:      proxy.GetLastSecondFormatted(),
			IP:        logIP,
			Country:   logCountry,
			BrowserFP: logBrowser,
			BotFP:     logBot,
			TLSFP:     logTLSFP,
			JA3:       logJA3,
			JA4:       logJA4,
			JA4R:      logJA4R,
			JA4O:      logJA4O,
			JA4H:      logJA4H,
			Useragent: reqUa,
			Method:    request.Method,
			Path:      request.RequestURI,
			Protocol:  requestProtocol(request),
			Status:    metrics.Status(),
			Size:      metrics.Bytes(),
		}
		firewall.DataMu.Lock()
		utils.AddLogs(entry, domainName)
		firewall.DataMu.Unlock()
	}()

	// Reject CONNECT outright. httputil.ReverseProxy would otherwise tunnel
	// it, turning LancarSec into an open HTTP proxy for attackers hopping to
	// arbitrary destinations.
	if request.Method == http.MethodConnect {
		IncrConnectReject()
		IncrBlocked()
		writer.Header().Set("Content-Type", "text/plain")
		writer.WriteHeader(http.StatusMethodNotAllowed)
		SendResponse("CONNECT not allowed", buffer, writer)
		return
	}

	// WebSocket upgrade requests skip every subsequent HTTP challenge after
	// the handshake succeeds — if we let an un-challenged WS upgrade through
	// we'd effectively whitelist the connection for as long as the socket
	// lives. Flag it here so the susLv + cookie check below treats it like
	// any other request, and force a higher minimum sus level so bots that
	// abuse WS for flooding don't get a free pass.
	isWebsocket := strings.EqualFold(request.Header.Get("Upgrade"), "websocket") &&
		strings.Contains(strings.ToLower(request.Header.Get("Connection")), "upgrade")

	// Cap request bodies so a slow/huge POST can't exhaust memory. 10 MiB
	// is enough for any JSON/form payload; larger uploads should go direct
	// or use a different path configured per-domain in future work.
	if request.Body != nil {
		request.Body = http.MaxBytesReader(writer, request.Body, 10<<20)
	}

	// Blocklist check — IPs / CIDRs / UA patterns published atomically by
	// config.Apply. Evaluated before any ratelimit/challenge logic so a
	// confirmed bad actor never consumes a window counter or a PoW worker.
	// ASN field left blank for now; ASN resolution lands with the future
	// GeoLite2 integration.
	peerIP := peerHost(request.RemoteAddr)
	// Resolve forwarded IP early for blocklist match — but only trust it
	// from a trusted proxy, per the realClientIP rules.
	resolvedIP := peerIP
	if trusted.IsTrusted(peerIP) {
		if cf := strings.TrimSpace(request.Header.Get("Cf-Connecting-Ip")); cf != "" {
			resolvedIP = cf
		}
	}
	// Pre-load TLS fingerprints so the blocklist can match against JA3 / JA4
	// / JA4_R / JA4_O. In Cloudflare mode JA3 comes from the Cf-Ja3-Hash
	// header (Enterprise add-on); the legacy hex string is set to a sentinel.
	earlyTLSFP := ""
	earlyJA3 := ""
	earlyJA4 := ""
	earlyJA4R := ""
	earlyJA4O := ""
	if proxy.Cloudflare {
		earlyTLSFP = "Cloudflare"
		if h := strings.TrimSpace(request.Header.Get("Cf-Ja3-Hash")); h != "" {
			earlyJA3 = h
			earlyJA4 = "cf:" + h
		}
	} else {
		if v, ok := firewall.Connections.Load(request.RemoteAddr); ok {
			earlyTLSFP = v.(string)
		}
		if v, ok := firewall.JA4s.Load(request.RemoteAddr); ok {
			earlyJA4 = v.(string)
		}
		if v, ok := firewall.JA3s.Load(request.RemoteAddr); ok {
			earlyJA3 = v.(string)
		}
		if v, ok := firewall.JA4Rs.Load(request.RemoteAddr); ok {
			earlyJA4R = v.(string)
		}
		if v, ok := firewall.JA4Os.Load(request.RemoteAddr); ok {
			earlyJA4O = v.(string)
		}
	}
	earlyJA4H := firewall.ComputeJA4H(request)
	logTLSFP = earlyTLSFP
	logJA3 = earlyJA3
	logJA4 = earlyJA4
	logJA4R = earlyJA4R
	logJA4O = earlyJA4O
	logJA4H = earlyJA4H

	// ASN + country resolution. Both are O(1) when the GeoLite2 DBs are
	// loaded; both return empty when not, which falls through cleanly.
	// Country prefers Cloudflare's Cf-Ipcountry header (already trusted
	// because we're past the trusted-proxy peer check) before falling back
	// to GeoLite2 lookup so we don't pay a bdb lookup when CF already told
	// us the answer.
	asn := firewall.ResolveASN(resolvedIP)
	country := strings.ToUpper(strings.TrimSpace(request.Header.Get("Cf-Ipcountry")))
	if country == "" || country == "XX" {
		country = firewall.ResolveCountry(resolvedIP)
	}
	logCountry = country
	if decision := firewall.Evaluate(firewall.EvalContext{
		IP:        resolvedIP,
		UserAgent: request.UserAgent(),
		ASN:       asn,
		Country:   country,
		Domain:    domainName,
		TLSFP:     earlyTLSFP,
		JA3:       earlyJA3,
		JA4:       earlyJA4,
		JA4R:      earlyJA4R,
		JA4O:      earlyJA4O,
		JA4H:      earlyJA4H,
	}); decision.Hit {
		IncrBlocklistHit()
		IncrBlocked()
		writer.Header().Set("Content-Type", "text/plain")
		writer.WriteHeader(http.StatusForbidden)
		reason := decision.Entry.Reason
		if reason == "" {
			reason = "listed on " + decision.Entry.Type + " blocklist"
		}
		SendResponse("Blocked by LancarSec.\n"+reason, buffer, writer)
		return
	}

	// Admin API v1: secret moved from URL path (where it ends up in access
	// logs, referers, and CDN caches) to required Admin-Secret + Proxy-Secret
	// headers. Bad credentials stop here instead of falling through upstream.
	if request.URL.Path == "/_lancarsec/api/v1" {
		if !validSecret(request.Header.Get("Admin-Secret"), proxy.AdminSecret) ||
			!validSecret(request.Header.Get("Proxy-Secret"), proxy.APISecret) {
			writer.WriteHeader(http.StatusUnauthorized)
			return
		}
		if api.Process(writer, request, domainData) {
			return
		}
		http.NotFound(writer, request)
		return
	}

	if request.URL.Path == "/_lancarsec/api/v2" || strings.HasPrefix(request.URL.Path, "/_lancarsec/api/v2/") {
		if !validSecret(request.Header.Get("Proxy-Secret"), proxy.APISecret) {
			writer.WriteHeader(http.StatusUnauthorized)
			return
		}
		if api.ProcessV2(writer, request) {
			return
		}
		http.NotFound(writer, request)
		return
	}

	// Static assets served to the challenge page itself; must bypass the
	// cookie/ratelimit gates so the browser can load them on the first hit.
	switch request.URL.Path {
	case "/_lancarsec/static/lancarpow.min.js":
		writer.Header().Set("Content-Type", "application/javascript")
		writer.Header().Set("Cache-Control", "public, max-age=3600")
		http.ServeFile(writer, request, "assets/js/lancarpow.min.js")
		return
	case "/_lancarsec/static/crypto-js.min.js":
		writer.Header().Set("Content-Type", "application/javascript")
		writer.Header().Set("Cache-Control", "public, max-age=3600")
		http.ServeFile(writer, request, "assets/js/crypto-js.min.js")
		return
	}

	// Per-path / per-method rate limits evaluated against the same IP. Runs
	// before the generic per-IP limit so a heavy endpoint gets its tight cap
	// without polluting the baseline counter. Only touches lock-protected
	// state when the path actually matches a configured pattern, so domains
	// without path rules pay zero compute.
	pathLimitChallenge := false
	nowSecond := proxy.GetLastSecondTimestamp()
	nowBucket := proxy.GetLast10SecondTimestamp()
	if pd := firewall.EvaluatePath(domainName, request.Method, request.URL.Path, resolvedIP, nowSecond, proxy.RatelimitWindow); pd.Hit {
		IncrPathLimitHit()
		if strings.EqualFold(pd.Action, "challenge") {
			pathLimitChallenge = true
		} else {
			IncrBlocked()
			writer.Header().Set("Content-Type", "text/plain")
			writer.Header().Set("Retry-After", "60")
			writer.WriteHeader(http.StatusTooManyRequests)
			SendResponse("Blocked by LancarSec.\n"+pd.Reason, buffer, writer)
			return
		}
	}

	var browser string
	var botFp string

	var fpCount int
	var ipCount int
	var ipCountCookie int

	ip := realClientIP(request)
	tlsFp := earlyTLSFP
	ja3 := earlyJA3
	ja4 := earlyJA4
	ja4r := earlyJA4R
	ja4o := earlyJA4O
	ja4h := earlyJA4H
	logIP = ip
	logTLSFP = tlsFp
	logJA3 = ja3
	logJA4 = ja4
	logJA4R = ja4r
	logJA4O = ja4o
	logJA4H = ja4h

	if proxy.Cloudflare {
		// Sentinel for the JA4 slot when Cf-Ja3-Hash isn't forwarded — keeps
		// downstream code from treating "" as a legitimate fingerprint.
		if ja4 == "" {
			ja4 = "Cloudflare"
		}
		browser = "Cloudflare"
		botFp = ""
		fpCount = 0

		firewall.CountersMu.RLock()
		ipCount = firewall.SumWindow(firewall.WindowAccessIps, ip, proxy.RatelimitWindow, nowSecond)
		ipCountCookie = firewall.SumWindow(firewall.WindowAccessIpsCookie, ip, proxy.RatelimitWindow, nowSecond)
		firewall.CountersMu.RUnlock()
	} else {
		firewall.CountersMu.RLock()
		fpCount = firewall.SumWindow(firewall.WindowUnkFps, tlsFp, proxy.RatelimitWindow, nowSecond)
		ipCount = firewall.SumWindow(firewall.WindowAccessIps, ip, proxy.RatelimitWindow, nowSecond)
		ipCountCookie = firewall.SumWindow(firewall.WindowAccessIpsCookie, ip, proxy.RatelimitWindow, nowSecond)
		firewall.CountersMu.RUnlock()

		// Atomic pointer lookups — safe to read concurrently with config
		// reload, which swaps the published map rather than mutating it.
		browser = firewall.LookupKnown(tlsFp)
		botFp = firewall.LookupBot(tlsFp)
	}
	logBrowser = browser
	logBot = botFp

	// Bounded counter bump. Incr drops the increment if the per-bucket key
	// count has hit the cap — an attacker flooding with fresh IPs can't
	// balloon the window map.
	firewall.Incr(firewall.WindowAccessIps, nowBucket, ip)

	// Per-domain request counter is an atomic — no lock, no struct copy. The
	// full DomainData copy only happens where we genuinely need the rest of
	// the fields (stage, settings, etc).
	domains.CountersFor(domainName).Total.Add(1)
	firewall.DataMu.RLock()
	domainData = domains.DomainsData[domainName]
	firewall.DataMu.RUnlock()

	if !proxy.HideVersionHeader {
		writer.Header().Set("LancarSec-Proxy", "1.0")
	}

	//Start the suspicious level where the stage currently is
	susLv := domainData.Stage
	if pathLimitChallenge && susLv < 3 {
		susLv = 3
	}

	// WebSocket: require at least Stage 2 (JS PoW) so a long-lived socket
	// can't be opened by a bot that only passes a cookie-level challenge.
	if isWebsocket && susLv < 2 {
		susLv = 2
	}

	//Ratelimit faster if client repeatedly fails the verification challenge (feel free to play around with the threshhold)
	if ipCountCookie > proxy.FailChallengeRatelimit {
		IncrRateLimitHit()
		IncrBlocked()
		writer.Header().Set("Content-Type", "text/plain")
		SendResponse("Blocked by LancarSec.\nYou have been ratelimited. (R1)", buffer, writer)
		return
	}

	//Ratelimit spamming Ips (feel free to play around with the threshhold)
	if ipCount > proxy.IPRatelimit {
		IncrRateLimitHit()
		IncrBlocked()
		writer.Header().Set("Content-Type", "text/plain")
		SendResponse("Blocked by LancarSec.\nYou have been ratelimited. (R2)", buffer, writer)
		return
	}

	//Ratelimit fingerprints that don't belong to major browsers
	if browser == "" {
		if fpCount > proxy.FPRatelimit {
			IncrRateLimitHit()
			IncrBlocked()
			writer.Header().Set("Content-Type", "text/plain")
			SendResponse("Blocked by LancarSec.\nYou have been ratelimited. (R3)", buffer, writer)
			return
		}

		firewall.Incr(firewall.WindowUnkFps, nowBucket, tlsFp)
	}

	//Block user-specified fingerprints
	forbiddenFp := firewall.LookupForbidden(tlsFp)
	if forbiddenFp != "" {
		writer.Header().Set("Content-Type", "text/plain")
		SendResponse("Blocked by LancarSec.\nYour browser "+forbiddenFp+" is not allowed.", buffer, writer)
		return
	}

	//Demonstration of how to use "susLv". Essentially allows you to challenge specific requests with a higher challenge

	//SyncMap because semi-readonly
	settingsQuery, ok := domains.DomainsMap.Load(domainName)
	if !ok {
		writer.Header().Set("Content-Type", "text/plain")
		SendResponse("404 Not Found", buffer, writer)
		return
	}
	domainSettings := settingsQuery.(domains.DomainSettings)

	if len(domainSettings.CustomRules) != 0 {
		requestVariables := gofilter.Message{
			"ip.src":                net.ParseIP(ip),
			"ip.engine":             browser,
			"ip.bot":                botFp,
			"ip.fingerprint":        tlsFp,
			"ip.ja3":                ja3,
			"ip.ja4":                ja4,
			"ip.ja4_r":              ja4r,
			"ip.ja4_o":              ja4o,
			"ip.ja4h":               ja4h,
			"ip.country":            country,
			"ip.asn":                asn,
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
			"proxy.cloudflare":    proxy.Cloudflare,
			"proxy.stage_locked":  domainData.StageManuallySet,
			"proxy.attack":        domainData.RawAttack,
			"proxy.bypass_attack": domainData.BypassAttack,
			"proxy.rps":           domainData.RequestsPerSecond,
			"proxy.rps_allowed":   domainData.RequestsBypassedPerSecond,
		}

		susLv = firewall.EvalFirewallRule(domainSettings, requestVariables, susLv)
	}

	//Check if encryption-result is already "cached" to prevent load on reverse proxy
	encryptedIP := ""
	hashedEncryptedIP := ""
	susLvStr := utils.StageToString(susLv)
	accessKey := ip + tlsFp + reqUa + proxy.GetCurrHourStr()
	encryptedCache, encryptedExists := firewall.CacheIps.Load(accessKey + susLvStr)

	if !encryptedExists {
		switch susLv {
		case 0:
			//whitelisted
		case 1:
			encryptedIP = utils.Encrypt(accessKey, proxy.GetCookieOTP())
		case 2:
			encryptedIP = utils.Encrypt(accessKey, proxy.GetJSOTP())
			hashedEncryptedIP = utils.EncryptSha(encryptedIP, "")
			firewall.CacheIps.Store(encryptedIP, hashedEncryptedIP)
		case 3:
			encryptedIP = utils.Encrypt(accessKey, proxy.GetCaptchaOTP())
		default:
			writer.Header().Set("Content-Type", "text/plain")
			SendResponse("Blocked by LancarSec.\nSuspicious request of level "+susLvStr+" (base "+strconv.Itoa(domainData.Stage)+")", buffer, writer)
			return
		}
		firewall.CacheIps.Store(accessKey+susLvStr, encryptedIP)
	} else {
		encryptedIP = encryptedCache.(string)
		cachedHIP, foundCachedHIP := firewall.CacheIps.Load(encryptedIP)
		if foundCachedHIP {
			hashedEncryptedIP = cachedHIP.(string)
		}
	}

	//Check if client provided correct verification result
	if !hasValidChallengeCookie(request, encryptedIP) {

		firewall.Incr(firewall.WindowAccessIpsCookie, nowBucket, ip)
		// Per-IP escalation: a single client racking up cookie failures gets
		// its Stage 2 difficulty bumped individually so retry-loop bots pay
		// more CPU per attempt without affecting legitimate Stage 2 visitors
		// on the same domain. ipCountCookie was read before the Incr above,
		// so +1 reflects the count this very request just produced.
		firewall.BumpIPDifficultyOn(ip, ipCountCookie+1)

		//Respond with verification challenge if client didnt provide correct result/none
		switch susLv {
		case 0:
			//This request is not to be challenged (whitelist)
		case 1:
			// HttpOnly prevents the protected site's JavaScript from reading
			// the challenge token (XSS on the backend shouldn't bypass the
			// proxy's DDoS gate). Secure + SameSite=Lax reduce CSRF/MitM
			// exposure; this cookie is never read by client JS so HttpOnly
			// costs us nothing.
			writer.Header().Set("Set-Cookie", "_1__lSec_v="+encryptedIP+"; HttpOnly; SameSite=Lax; Path=/; Secure")
			http.Redirect(writer, request, request.URL.RequestURI(), http.StatusFound)
			return
		case 2:
			// Effective difficulty is the configured base, optionally
			// bumped by the monitor's adaptive logic in response to a
			// live bypass attack, AND optionally bumped further per-IP
			// when this client has a recent history of failing Stage 2.
			difficulty := firewall.EffectiveDifficulty(domainName, ip, domainData.Stage2Difficulty)
			publicSalt := encryptedIP[:len(encryptedIP)-difficulty]
			IncrChallengeJS()
			writer.Header().Set("Content-Type", "text/html; charset=utf-8")
			writer.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
			writer.Header().Set("X-Content-Type-Options", "nosniff")
			writer.Header().Set("X-Frame-Options", "DENY")
			writer.Header().Set("Referrer-Policy", "no-referrer")
			SendResponse(renderJSChallenge(publicSalt, hashedEncryptedIP, difficulty), buffer, writer)
			return
		case 3:
			secretPart := encryptedIP[:6]
			publicPart := encryptedIP[6:]

			captchaData, maskData, captchaExists := firewall.LoadCaptcha(secretPart)

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

				for i := 0; i < numTriangles; i++ {
					size := utils.RandomIntN(5) + 10
					x := utils.RandomIntN(captchaImg.Bounds().Dx() - size)
					y := utils.RandomIntN(captchaImg.Bounds().Dy() - size)
					blacklist = utils.DrawTriangle(blacklist, captchaImg, maskImg, x, y, size, randomShift)
				}

				var captchaBuf, maskBuf bytes.Buffer
				if err := png.Encode(&captchaBuf, captchaImg); err != nil {
					SendResponse("LancarSec Error: Failed to encode captcha: "+err.Error(), buffer, writer)
					return
				}
				if err := png.Encode(&maskBuf, maskImg); err != nil {
					SendResponse("LancarSec Error: Failed to encode captchaMask: "+err.Error(), buffer, writer)
					return
				}

				captchaData = base64.StdEncoding.EncodeToString(captchaBuf.Bytes())
				maskData = base64.StdEncoding.EncodeToString(maskBuf.Bytes())

				firewall.StoreCaptcha(secretPart, captchaData, maskData)
			}

			IncrChallengeCAP()
			writer.Header().Set("Content-Type", "text/html; charset=utf-8")
			writer.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
			writer.Header().Set("X-Content-Type-Options", "nosniff")
			writer.Header().Set("X-Frame-Options", "DENY")
			writer.Header().Set("Referrer-Policy", "no-referrer")
			SendResponse(renderCaptchaChallenge(ip, publicPart, captchaData, maskData), buffer, writer)
			return
		default:
			writer.Header().Set("Content-Type", "text/plain")
			SendResponse("Blocked by LancarSec.\nSuspicious request of level "+susLvStr, buffer, writer)
			return
		}
	}

	// Atomic Bypassed counter (no lock). Log append still needs DataMu because
	// it mutates a shared slice inside DomainsData.
	IncrForwarded()
	domains.CountersFor(domainName).Bypassed.Add(1)

	//Reserved proxy-paths

	switch request.URL.Path {
	case "/_lancarsec/stats":
		writer.Header().Set("Content-Type", "text/plain")
		SendResponse("Stage: "+utils.StageToString(domainData.Stage)+"\nTotal Requests: "+strconv.Itoa(domainData.TotalRequests)+"\nBypassed Requests: "+strconv.Itoa(domainData.BypassedRequests)+"\nTotal R/s: "+strconv.Itoa(domainData.RequestsPerSecond)+"\nBypassed R/s: "+strconv.Itoa(domainData.RequestsBypassedPerSecond)+"\nProxy Fingerprint: "+proxy.Fingerprint, buffer, writer)
		return
	case "/_lancarsec/fingerprint":
		writer.Header().Set("Content-Type", "text/plain")
		body := "IP: " + ip +
			"\nIP Requests: " + strconv.Itoa(ipCount) +
			"\nIP Challenge Requests: " + strconv.Itoa(ipCountCookie) +
			"\nSusLV: " + strconv.Itoa(susLv) +
			"\nIP Difficulty Bump: +" + strconv.Itoa(firewall.IPDifficultyBumpFor(ip)) +
			"\nFingerprint (legacy): " + tlsFp +
			"\nJA3: " + ja3 +
			"\nJA4: " + ja4 +
			"\nJA4_R: " + ja4r +
			"\nJA4_O: " + ja4o +
			"\nJA4H: " + ja4h +
			"\nBrowser: " + browser + botFp
		SendResponse(body, buffer, writer)
		return
	case "/_lancarsec/verified":
		writer.Header().Set("Content-Type", "text/plain")
		SendResponse("verified", buffer, writer)
		return
	case "/_lancarsec/credits":
		writer.Header().Set("Content-Type", "text/plain")
		SendResponse("LancarSec; Lightweight http reverse-proxy. Protected by GNU GENERAL PUBLIC LICENSE Version 2, June 1991", buffer, writer)
		return
	}

	// Strip LancarSec-internal cookies before forwarding so the backend never
	// sees the challenge token (it can't authenticate a user with it anyway,
	// and an XSSable backend that echoes cookies would otherwise leak it).
	stripProxyCookies(request)

	//Allow backend to read client information
	request.Header.Add("x-real-ip", ip)
	request.Header.Add("proxy-real-ip", ip)
	request.Header.Add("proxy-tls-fp", tlsFp)
	request.Header.Add("proxy-tls-ja4", ja4)
	if ja3 != "" {
		request.Header.Add("proxy-tls-ja3", ja3)
	}
	if ja4r != "" {
		request.Header.Add("proxy-tls-ja4-r", ja4r)
	}
	if ja4o != "" {
		request.Header.Add("proxy-tls-ja4-o", ja4o)
	}
	if ja4h != "" {
		request.Header.Add("proxy-http-ja4h", ja4h)
	}
	request.Header.Add("proxy-tls-name", browser+botFp)
	if asn != "" {
		request.Header.Add("proxy-client-asn", asn)
	}
	if country != "" {
		request.Header.Add("proxy-client-country", country)
	}

	domainSettings.DomainProxy.ServeHTTP(writer, request)
}
