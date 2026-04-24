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
	peer := remote
	if host, _, err := net.SplitHostPort(remote); err == nil {
		peer = host
	}

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

	if !domainFound {
		writer.Header().Set("Content-Type", "text/plain")
		SendResponse("404 Not Found", buffer, writer)
		return
	}

	// Reject CONNECT outright. httputil.ReverseProxy would otherwise tunnel
	// it, turning LancarSec into an open HTTP proxy for attackers hopping to
	// arbitrary destinations.
	if request.Method == http.MethodConnect {
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

	var ip string
	var tlsFp string
	var ja4 string
	var browser string
	var botFp string

	var fpCount int
	var ipCount int
	var ipCountCookie int

	ip = realClientIP(request)

	if domains.LoadConfig().Proxy.Cloudflare {

		// Enforce that the socket peer is in the trusted proxy list. Anyone
		// reaching the origin directly (discovered the IP, bypassed CF) gets
		// a 403 instead of being served. realClientIP already honors CF
		// headers only for trusted peers; this flag makes the untrusted path
		// a hard block rather than a fallback to RemoteAddr.
		if proxy.CloudflareEnforceOrigin {
			peer := request.RemoteAddr
			if h, _, err := net.SplitHostPort(peer); err == nil {
				peer = h
			}
			if !trusted.IsTrusted(peer) {
				writer.Header().Set("Content-Type", "text/plain")
				writer.WriteHeader(http.StatusForbidden)
				SendResponse("Blocked by LancarSec.\nDirect origin access is not allowed; connect via Cloudflare.", buffer, writer)
				return
			}
		}

		tlsFp = "Cloudflare"
		// If Cloudflare Enterprise is enabled with TLS fingerprinting add-on,
		// it forwards the client JA3 here. Otherwise the sentinel stays.
		if ja3 := request.Header.Get("Cf-Ja3-Hash"); ja3 != "" {
			ja4 = "cf:" + ja3
		} else {
			ja4 = "Cloudflare"
		}
		browser = "Cloudflare"
		botFp = ""
		fpCount = 0

		firewall.CountersMu.RLock()
		ipCount = firewall.SumWindow(firewall.WindowAccessIps, ip, proxy.RatelimitWindow, proxy.LastSecondTimestamp)
		ipCountCookie = firewall.SumWindow(firewall.WindowAccessIpsCookie, ip, proxy.RatelimitWindow, proxy.LastSecondTimestamp)
		firewall.CountersMu.RUnlock()
	} else {
		if v, ok := firewall.Connections.Load(request.RemoteAddr); ok {
			tlsFp = v.(string)
		}
		if v, ok := firewall.JA4s.Load(request.RemoteAddr); ok {
			ja4 = v.(string)
		}

		firewall.CountersMu.RLock()
		fpCount = firewall.SumWindow(firewall.WindowUnkFps, tlsFp, proxy.RatelimitWindow, proxy.LastSecondTimestamp)
		ipCount = firewall.SumWindow(firewall.WindowAccessIps, ip, proxy.RatelimitWindow, proxy.LastSecondTimestamp)
		ipCountCookie = firewall.SumWindow(firewall.WindowAccessIpsCookie, ip, proxy.RatelimitWindow, proxy.LastSecondTimestamp)
		firewall.CountersMu.RUnlock()

		// Atomic pointer lookups — safe to read concurrently with config
		// reload, which swaps the published map rather than mutating it.
		browser = firewall.LookupKnown(tlsFp)
		botFp = firewall.LookupBot(tlsFp)
	}

	// Bounded counter bump. Incr drops the increment if the per-bucket key
	// count has hit the cap — an attacker flooding with fresh IPs can't
	// balloon the window map.
	firewall.Incr(firewall.WindowAccessIps, proxy.Last10SecondTimestamp, ip)

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

	// WebSocket: require at least Stage 2 (JS PoW) so a long-lived socket
	// can't be opened by a bot that only passes a cookie-level challenge.
	if isWebsocket && susLv < 2 {
		susLv = 2
	}

	//Ratelimit faster if client repeatedly fails the verification challenge (feel free to play around with the threshhold)
	if ipCountCookie > proxy.FailChallengeRatelimit {
		writer.Header().Set("Content-Type", "text/plain")
		SendResponse("Blocked by LancarSec.\nYou have been ratelimited. (R1)", buffer, writer)
		return
	}

	//Ratelimit spamming Ips (feel free to play around with the threshhold)
	if ipCount > proxy.IPRatelimit {
		writer.Header().Set("Content-Type", "text/plain")
		SendResponse("Blocked by LancarSec.\nYou have been ratelimited. (R2)", buffer, writer)
		return
	}

	//Ratelimit fingerprints that don't belong to major browsers
	if browser == "" {
		if fpCount > proxy.FPRatelimit {
			writer.Header().Set("Content-Type", "text/plain")
			SendResponse("Blocked by LancarSec.\nYou have been ratelimited. (R3)", buffer, writer)
			return
		}

		firewall.Incr(firewall.WindowUnkFps, proxy.Last10SecondTimestamp, tlsFp)
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
	settingsQuery, _ := domains.DomainsMap.Load(domainName)
	domainSettings := settingsQuery.(domains.DomainSettings)

	reqUa := request.UserAgent()

	if len(domainSettings.CustomRules) != 0 {
		requestVariables := gofilter.Message{
			"ip.src":                net.ParseIP(ip),
			"ip.engine":             browser,
			"ip.bot":                botFp,
			"ip.fingerprint":        tlsFp,
			"ip.ja4":                ja4,
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
	accessKey := ip + tlsFp + reqUa + proxy.CurrHourStr
	encryptedCache, encryptedExists := firewall.CacheIps.Load(accessKey + susLvStr)

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

		firewall.Incr(firewall.WindowAccessIpsCookie, proxy.Last10SecondTimestamp, ip)

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
			publicSalt := encryptedIP[:len(encryptedIP)-domainData.Stage2Difficulty]
			writer.Header().Set("Content-Type", "text/html; charset=utf-8")
			writer.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
			writer.Header().Set("X-Content-Type-Options", "nosniff")
			writer.Header().Set("X-Frame-Options", "DENY")
			writer.Header().Set("Referrer-Policy", "no-referrer")
			SendResponse(renderJSChallenge(publicSalt, hashedEncryptedIP, domainData.Stage2Difficulty), buffer, writer)
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
	domains.CountersFor(domainName).Bypassed.Add(1)
	firewall.DataMu.Lock()
	utils.AddLogs(domains.DomainLog{
		Time:      proxy.LastSecondTimeFormated,
		IP:        ip,
		BrowserFP: browser,
		BotFP:     botFp,
		TLSFP:     tlsFp,
		Useragent: reqUa,
		Path:      request.RequestURI,
	}, domainName)
	firewall.DataMu.Unlock()

	//Reserved proxy-paths

	switch request.URL.Path {
	case "/_lancarsec/stats":
		writer.Header().Set("Content-Type", "text/plain")
		SendResponse("Stage: "+utils.StageToString(domainData.Stage)+"\nTotal Requests: "+strconv.Itoa(domainData.TotalRequests)+"\nBypassed Requests: "+strconv.Itoa(domainData.BypassedRequests)+"\nTotal R/s: "+strconv.Itoa(domainData.RequestsPerSecond)+"\nBypassed R/s: "+strconv.Itoa(domainData.RequestsBypassedPerSecond)+"\nProxy Fingerprint: "+proxy.Fingerprint, buffer, writer)
		return
	case "/_lancarsec/fingerprint":
		writer.Header().Set("Content-Type", "text/plain")
		SendResponse("IP: "+ip+"\nIP Requests: "+strconv.Itoa(ipCount)+"\nIP Challenge Requests: "+strconv.Itoa(ipCountCookie)+"\nSusLV: "+strconv.Itoa(susLv)+"\nFingerprint: "+tlsFp+"\nBrowser: "+browser+botFp, buffer, writer)
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

	// Admin API v1: secret moved from URL path (where it ends up in access
	// logs, referers, and CDN caches) to a required Admin-Secret header.
	// Handler only runs if the header matches in constant time.
	if request.URL.Path == "/_lancarsec/api/v1" {
		if subtle.ConstantTimeCompare([]byte(request.Header.Get("Admin-Secret")), []byte(proxy.AdminSecret)) == 1 {
			if api.Process(writer, request, domainData) {
				return
			}
		}
	}

	if strings.HasPrefix(request.URL.Path, "/_lancarsec/api/v2") {
		if api.ProcessV2(writer, request) {
			return
		}
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
	request.Header.Add("proxy-tls-name", browser+botFp)

	domainSettings.DomainProxy.ServeHTTP(writer, request)
}
