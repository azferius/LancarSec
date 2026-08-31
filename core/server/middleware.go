package server

import (
	"bytes"
	"crypto/subtle"
	"encoding/base64"
	"github.com/azferius/lancarsec/core/api"
	"github.com/azferius/lancarsec/core/domains"
	"github.com/azferius/lancarsec/core/firewall"
	"github.com/azferius/lancarsec/core/proxy"
	"github.com/azferius/lancarsec/core/utils"
	"image"
	"image/color"
	"image/draw"
	"image/png"
	"math"
	"net"
	"net/http"
	"strconv"
	"strings"

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

	domainName := request.Host

	firewall.Mutex.RLock()
	domainData, domainFound := domains.DomainsData[domainName]
	firewall.Mutex.RUnlock()

	if !domainFound {
		writer.Header().Set("Content-Type", "text/plain")
		SendResponse("404 Not Found", buffer, writer)
		return
	}

	var ip string
	var tlsFp string
	var browser string
	var botFp string

	var fpCount int
	var ipCount int
	var ipCountCookie int

	if domains.Config.Proxy.Cloudflare {

		ip = request.Header.Get("Cf-Connecting-Ip")

		tlsFp = "Cloudflare"
		browser = "Cloudflare"
		botFp = ""
		fpCount = 0

		firewall.Mutex.RLock()
		ipCount = firewall.AccessIps[ip]
		ipCountCookie = firewall.AccessIpsCookie[ip]
		firewall.Mutex.RUnlock()
	} else {
		ip = strings.Split(request.RemoteAddr, ":")[0]

		//Retrieve information about the client
		firewall.Mutex.RLock()
		tlsFp = firewall.Connections[request.RemoteAddr]
		fpCount = firewall.UnkFps[tlsFp]
		ipCount = firewall.AccessIps[ip]
		ipCountCookie = firewall.AccessIpsCookie[ip]
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
	firewall.WindowAccessIps[proxy.Last10SecondTimestamp][ip]++
	domainData = domains.DomainsData[domainName]
	domainData.TotalRequests++
	domains.DomainsData[domainName] = domainData
	firewall.Mutex.Unlock()

	writer.Header().Set("baloo-Proxy", "1.5")

	//Start the suspicious level where the stage currently is
	susLv := domainData.Stage

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

	//Block user-specified fingerprints
	forbiddenFp := firewall.ForbiddenFingerprints[tlsFp]
	if forbiddenFp != "" {
		writer.Header().Set("Content-Type", "text/plain")
		SendResponse("Blocked by BalooProxy.\nYour browser "+forbiddenFp+" is not allowed.", buffer, writer)
		return
	}

	//Demonstration of how to use "susLv". Essentially allows you to challenge specific requests with a higher challenge

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

	if len(domainSettings.CustomRules) != 0 {
		requestVariables := gofilter.Message{
			"ip.src":                net.ParseIP(ip),
			"ip.engine":             browser,
			"ip.bot":                botFp,
			"ip.fingerprint":        tlsFp,
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

		firewall.Mutex.Lock()
		firewall.WindowAccessIpsCookie[proxy.Last10SecondTimestamp][ip]++
		firewall.Mutex.Unlock()

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
		SendResponse("IP: "+ip+"\nIP Requests: "+strconv.Itoa(ipCount)+"\nIP Challenge Requests: "+strconv.Itoa(ipCountCookie)+"\nSusLV: "+strconv.Itoa(susLv)+"\nFingerprint: "+tlsFp+"\nBrowser: "+browser+botFp, buffer, writer)
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

	//Allow backend to read client information
	request.Header.Add("x-real-ip", ip)
	request.Header.Add("proxy-real-ip", ip)
	request.Header.Add("proxy-tls-fp", tlsFp)
	request.Header.Add("proxy-tls-name", browser+botFp)

	domainSettings.DomainProxy.ServeHTTP(writer, request)
}
