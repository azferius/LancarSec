package server

// Challenge cookies and the three challenge responders. Split out of
// middleware.go (wave 9 W2, QUAL-03): this file owns what a challenged client
// is SENT; middleware.go owns whether he is challenged at all.
//
// WAVE 9 W2: the stage-2 and stage-3 pages are rendered by html/template. The
// old page literals interpolated values through hand-rolled escapeHTML /
// escapeJSString calls, which is correct today but puts the burden on every
// future edit to remember to escape; the template engine derives the correct
// escaping per position (HTML text, JS string literal, JS value) from the
// markup itself, so a forgotten escape is no longer expressible. The
// interpolated values are all server-derived (blake3 hex, the captcha PNGs'
// base64, a fixed cookie name); every test-pinned byte for hex values is
// unchanged, because no escaper rewrites [0-9a-f].

import (
	"bytes"
	"encoding/base64"
	"html/template"
	"image"
	"image/color"
	"image/draw"
	"image/png"
	"log"
	"math"
	"net/http"
	"strconv"
	"strings"

	"github.com/azferius/lancarsec/core/firewall"
	"github.com/azferius/lancarsec/core/utils"
)

// proxyCookieSuffix is the shared suffix of every challenge cookie the proxy
// issues: "_1"+suffix for stage 1, "_2"+suffix for stage 2 and
// "<ip>_3"+suffix for stage 3. Renaming this token is wave 10's job - it
// invalidates every clearance cookie in flight - so it stays spelled exactly
// as it is on the wire today.
const proxyCookieSuffix = "__bProxy_v"

// challengeCookieName is the name of the cookie a client is expected to
// present for a given suspicion level. Levels with no challenge (0, and
// anything from 4 up, which is a hard block) have no cookie and return "".
//
// WAVE 9: the stage-3 name no longer embeds the client ip. An IPv6 ip carries
// ':', and browsers reject ':' in document.cookie NAMES - the stage-3 page
// writes this cookie from JavaScript - so stage 3 was unsolvable for every
// IPv6 client. Binding the token to the ip is NOT lost: the token VALUE is
// length-prefix encoded over (v1, domain, ip, fingerprint, user agent, hour)
// as of wave 5, so a token still clears exactly the identity it was minted
// for. Stage-3 cookies issued before this change no longer match the name the
// proxy expects; every affected client is re-challenged once.
func challengeCookieName(susLv int) string {
	switch susLv {
	case 1:
		return "_1" + proxyCookieSuffix
	case 2:
		return "_2" + proxyCookieSuffix
	case 3:
		// The stage-3 page writes this name from JavaScript; see the
		// document.cookie call in the stage-3 template below, which derives
		// the name from THIS function so the two can never drift apart.
		return "_3" + proxyCookieSuffix
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
	// token, and a cookie name is client-chosen junk the moment an attacker
	// invents one. So fall back to walking the header ourselves rather than
	// letting a name that does not parse as a token hide a presented cookie.
	// WAVE 9: the stage-3 name the proxy issues ("_3__bProxy_v") is itself a
	// valid token now that it no longer embeds the client ip, so the primary
	// request.Cookie lookup covers it; the walk remains for exact-match
	// robustness and is still never a substring test.
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

// ---------------------------------------------------------------------------
// stage responders
// ---------------------------------------------------------------------------

// serveStage1Challenge issues the stage-1 clearance cookie and bounces the
// client back onto the same URL to replay it.
func serveStage1Challenge(writer http.ResponseWriter, request *http.Request, buffer *bytes.Buffer, encryptedIP string) {
	// WAVE 9: refuse any request-target that is not clean origin-form.
	// A protocol-relative target like "GET //evil.com/ HTTP/1.1" parses
	// (viaRequest, no scheme) with the '//' left in Path and Host empty
	// - url.ParseRequestURI never reads a scheme-less '//' as an
	// authority - so RequestURI() returns "//evil.com/", and
	// http.Redirect re-parses THAT string with url.Parse, which DOES
	// read '//' as an authority and skips its relative-URL fixup:
	// Location: //evil.com/ is emitted verbatim, an open redirect off
	// the protected site. Absolute-form targets (URL.Host set) are
	// refused too; only a relative URI reaches the redirect below.
	if request.URL.Host != "" || strings.HasPrefix(request.URL.Path, "//") {
		writer.Header().Set("Content-Type", "text/plain")
		SendResponseWithStatus(http.StatusBadRequest, "400 Bad Request", buffer, writer)
		return
	}
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
	setProxyPageHeaders(writer)
	writer.Header().Set("Cache-Control", "no-store")
	http.Redirect(writer, request, request.URL.RequestURI(), http.StatusFound)
}

// stage2PageData carries every value the stage-2 proof-of-work page
// interpolates. All strings are server-derived: PublicSalt and Challenge are
// blake3 hex, the paths are this file's own consts. Difficulty is rendered as
// a bare JS numeric literal: html/template's JS-value escaper pads numbers
// with spaces (" 5 "), which would change the page byte-for-byte, so the call
// site passes strconv.Itoa's output as template.JS - verbatim, and safe
// because it can only ever be decimal digits.
type stage2PageData struct {
	PublicSalt   string
	Challenge    string
	Difficulty   template.JS
	BalooPowPath string
	CryptoJSPath string
}

// stage2Page is the stage-2 proof-of-work page. html/template applies
// context-aware escaping at every action: HTML text inside the <span>
// placeholders, JS string literals inside the solver, a bare JS value for the
// difficulty.
//
// WAVE 9: both scripts are vendored (global/pow) and served first-party via
// BalooPowPath/CryptoJSPath; they used to be mutable CDN references with no
// SRI that neutered stage 2 when the CDN was unavailable.
var stage2Page = template.Must(template.New("stage2").Parse(`<!doctypehtml><html lang=en><meta charset=UTF-8><meta content="width=device-width,initial-scale=1"name=viewport><title>Completing challenge ...</title><style>body,html{height:100%;width:100%;margin:0;display:flex;flex-direction:column;justify-content:center;align-items:center;background-color:#f0f0f0;font-family:Arial,sans-serif}.loader{display:flex;justify-content:space-around;align-items:center;width:100px;height:100px}.loader div{width:20px;height:20px;background-color:#333;border-radius:50%;animation:bounce .6s infinite alternate}.loader div:nth-child(2){animation-delay:.2s}.loader div:nth-child(3){animation-delay:.4s}@keyframes bounce{to{transform:translateY(-30px)}}.message{text-align:center;margin-top:20px;color:#333}.subtext{text-align:center;color:#666;font-size:.9em;margin-top:5px}.placeholder-container{width:25%;text-align:center;margin:10px 0}.placeholder-label{font-weight:700;margin-bottom:5px}.placeholder{background-color:#e0e0e0;padding:10px;border-radius:5px;word-break:break-all;font-family:monospace;cursor:pointer;}</style><div class=loader><div></div><div></div><div></div></div><div class=message><p>Completing challenge ...<div class=subtext>The process is automatic and shouldn't take too long. Please be patient.</div></div><div class=placeholder-container><div class=placeholder-label>publicSalt:</div><div class=placeholder id=publicSalt onclick='ctc("publicSalt")'><span>{{.PublicSalt}}</span></div></div><div class=placeholder-container><div class=placeholder-label>challenge:</div><div class=placeholder id=challenge onclick='ctc("challenge")'><span>{{.Challenge}}</span></div></div><script>function ctc(t){navigator.clipboard.writeText(document.getElementById(t).innerText)}</script><script src="{{.BalooPowPath}}"></script><script src="{{.CryptoJSPath}}"></script><script>function solved(e){document.cookie="_2__bProxy_v={{.PublicSalt}}"+e.solution+"; SameSite=Lax; path=/; Secure",location.href=location.href}new BalooPow("{{.PublicSalt}}",{{.Difficulty}},"{{.Challenge}}",!1).Solve().then(e=>{if(e.match == ""){solved(e)}else alert("Navigator Missmatch ("+e.match+"). Please contact @ddosmitigation")});</script>`))

// serveStage2Challenge presents the stage-2 proof-of-work page.
func serveStage2Challenge(writer http.ResponseWriter, buffer *bytes.Buffer, publicSalt, hashedEncryptedIP string, difficulty int) {
	writer.Header().Set("Content-Type", "text/html")
	writer.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0") // Prevent special(ed) browsers from caching the challenge
	setProxyPageHeaders(writer)
	err := stage2Page.Execute(buffer, stage2PageData{
		PublicSalt:   publicSalt,
		Challenge:    hashedEncryptedIP,
		Difficulty:   template.JS(strconv.Itoa(difficulty)),
		BalooPowPath: powBalooPowPath,
		CryptoJSPath: powCryptoJSPath,
	})
	if err != nil {
		// Unreachable with these value types, but a half-rendered page must
		// never leave as 200.
		buffer.Reset()
		log.Printf("BalooProxy: failed to render stage-2 challenge page: %v", err)
		writer.Header().Set("Content-Type", "text/plain")
		SendResponseWithStatus(http.StatusInternalServerError, "500 Internal Server Error", buffer, writer)
		return
	}
	writer.Write(buffer.Bytes())
}

// serveStage3Challenge presents the stage-3 captcha. It draws, encodes and
// caches the captcha/mask pair on a cache miss and renders the page.
func serveStage3Challenge(writer http.ResponseWriter, buffer *bytes.Buffer, encryptedIP string) {
	secretPart := encryptedIP[:6]
	publicPart := encryptedIP[6:]

	captchaData := ""
	maskData := ""
	// WAVE 11: the cache is keyed on the FULL token, not secretPart. Six hex
	// chars are 24 bits - birthday collisions start around 4000 concurrent
	// stage-3 clients, and a collision served client B the PNG carrying
	// client A's complete token. The full token is blake3 hex of the access
	// key, so it is collision-free as a key.
	captchaCache, captchaExists := firewall.CacheImgs.Load(encryptedIP)

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
			// WAVE 9: the internal error string used to be echoed to
			// the client. The client gets a generic 500 with no
			// internal detail; the cause goes to the log, consistent
			// with the stdlib-log pattern used elsewhere in this tree.
			log.Printf("BalooProxy: failed to encode stage-3 captcha image: %v", err)
			writer.Header().Set("Content-Type", "text/plain")
			SendResponseWithStatus(http.StatusInternalServerError, "500 Internal Server Error", buffer, writer)
			return
		}
		if err := png.Encode(&maskBuf, maskImg); err != nil {
			log.Printf("BalooProxy: failed to encode stage-3 captcha mask: %v", err)
			writer.Header().Set("Content-Type", "text/plain")
			SendResponseWithStatus(http.StatusInternalServerError, "500 Internal Server Error", buffer, writer)
			return
		}

		captchaData = base64.StdEncoding.EncodeToString(captchaBuf.Bytes())
		maskData = base64.StdEncoding.EncodeToString(maskBuf.Bytes())

		firewall.CacheImgs.Store(encryptedIP, [2]string{captchaData, maskData})
	} else {
		captchaDataTmp := captchaCache.([2]string)
		captchaData = captchaDataTmp[0]
		maskData = captchaDataTmp[1]
	}

	writer.Header().Set("Content-Type", "text/html")
	writer.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0") // Prevent special(ed) browsers from caching the challenge
	setProxyPageHeaders(writer)
	// WAVE 9: the stage-3 cookie NAME no longer embeds the client ip -
	// ':' in an IPv6 name is rejected by browsers, which made stage 3
	// unsolvable for IPv6 clients. The name is derived from
	// challengeCookieName so the page's document.cookie and the
	// server-side validation can never disagree; the token VALUE is
	// still bound to the ip via the access key (wave 5).
	stage3CookieName := challengeCookieName(3)
	err := stage3Page.Execute(buffer, stage3PageData{
		CookieName:  stage3CookieName,
		PublicPart:  publicPart,
		CaptchaData: captchaData,
		MaskData:    maskData,
	})
	if err != nil {
		buffer.Reset()
		log.Printf("BalooProxy: failed to render stage-3 challenge page: %v", err)
		writer.Header().Set("Content-Type", "text/plain")
		SendResponseWithStatus(http.StatusInternalServerError, "500 Internal Server Error", buffer, writer)
		return
	}
	writer.Write(buffer.Bytes())
}

// stage3PageData carries every value the stage-3 captcha page interpolates.
// CookieName is challengeCookieName(3); PublicPart is blake3 hex; the two PNG
// payloads are std-base64 - html/template's JS-string escaper rewrites their
// '+' and '/' (to \u002b and \/) and the browser decodes the very same
// strings.
type stage3PageData struct {
	CookieName  string
	PublicPart  string
	CaptchaData string
	MaskData    string
}

// stage3Page is the stage-3 captcha page; same escaping contract as stage2Page.
var stage3Page = template.Must(template.New("stage3").Parse(`<style>body{background-color:#f5f5f5;font-family:Arial,sans-serif}.center{display:flex;align-items:center;justify-content:center;height:100vh}.box{background-color:#fff;border:1px solid #ddd;border-radius:4px;padding:20px;width:500px}canvas{display:block;margin:0 auto;max-width:100%;width:100%;height:auto}input[type=text]{width:100%;padding:12px 20px;margin:8px 0;box-sizing:border-box;border:2px solid #ccc;border-radius:4px}button{width:100%;background-color:#4caf50;color:#fff;padding:14px 20px;margin:8px 0;border:none;border-radius:4px;cursor:pointer}button:hover{background-color:#45a049}.box{background-color:#fff;border:1px solid #ddd;border-radius:4px;padding:20px;width:500px;transition:height .1s;position:block}.box *{transition:opacity .1s}.success{background-color:#dff0d8;border:1px solid #d6e9c6;border-radius:4px;color:#3c763d;padding:20px}.failure{background-color:#f0d8d8;border:1px solid #e9c6c6;border-radius:4px;color:#763c3c;padding:20px}.collapsible{background-color:#f5f5f5;color:#444;cursor:pointer;padding:18px;width:100%;border:none;text-align:left;outline:0;font-size:15px}.collapsible:after{content:'\002B';color:#777;font-weight:700;float:right;margin-left:5px}.collapsible.active:after{content:"\2212"}.collapsible:hover{background-color:#e5e5e5}.collapsible-content{padding:0 18px;max-height:0;overflow:hidden;transition:max-height .2s ease-out;background-color:#f5f5f5}.captcha-wrapper{position:relative;width:100%;height:200px}.captcha-wrapper canvas{position:absolute}input[type=range]{-webkit-appearance:none;width:100%;height:25px;background:#ddd;outline:0;opacity:.7;transition:opacity .2s;border-radius:4px;margin:8px 0}input[type=range]:hover{opacity:1}input[type=range]::-webkit-slider-thumb{-webkit-appearance:none;appearance:none;width:25px;height:25px;background:#4caf50;cursor:pointer;border-radius:50%}input[type=range]::-moz-range-thumb{width:25px;height:25px;background:#4caf50;cursor:pointer;border-radius:50%}</style><div class=center id=center><div class=box id=box><h1>Drag the <b>slider</b> and enter the <b>green</b> text you see in the picture</h1><div class=captcha-wrapper><canvas height=37 id=captcha width=100></canvas><canvas height=37 id=mask width=100></canvas></div><input id=captcha-slider max=50 min=-50 type=range><form onsubmit="return checkAnswer(event)"><input id=text type=text maxlength=6 placeholder=Solution required> <button type=submit>Submit</button></form><div class=success id=successMessage style=display:none>Success! Redirecting ...</div><div class=failure id=failMessage style=display:none>Failed! Please try again.</div><button class=collapsible>Why am I seeing this page?</button><div class=collapsible-content><p>The website you are trying to visit needs to make sure that you are not a bot. This is a common security measure to protect websites from automated spam and abuse. By entering the characters you see in the picture, you are helping to verify that you are a real person.</div></div></div><script>let captcha_canvas=document.getElementById("captcha"),captcha_ctx=captcha_canvas.getContext("2d"),mask_canvas=document.getElementById("mask"),mask_ctx=mask_canvas.getContext("2d"),slider=document.getElementById("captcha-slider"),demo_slider=!1,demo_val=1;var i,captcha_image=new Image,mask_image=new Image;function checkAnswer(e){e.preventDefault();var a=document.getElementById("text").value;document.cookie="{{.CookieName}}="+a+"{{.PublicPart}}; SameSite=Lax; path=/; Secure",fetch("https://"+location.hostname+"/_bProxy/verified").then(function(e){return e.text()}).then(function(e){"verified"===e?(document.getElementById("successMessage").style.display="block",setInterval(function(){var e=document.getElementById("box"),a=e.offsetHeight,t=setInterval(function(){a-=20,e.style.height=a+"px";for(var c=e.children,s=0;s<c.length;s++)c[s].style.opacity=0;a<=0&&(e.style.height="0",e.remove(),clearInterval(t),location.href=location.href)},20)},1e3)):(document.getElementById("failMessage").style.display="block",setInterval(function(){location.href=location.href},1e3))}).catch(function(e){document.getElementById("failMessage").style.display="block",setInterval(function(){location.href=location.href},1e3)})}captcha_image.onload=function(){captcha_ctx.drawImage(captcha_image,(captcha_canvas.width-captcha_image.width)/2,(captcha_canvas.height-captcha_image.height)/2)},captcha_image.src="data:image/png;base64,{{.CaptchaData}}",mask_image.onload=function(){mask_ctx.drawImage(mask_image,(mask_canvas.width-mask_image.width)/2,(mask_canvas.height-mask_image.height)/2)},mask_image.src="data:image/png;base64,{{.MaskData}}";let demo_int=setInterval(()=>{if(!demo_slider){clearInterval(demo_int);return}slider.value<=-50&&(demo_val=1),slider.value>=50&&(demo_val=-1),slider.value=parseInt(slider.value)+demo_val,updateCaptcha()},50);function updateCaptcha(){let e=parseInt(slider.value);mask_ctx.clearRect(0,0,mask_canvas.width,mask_canvas.height),mask_ctx.drawImage(mask_image,(mask_canvas.width-mask_image.width)/2+e,0)}slider.oninput=function(){demo_slider=!1,updateCaptcha()};var coll=document.getElementsByClassName("collapsible");for(i=0;i<coll.length;i++)coll[i].addEventListener("click",function(){this.classList.toggle("active");var e=this.nextElementSibling;e.style.maxHeight?e.style.maxHeight=null:e.style.maxHeight=e.scrollHeight+"px"});</script>`))
