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
	"html/template"
	"log"
	"net/http"
	"strconv"
	"strings"
)

// proxyCookieSuffix is the shared suffix of every challenge cookie the proxy
// issues: "_1"+suffix for stage 1, "_2"+suffix for stage 2 and "_3"+suffix
// for stage 3.
//
// WAVE 10 rebrand: the token was renamed from "__bProxy_v" to "__lSec_v",
// which by itself invalidates every clearance cookie in flight. To keep the
// cutover from challenging every established client, legacyProxyCookieSuffix
// below is still ACCEPTED for one release (issued never).
const proxyCookieSuffix = "__lSec_v"

// legacyProxyCookieSuffix is the pre-rebrand cookie token. One release of
// grace: a client presenting it is verified and immediately re-issued the new
// name, and stripProxyCookies strips it from every forwarded request either
// way. Remove this const (and its use sites) one release after the cutover.
const legacyProxyCookieSuffix = "__bProxy_v"

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
		// The PoW page renders this name into its document.cookie call (the
		// shared stage-2/stage-3 template), so the two can never drift apart.
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
	// WAVE 9: the stage-3 name the proxy issues ("_3__lSec_v") is itself a
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

// carriesProxyToken reports whether a raw Cookie header or a single cookie
// NAME carries one of the proxy's clearance tokens - current or legacy. The
// match is a substring test BY DESIGN here: it is what stripProxyCookies and
// the verify grace use to catch a token under ANY prefix, and neither site
// uses it to decide what a request is.
//
// WAVE 10: the legacy arm goes away with legacyProxyCookieSuffix.
func carriesProxyToken(s string) bool {
	return strings.Contains(s, proxyCookieSuffix) || strings.Contains(s, legacyProxyCookieSuffix)
}

// legacyCookieNames returns the pre-rebrand cookie NAMES a challenged client
// may still present for susLv, in lookup order. The proxy never issues these
// any more; they exist only for the one-release verify grace. Legacy stage-3
// cookies predate wave 9, so the name may embed the raw client ip - the ip is
// passed in and both spellings are offered. The constant-time compare at the
// verify site gates the VALUE either way.
//
// WAVE 10: remove this helper with legacyProxyCookieSuffix.
func legacyCookieNames(susLv int, ip string) []string {
	switch susLv {
	case 1:
		return []string{"_1" + legacyProxyCookieSuffix}
	case 2:
		return []string{"_2" + legacyProxyCookieSuffix}
	case 3:
		names := []string{"_3" + legacyProxyCookieSuffix}
		if ip != "" {
			return append(names, ip+"_3"+legacyProxyCookieSuffix)
		}
		return names
	default:
		return nil
	}
}

// reissueClearanceCookie re-writes the CURRENT name for susLv with the token
// the client just proved via a legacy cookie, so an established client
// migrates off the old name during the grace release instead of carrying it
// forever. Stage 1 gets HttpOnly (the proxy is its only reader); stages 2 and
// 3 cannot - the challenge pages rewrite those names from script, and a
// browser refuses to let script set an HttpOnly cookie - so they are written
// exactly as the pages write them.
//
// WAVE 10: remove this helper with legacyProxyCookieSuffix.
func reissueClearanceCookie(writer http.ResponseWriter, susLv int, encryptedIP string) {
	if susLv < 1 || susLv > 3 || encryptedIP == "" {
		return
	}
	cookie := challengeCookieName(susLv) + "=" + encryptedIP + "; SameSite=Lax; path=/; Secure"
	if susLv == 1 {
		cookie += "; HttpOnly"
	}
	writer.Header().Add("Set-Cookie", cookie)
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
		if !carriesProxyToken(header) {
			rewritten = append(rewritten, header)
			continue
		}

		changed = true
		pairs := strings.Split(header, ";")
		kept := make([]string, 0, len(pairs))
		for _, pair := range pairs {
			pair = strings.TrimSpace(pair)
			cookieName, _, _ := strings.Cut(pair, "=")
			// Matched on a suffix, not on equality: "_1__lSec_v", the legacy
			// "_1__bProxy_v" and any other prefix an attacker invents all
			// carry a proxy token and all have to go.
			if carriesProxyToken(cookieName) {
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

// stage2PageData carries every value a proof-of-work challenge page
// interpolates. All strings are server-derived: PublicSalt and Challenge are
// blake3 hex, CookieName comes from challengeCookieName, the paths are this
// file's own consts. Difficulty is rendered as a bare JS numeric literal:
// html/template's JS-value escaper pads numbers with spaces (" 5 "), which
// would change the page byte-for-byte, so the call site passes strconv.Itoa's
// output as template.JS - verbatim, and safe because it can only ever be
// decimal digits.
type stage2PageData struct {
	CookieName   string
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
var stage2Page = template.Must(template.New("stage2").Parse(`<!doctypehtml><html lang=en><meta charset=UTF-8><meta content="width=device-width,initial-scale=1"name=viewport><title>Completing challenge ...</title><style>body,html{height:100%;width:100%;margin:0;display:flex;flex-direction:column;justify-content:center;align-items:center;background-color:#f0f0f0;font-family:Arial,sans-serif}.loader{display:flex;justify-content:space-around;align-items:center;width:100px;height:100px}.loader div{width:20px;height:20px;background-color:#333;border-radius:50%;animation:bounce .6s infinite alternate}.loader div:nth-child(2){animation-delay:.2s}.loader div:nth-child(3){animation-delay:.4s}@keyframes bounce{to{transform:translateY(-30px)}}.message{text-align:center;margin-top:20px;color:#333}.subtext{text-align:center;color:#666;font-size:.9em;margin-top:5px}.placeholder-container{width:25%;text-align:center;margin:10px 0}.placeholder-label{font-weight:700;margin-bottom:5px}.placeholder{background-color:#e0e0e0;padding:10px;border-radius:5px;word-break:break-all;font-family:monospace;cursor:pointer;}</style><div class=loader><div></div><div></div><div></div></div><div class=message><p>Completing challenge ...<div class=subtext>The process is automatic and shouldn't take too long. Please be patient.</div></div><div class=placeholder-container><div class=placeholder-label>publicSalt:</div><div class=placeholder id=publicSalt onclick='ctc("publicSalt")'><span>{{.PublicSalt}}</span></div></div><div class=placeholder-container><div class=placeholder-label>challenge:</div><div class=placeholder id=challenge onclick='ctc("challenge")'><span>{{.Challenge}}</span></div></div><script>function ctc(t){navigator.clipboard.writeText(document.getElementById(t).innerText)}</script><script src="{{.BalooPowPath}}"></script><script src="{{.CryptoJSPath}}"></script><script>function solved(e){document.cookie="{{.CookieName}}={{.PublicSalt}}"+e.solution+"; SameSite=Lax; path=/; Secure",location.href=location.href}new BalooPow("{{.PublicSalt}}",{{.Difficulty}},"{{.Challenge}}",!1).Solve().then(e=>{if(e.match == ""){solved(e)}else alert("Navigator Missmatch ("+e.match+"). Please contact @ddosmitigation")});</script>`))

// serveStage2Challenge presents the stage-2 proof-of-work page.
func serveStage2Challenge(writer http.ResponseWriter, buffer *bytes.Buffer, publicSalt, hashedEncryptedIP string, difficulty int) {
	renderPowChallenge(writer, buffer, challengeCookieName(2), publicSalt, hashedEncryptedIP, difficulty)
}

// renderPowChallenge renders the shared proof-of-work page for the given
// challenge cookie name. Stage 2 and stage 3 run the exact same solver; the
// stage-3 call site passes a difficulty one higher and its own cookie name.
func renderPowChallenge(writer http.ResponseWriter, buffer *bytes.Buffer, cookieName, publicSalt, hashedEncryptedIP string, difficulty int) {
	writer.Header().Set("Content-Type", "text/html")
	writer.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0") // Prevent special(ed) browsers from caching the challenge
	setProxyPageHeaders(writer)
	err := stage2Page.Execute(buffer, stage2PageData{
		CookieName:   cookieName,
		PublicSalt:   publicSalt,
		Challenge:    hashedEncryptedIP,
		Difficulty:   template.JS(strconv.Itoa(difficulty)),
		BalooPowPath: powAssetPath,
		CryptoJSPath: powCryptoJSPath,
	})
	if err != nil {
		// Unreachable with these value types, but a half-rendered page must
		// never leave as 200.
		buffer.Reset()
		log.Printf("LancarSec: failed to render proof-of-work challenge page: %v", err)
		writer.Header().Set("Content-Type", "text/plain")
		SendResponseWithStatus(http.StatusInternalServerError, "500 Internal Server Error", buffer, writer)
		return
	}
	writer.Write(buffer.Bytes())
}

// serveStage3Challenge presents the stage-3 proof-of-work page.
//
// WAVE 11 (CRYPTO-03): stage 3 used to be a home-grown canvas captcha whose
// answer was the secret 24 bits of the token, handed to the client inside the
// PNG. That is not a secret: a solver reads the image, and the token's other
// 40 hex chars were already public on the page. Stage 3 now reuses the exact
// stage-2 proof-of-work machinery - same vendored solver, same page - with
// the difficulty one higher, so escalation buys a strictly harder hash
// puzzle instead of a picture. The cookie check in middleware is unchanged:
// the page still sets the full token under challengeCookieName(3).
func serveStage3Challenge(writer http.ResponseWriter, buffer *bytes.Buffer, encryptedIP, hashedEncryptedIP string, stage2Difficulty int) {
	difficulty := stage2Difficulty + 1
	publicSalt := encryptedIP[:len(encryptedIP)-difficulty]
	renderPowChallenge(writer, buffer, challengeCookieName(3), publicSalt, hashedEncryptedIP, difficulty)
}
