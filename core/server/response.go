package server

// Response plumbing shared by every proxy-generated page. Split out of
// middleware.go (wave 9 W2, QUAL-03): this file owns HOW the proxy answers;
// middleware.go owns what is decided.

import (
	"bytes"
	"crypto/subtle"
	"net/http"

	"github.com/azferius/lancarsec/core/proxy"
)

func SendResponse(str string, buffer *bytes.Buffer, writer http.ResponseWriter) {
	buffer.WriteString(str)
	writer.Write(buffer.Bytes())
}

// setProxyPageHeaders applies the security headers every proxy-generated page
// carries. It must be called at each proxy-generated response site, NEVER once
// at the top of Middleware: httputil.ReverseProxy ADDS the backend's response
// headers to the writer without clearing what the handler already set, so a
// header set globally would leak onto responses that were proxied to a customer
// backend. Proxied responses keep exactly the headers the backend chose.
//
// WAVE 9: no CSP is set deliberately. The challenge pages run inline scripts -
// stage 2's solver and stage 3's captcha logic ARE the challenge - so any real
// CSP would need 'unsafe-inline' and would be security theater: a header that
// reads as protection while permitting the exact execution it names.
func setProxyPageHeaders(writer http.ResponseWriter) {
	header := writer.Header()
	header.Set("X-Content-Type-Options", "nosniff")
	header.Set("X-Frame-Options", "DENY")
	header.Set("Referrer-Policy", "no-referrer")
}

// SendResponseWithStatus is SendResponse for every proxy-generated response
// that is not one of the legitimate 200 bodies (the challenge pages, the
// verified/stats/credits/fingerprint reports): it sends the security headers,
// Cache-Control: no-store and a REAL status code ahead of the body.
//
// WAVE 9: SendResponse never calls WriteHeader, so every block, ratelimit and
// unknown-domain page left the proxy as a cacheable 200 OK - a shared CDN
// poisons itself with "this site is blocked" for every later visitor of the
// same URL. Callers that need a Content-Type still set it themselves
// beforehand, exactly as they did; 429 call sites set Retry-After alongside it.
func SendResponseWithStatus(status int, str string, buffer *bytes.Buffer, writer http.ResponseWriter) {
	setProxyPageHeaders(writer)
	writer.Header().Set("Cache-Control", "no-store")
	writer.WriteHeader(status)
	buffer.WriteString(str)
	writer.Write(buffer.Bytes())
}

// The paths the vendored stage-2 proof-of-work bundle is served from.
const (
	powBalooPowPath = "/_bProxy/balooPow.min.js"
	powCryptoJSPath = "/_bProxy/crypto-js.min.js"
)

// servePowAsset writes one of the embedded stage-2 scripts byte for byte.
//
// WAVE 9: the stage-2 page used to load balooPow from cdn.jsdelivr.net and
// crypto-js from cdnjs - mutable third-party references with no SRI. If either
// CDN was unreachable or mutated, stage 2 was dead for every challenged
// visitor mid-attack, and every challenged visitor's IP leaked to two third
// parties. The scripts are now compiled into the binary (global/pow) and
// served from paths this proxy controls.
func servePowAsset(writer http.ResponseWriter, asset []byte) {
	header := writer.Header()
	header.Set("Content-Type", "text/javascript")
	header.Set("Cache-Control", "public, max-age=31536000, immutable")
	setProxyPageHeaders(writer)
	writer.Write(asset)
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
	SendResponseWithStatus(http.StatusNotFound, "404 Not Found", buffer, writer)
}
