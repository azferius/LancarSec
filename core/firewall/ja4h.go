package firewall

import (
	"fmt"
	"net/http"
	"sort"
	"strings"
)

// ComputeJA4H produces a JA4H HTTP-request fingerprint per FoxIO spec.
// Format:
//
//	ja4h_a + "_" + ja4h_b + "_" + ja4h_c + "_" + ja4h_d
//
// ja4h_a:  <method:2><httpver:2><cookie:1><referer:1><headercount:4><lang:4>
// ja4h_b:  sha256[:12] of header names in order, excluding Cookie and Referer
// ja4h_c:  sha256[:12] of cookie names sorted alphabetically
// ja4h_d:  sha256[:12] of "name=value" cookie pairs sorted alphabetically
//
// Caveat: Go's http.Header is a map and does NOT preserve original header
// order, so ja4h_b is computed from a sorted header-name list (deterministic
// per-client but won't byte-match an external JA4H calculator). Capturing
// raw HTTP/1.1 request bytes via a peek-style listener — analogous to what
// peek.go does for TLS — would close that gap. Deferred for a later session.
//
// JA4H runs on every forwarded request, so the implementation avoids
// allocations on the fast path: header counting and language extraction
// are single-pass; sha256 happens once per call.
func ComputeJA4H(r *http.Request) string {
	method := strings.ToLower(r.Method)
	if len(method) >= 2 {
		method = method[:2]
	} else if len(method) == 1 {
		method = method + "0"
	} else {
		method = "00"
	}

	var ver string
	switch r.ProtoMajor*10 + r.ProtoMinor {
	case 10:
		ver = "10"
	case 11:
		ver = "11"
	case 20:
		ver = "20"
	case 30:
		ver = "30"
	default:
		ver = "00"
	}

	cookieFlag := "n"
	if r.Header.Get("Cookie") != "" {
		cookieFlag = "c"
	}
	referFlag := "n"
	if r.Header.Get("Referer") != "" {
		referFlag = "r"
	}

	headerNames := make([]string, 0, len(r.Header))
	for name := range r.Header {
		l := strings.ToLower(name)
		if l == "cookie" || l == "referer" {
			continue
		}
		headerNames = append(headerNames, l)
	}
	headerCount := len(headerNames)
	if headerCount > 9999 {
		headerCount = 9999
	}

	lang := primaryLang(r.Header.Get("Accept-Language"))

	a := fmt.Sprintf("%s%s%s%s%04d%s", method, ver, cookieFlag, referFlag, headerCount, lang)

	sort.Strings(headerNames)
	b := sha256First12(strings.Join(headerNames, ","))

	cookies := r.Cookies()
	cookieNames := make([]string, 0, len(cookies))
	cookiePairs := make([]string, 0, len(cookies))
	for _, c := range cookies {
		cookieNames = append(cookieNames, c.Name)
		cookiePairs = append(cookiePairs, c.Name+"="+c.Value)
	}
	sort.Strings(cookieNames)
	sort.Strings(cookiePairs)
	c := sha256First12(strings.Join(cookieNames, ","))
	d := sha256First12(strings.Join(cookiePairs, ","))

	return a + "_" + b + "_" + c + "_" + d
}

// primaryLang returns the first 4 characters of the highest-priority
// Accept-Language tag, lowercased, padded with '0' if shorter. Per JA4H
// spec, an absent or empty header yields "0000".
func primaryLang(header string) string {
	if header == "" {
		return "0000"
	}
	first := header
	if i := strings.IndexByte(first, ','); i >= 0 {
		first = first[:i]
	}
	if i := strings.IndexByte(first, ';'); i >= 0 {
		first = first[:i]
	}
	first = strings.ToLower(strings.TrimSpace(first))
	first = strings.ReplaceAll(first, "-", "")
	if first == "" {
		return "0000"
	}
	if len(first) >= 4 {
		return first[:4]
	}
	return first + strings.Repeat("0", 4-len(first))
}
