package firewall

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"

	"lancarsec/core/tlsparse"
)

// ComputeJA4Spec produces a JA4 fingerprint byte-matching the FoxIO spec from
// a fully parsed ClientHello. Requires the raw extension list and signature
// algorithm vector, which is why this takes *tlsparse.ClientHello and not the
// filtered tls.ClientHelloInfo that Go hands us in the handshake callback.
//
// Format: q|t + tls_ver(2) + sni(d|i) + cipher_count(2d) + ext_count(2d) + alpn2 + "_" + cipher_hash12 + "_" + ext_sig_hash12
//
// Per spec:
//   - Extensions count includes SNI (0x0000) and ALPN (0x0010).
//   - Extensions hash EXCLUDES SNI and ALPN from the sorted list, but appends
//     signature algorithms in original order after "_".
//   - GREASE values are stripped from cipher and extension lists.
func ComputeJA4Spec(hello *tlsparse.ClientHello) string {
	proto := "t" // TCP (TLS); "q" would be QUIC, we only ever see TLS here.

	tlsVer := versionCode(hello.TLSVersion())

	sni := "i"
	if hello.SNI != "" {
		sni = "d"
	}

	ciphers := stripGrease(hello.Ciphers)
	extensions := stripGrease(hello.Extensions)
	sigAlgs := stripGrease(hello.SigAlgs)

	cipherCount := twoDigit(len(ciphers))
	// Spec: extension count includes SNI/ALPN even though they're removed
	// from the hashed list.
	extCount := twoDigit(len(extensions))

	alpn := alpnCode(hello.ALPN)

	cipherHash := sha256First12(joinSortedHex(ciphers))

	extsForHash := filterExt(extensions, 0x0000, 0x0010)
	sort.Slice(extsForHash, func(i, j int) bool { return extsForHash[i] < extsForHash[j] })
	// Sigalgs go in ORIGINAL order per spec, not sorted.
	extHash := sha256First12(joinHex(extsForHash) + "_" + joinHex(sigAlgs))

	return fmt.Sprintf("%s%s%s%s%s%s_%s_%s",
		proto, tlsVer, sni, cipherCount, extCount, alpn, cipherHash, extHash)
}

// ComputeJA4Fallback is a best-effort computation from tls.ClientHelloInfo
// when the raw parser output isn't available (for example when the peek
// listener didn't fire — shouldn't happen in origin mode but serves as a
// safety net). Produces a JA4-shaped string that is stable per-client but
// does NOT byte-match the spec because Go hides the raw extension list.
func ComputeJA4Fallback(hello *tls.ClientHelloInfo) string {
	converted := &tlsparse.ClientHello{
		LegacyVersion:   0x0303,
		Ciphers:         append([]uint16(nil), hello.CipherSuites...),
		SupportedGroups: curveIDsToUint16(hello.SupportedCurves),
		SupportedVers:   append([]uint16(nil), hello.SupportedVersions...),
		ALPN:            append([]string(nil), hello.SupportedProtos...),
		SNI:             hello.ServerName,
	}
	for _, s := range hello.SignatureSchemes {
		converted.SigAlgs = append(converted.SigAlgs, uint16(s))
	}
	// Synthesize extension IDs from observed fields.
	if hello.ServerName != "" {
		converted.Extensions = append(converted.Extensions, 0x0000)
	}
	if len(hello.SupportedCurves) > 0 {
		converted.Extensions = append(converted.Extensions, 0x000a)
	}
	if len(hello.SupportedPoints) > 0 {
		converted.Extensions = append(converted.Extensions, 0x000b)
	}
	if len(hello.SignatureSchemes) > 0 {
		converted.Extensions = append(converted.Extensions, 0x000d)
	}
	if len(hello.SupportedProtos) > 0 {
		converted.Extensions = append(converted.Extensions, 0x0010)
	}
	if len(hello.SupportedVersions) > 0 {
		converted.Extensions = append(converted.Extensions, 0x002b)
	}
	return ComputeJA4Spec(converted)
}

func curveIDsToUint16(curves []tls.CurveID) []uint16 {
	out := make([]uint16, len(curves))
	for i, c := range curves {
		out[i] = uint16(c)
	}
	return out
}

func stripGrease(in []uint16) []uint16 {
	out := make([]uint16, 0, len(in))
	for _, v := range in {
		if !tlsparse.IsGrease(v) {
			out = append(out, v)
		}
	}
	return out
}

func filterExt(in []uint16, drop ...uint16) []uint16 {
	dropset := make(map[uint16]struct{}, len(drop))
	for _, d := range drop {
		dropset[d] = struct{}{}
	}
	out := make([]uint16, 0, len(in))
	for _, v := range in {
		if _, skip := dropset[v]; skip {
			continue
		}
		out = append(out, v)
	}
	return out
}

func versionCode(v uint16) string {
	switch v {
	case tls.VersionTLS13:
		return "13"
	case tls.VersionTLS12:
		return "12"
	case tls.VersionTLS11:
		return "11"
	case tls.VersionTLS10:
		return "10"
	case 0x0300:
		return "s3"
	}
	return "00"
}

// alpnCode returns JA4's 2-char ALPN code:
//   - empty ALPN list or first protocol empty string -> "00"
//   - first byte of first protocol non-alphanumeric  -> "99"
//   - otherwise                                       -> first char + last char
func alpnCode(alpn []string) string {
	if len(alpn) == 0 || alpn[0] == "" {
		return "00"
	}
	first := alpn[0]
	if !isAlnum(first[0]) {
		return "99"
	}
	last := first[len(first)-1]
	if !isAlnum(last) {
		return "99"
	}
	return string(first[0]) + string(last)
}

func isAlnum(b byte) bool {
	return (b >= '0' && b <= '9') || (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z')
}

func joinSortedHex(vs []uint16) string {
	copied := append([]uint16(nil), vs...)
	sort.Slice(copied, func(i, j int) bool { return copied[i] < copied[j] })
	return joinHex(copied)
}

func joinHex(vs []uint16) string {
	if len(vs) == 0 {
		return ""
	}
	b := strings.Builder{}
	b.Grow(len(vs) * 5)
	for i, v := range vs {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, "%04x", v)
	}
	return b.String()
}

func sha256First12(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])[:12]
}

func twoDigit(n int) string {
	if n > 99 {
		return "99"
	}
	return fmt.Sprintf("%02d", n)
}

// -- legacy helpers kept for callers that still reference them --

// ComputeJA4 is retained as a shim calling ComputeJA4Fallback so older call
// sites compile; new code should prefer ComputeJA4Spec with a parsed hello.
func ComputeJA4(hello *tls.ClientHelloInfo) string { return ComputeJA4Fallback(hello) }
