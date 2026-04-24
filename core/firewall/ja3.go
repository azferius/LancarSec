package firewall

import (
	"crypto/md5"
	"crypto/tls"
	"encoding/hex"
	"strconv"
	"strings"

	"lancarsec/core/tlsparse"
)

// ComputeJA3Spec returns the Salesforce JA3 fingerprint as a lowercase MD5
// hex string. Format per spec:
//
//	MD5(LegacyVersion,Ciphers,Extensions,SupportedGroups,SupportedPoints)
//
// Each list is comma-separated decimal; GREASE values stripped from ciphers,
// extensions, and groups (the spec says "ignore GREASE"). Empty lists
// produce an empty field — adjacent commas are valid.
//
// JA3 deliberately uses LegacyVersion (not the highest supported_versions)
// because that's what Salesforce shipped in 2017 and what every threat
// intel feed publishes against.
func ComputeJA3Spec(hello *tlsparse.ClientHello) string {
	var sb strings.Builder
	sb.WriteString(strconv.Itoa(int(hello.LegacyVersion)))
	sb.WriteByte(',')
	sb.WriteString(joinDecimal(stripGrease(hello.Ciphers)))
	sb.WriteByte(',')
	sb.WriteString(joinDecimal(stripGrease(hello.Extensions)))
	sb.WriteByte(',')
	sb.WriteString(joinDecimal(stripGrease(hello.SupportedGroups)))
	sb.WriteByte(',')
	sb.WriteString(joinDecimalU8(hello.SupportedPoints))
	sum := md5.Sum([]byte(sb.String()))
	return hex.EncodeToString(sum[:])
}

// ComputeJA3Fallback derives JA3 from tls.ClientHelloInfo when raw bytes
// aren't available (the peek listener didn't fire). Same caveat as the JA4
// fallback: the extension list is synthesized from the fields Go exposes,
// so the resulting hash will be stable per-client but won't byte-match an
// external JA3 calculator. Useful for the proxy-internal blocklist; not
// useful for cross-checking against external feeds.
func ComputeJA3Fallback(hello *tls.ClientHelloInfo) string {
	converted := &tlsparse.ClientHello{
		LegacyVersion:   0x0303,
		Ciphers:         append([]uint16(nil), hello.CipherSuites...),
		SupportedGroups: curveIDsToUint16(hello.SupportedCurves),
	}
	for _, p := range hello.SupportedPoints {
		converted.SupportedPoints = append(converted.SupportedPoints, p)
	}
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
	return ComputeJA3Spec(converted)
}

func joinDecimal(vs []uint16) string {
	if len(vs) == 0 {
		return ""
	}
	var sb strings.Builder
	sb.Grow(len(vs) * 4)
	for i, v := range vs {
		if i > 0 {
			sb.WriteByte('-')
		}
		sb.WriteString(strconv.Itoa(int(v)))
	}
	return sb.String()
}

func joinDecimalU8(vs []uint8) string {
	if len(vs) == 0 {
		return ""
	}
	var sb strings.Builder
	sb.Grow(len(vs) * 3)
	for i, v := range vs {
		if i > 0 {
			sb.WriteByte('-')
		}
		sb.WriteString(strconv.Itoa(int(v)))
	}
	return sb.String()
}
