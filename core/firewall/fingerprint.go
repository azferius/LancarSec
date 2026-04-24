package firewall

import (
	"crypto/tls"
	"strings"
	"sync/atomic"

	"lancarsec/core/tlsparse"
)

// handshakes is a simple counter the server package reads via
// HandshakeCount() to feed the Prometheus metrics endpoint. Kept here so
// we don't have to plumb the counter through the tls.Config callback.
var handshakes atomic.Int64

// HandshakeCount exposes the handshake counter; called from core/server
// via the Prometheus scrape endpoint.
func HandshakeCount() int64 { return handshakes.Load() }

var (
	// KnownFingerprints / BotFingerprints / ForbiddenFingerprints are
	// populated from global/fingerprints/*.json at startup (see config
	// package). The literal starter sets below are immediately overwritten on
	// first load; they exist so an operator can run the proxy once without
	// network access and still get basic browser recognition.

	//READONLY
	KnownFingerprints = map[string]string{}

	//READONLY
	BotFingerprints = map[string]string{}

	//READONLY
	ForbiddenFingerprints = map[string]string{}
)

// Fingerprint is called by crypto/tls during the handshake. We derive the
// legacy hex-list fingerprint (used for KnownFingerprints/BotFingerprints
// lookup) and, when we captured the raw ClientHello via the peek listener,
// the spec-compliant JA4 as well.
func Fingerprint(clientHello *tls.ClientHelloInfo) (*tls.Config, error) {
	if len(clientHello.CipherSuites) == 0 {
		defer clientHello.Conn.Close()
		return nil, nil
	}

	remoteAddr := clientHello.Conn.RemoteAddr().String()
	handshakes.Add(1) // counted for the Prometheus endpoint
	legacy := buildLegacyFingerprint(clientHello)
	Connections.Store(remoteAddr, legacy)

	// Prefer the raw ClientHello captured by the peek listener (origin mode).
	// If it's missing, fall back to deriving JA4 from the info that Go hands
	// us — usable but not byte-match the spec.
	if v, ok := ClientHellos.Load(remoteAddr); ok {
		JA4s.Store(remoteAddr, ComputeJA4Spec(v.(*tlsparse.ClientHello)))
	} else {
		JA4s.Store(remoteAddr, ComputeJA4Fallback(clientHello))
	}

	return nil, nil
}

// buildLegacyFingerprint preserves the original balooProxy-style hex list so
// the bundled KnownFingerprints/BotFingerprints tables keep matching. Fixed
// bug vs. the upstream: GREASE values are filtered by pattern instead of
// assuming index [0] is always GREASE (Firefox and many clients don't send
// GREASE, so the upstream was dropping a real cipher every time).
func buildLegacyFingerprint(hello *tls.ClientHelloInfo) string {
	b := strings.Builder{}
	b.Grow(len(hello.CipherSuites)*8 +
		len(hello.SupportedCurves)*8 +
		len(hello.SupportedPoints)*6)

	writeHex := func(v uint16) {
		const hexDigits = "0123456789abcdef"
		b.WriteString("0x")
		first := true
		for shift := 12; shift >= 0; shift -= 4 {
			nib := (v >> shift) & 0x0f
			if first && nib == 0 && shift != 0 {
				continue
			}
			first = false
			b.WriteByte(hexDigits[nib])
		}
		b.WriteByte(',')
	}

	for _, suite := range hello.CipherSuites {
		if tlsparse.IsGrease(suite) {
			continue
		}
		writeHex(suite)
	}
	for _, curve := range hello.SupportedCurves {
		if tlsparse.IsGrease(uint16(curve)) {
			continue
		}
		writeHex(uint16(curve))
	}
	// SupportedPoints are 8-bit; emit as hex with same 0x prefix for parity
	// with the upstream fingerprint format.
	for _, point := range hello.SupportedPoints {
		writeHex(uint16(point))
	}
	return b.String()
}
