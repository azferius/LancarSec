package firewall

import (
	"crypto/tls"
	"fmt"
	"strings"

	fingerprints "github.com/azferius/lancarsec/global/fingerprints"
)

// The three classification tables, populated from the bundle compiled in by
// global/fingerprints. They used to be hardcoded here as a small fallback that
// config.Load overwrote with the result of three HTTP GETs against a third
// party's repository -- with the error discarded, so a failed fetch silently
// left the fallback in place. That is a fail-open in the one table that gates
// blocking, and a fail-closed in the table that recognises browsers, and it is
// invisible either way.
//
// The fallback is gone. There is no fetch left to fail, so there is nothing to
// fall back to: the tables are whatever the binary was built with, identically
// on every boot and with no outbound network required. A corrupt bundle panics
// in the fingerprints package's init, before any listener opens.
//
// Each var owns its own copy of the bundled data, so writing to one of these
// maps (as the server tests do) cannot corrupt the others or the bundle.
//
// READONLY at runtime: these are read lock-free on the request hot path
// (core/server/middleware.go). Anything that replaces them must do so during
// startup, before Serve.
var (
	// Fingerprint -> browser name, e.g. "Chromium", "Firefox", "Safari".
	KnownFingerprints = fingerprints.Known()

	// Fingerprint -> tool or crawler name, e.g. "Curl", "GoogleBot". Labels
	// only; a hit here does not block.
	BotFingerprints = fingerprints.Bot()

	// Fingerprint -> threat name. The only table that hard-blocks.
	ForbiddenFingerprints = fingerprints.Malicious()
)

// isGREASE reports whether a 16-bit ClientHello value (a cipher suite, a
// supported curve) is a GREASE value as defined by RFC 8701: both bytes equal
// and the low nibble 0xa, i.e. one of 0x0a0a, 0x1a1a, ... 0xfafa. Real cipher
// suites and curve IDs never collide with the pattern.
//
// WAVE 11 PREP (GREASE fix): the derivation used to drop index 0 of the
// cipher and curve lists instead. Only Chrome-family clients send GREASE --
// and they send it in the FIRST slot, which is why index-0 truncation ever
// worked at all. Every Firefox-family hello has a REAL cipher (0x1301) and a
// REAL curve (X25519) in its first slots, so [1:] threw away legitimate
// signal and produced a wrong fingerprint: any client differing from Firefox
// only in its first suite or curve was indistinguishable from Firefox, and a
// single-suite hello collapsed onto whatever its curves said. GREASE-pattern
// filtering skips exactly the randomised values, wherever they sit, and keeps
// everything else.
func isGREASE(v uint16) bool {
	return v&0x0f == 0x0a && v>>8 == v&0xff
}

// isGREASE8 is the single-byte analogue used for ec_point_formats values,
// which arrive as uint8: the 0x?a form (0x0a, 0x1a, ... 0xfa). Real point
// formats are 0 (uncompressed), 1 and 2, so nothing legitimate is filtered.
//
// WAVE 11 PREP (GREASE fix): the point list used to be emitted as
// SupportedPoints[:1] -- ONE byte, always the first -- the exact opposite of
// the "ignore first elements" comment above the old loops. A client offering
// several point formats contributed exactly one byte of signal, and always
// the same one. Every non-GREASE format is emitted now.
func isGREASE8(v uint8) bool {
	return v&0x0f == 0x0a
}

func Fingerprint(clientHello *tls.ClientHelloInfo) (*tls.Config, error) {

	//Invalid TLS
	if !(len(clientHello.CipherSuites) > 0) {
		defer clientHello.Conn.Close()
		return nil, nil
	}

	remoteAddr := clientHello.Conn.RemoteAddr().String()

	var fingerprint strings.Builder

	//Loop over ClientHello parameters and skip GREASE values wherever they
	//appear (RFC 8701; see isGREASE). Ranging over the full lists replaces the
	//old [1:] / [:1] slicing, so empty and nil lists simply contribute
	//nothing and the len() guards are no longer needed.

	for _, suite := range clientHello.CipherSuites {
		if isGREASE(suite) {
			continue
		}
		fingerprint.WriteString(fmt.Sprintf("0x%x,", suite))
	}

	for _, curve := range clientHello.SupportedCurves {
		if isGREASE(uint16(curve)) {
			continue
		}
		fingerprint.WriteString(fmt.Sprintf("0x%x,", curve))
	}
	for _, point := range clientHello.SupportedPoints {
		if isGREASE8(point) {
			continue
		}
		fingerprint.WriteString(fmt.Sprintf("0x%x,", point))
	}

	//Remember what connection has what fingerprint for later use
	Mutex.Lock()
	Connections[remoteAddr] = fingerprint.String()
	Mutex.Unlock()

	return nil, nil
}
