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

func Fingerprint(clientHello *tls.ClientHelloInfo) (*tls.Config, error) {

	//Invalid TLS
	if !(len(clientHello.CipherSuites) > 0) {
		defer clientHello.Conn.Close()
		return nil, nil
	}

	remoteAddr := clientHello.Conn.RemoteAddr().String()

	var fingerprint strings.Builder

	//Loop over clientHello parameters and ignore first elements of arrays since they may be randomised by certain browsers

	for _, suite := range clientHello.CipherSuites[1:] {
		fingerprint.WriteString(fmt.Sprintf("0x%x,", suite))
	}

	if len(clientHello.SupportedCurves) > 0 {
		for _, curve := range clientHello.SupportedCurves[1:] {
			fingerprint.WriteString(fmt.Sprintf("0x%x,", curve))
		}
	}
	if len(clientHello.SupportedPoints) > 0 {
		for _, point := range clientHello.SupportedPoints[:1] {
			fingerprint.WriteString(fmt.Sprintf("0x%x,", point))
		}
	}

	//Remember what connection has what fingerprint for later use
	Mutex.Lock()
	Connections[remoteAddr] = fingerprint.String()
	Mutex.Unlock()

	return nil, nil
}
