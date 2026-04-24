package firewall

import "sync/atomic"

// Published fingerprint tables. config.LoadFingerprints calls StoreKnown /
// StoreBot / StoreForbidden to publish a new set atomically; middleware and
// other readers use LoadKnown / LoadBot / LoadForbidden to snapshot a read.
//
// The legacy exported map vars (KnownFingerprints, BotFingerprints,
// ForbiddenFingerprints) are kept in sync so any file that hasn't migrated
// to the Load helpers keeps compiling; but direct reads of those maps race
// with reload, so new code should always use the helpers.
var (
	knownPtr     atomic.Pointer[map[string]string]
	botPtr       atomic.Pointer[map[string]string]
	forbiddenPtr atomic.Pointer[map[string]string]
)

func StoreKnown(m map[string]string)     { knownPtr.Store(&m); KnownFingerprints = m }
func StoreBot(m map[string]string)       { botPtr.Store(&m); BotFingerprints = m }
func StoreForbidden(m map[string]string) { forbiddenPtr.Store(&m); ForbiddenFingerprints = m }

// LookupKnown returns the browser/tool name registered for a raw fingerprint
// string, or empty if unknown. Nil-safe.
func LookupKnown(fp string) string {
	p := knownPtr.Load()
	if p == nil {
		return ""
	}
	return (*p)[fp]
}

// LookupBot returns the bot identifier registered for a raw fingerprint
// string, or empty if unknown. Nil-safe.
func LookupBot(fp string) string {
	p := botPtr.Load()
	if p == nil {
		return ""
	}
	return (*p)[fp]
}

// LookupForbidden returns the block reason for a known-malicious fingerprint,
// or empty if the fingerprint is not on the denylist. Nil-safe.
func LookupForbidden(fp string) string {
	p := forbiddenPtr.Load()
	if p == nil {
		return ""
	}
	return (*p)[fp]
}
