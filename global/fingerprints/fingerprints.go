// Package fingerprints ships the TLS-fingerprint classification tables as
// compiled-in data.
//
// The three JSON documents in this directory used to be fetched over the
// network at every startup, from a third party's repository, with the returned
// error discarded at all three call sites. That made the block list remotely
// mutable by someone outside this project, made a boot with no outbound
// internet silently degrade the fingerprint layer, and made two runs of the
// same binary classify traffic differently.
//
// They are now embedded. There is no fetch, so there is nothing to fail open:
// the tables a binary ships with are the tables it uses, and a corrupt or
// unparseable bundle stops the process at init rather than quietly leaving a
// smaller table behind. Refreshing the intelligence is a rebuild, which is the
// same review and rollback path as any other change to the proxy.
//
// Every accessor returns a fresh copy, so a caller that mutates its table
// cannot corrupt the bundled data for anyone else.
package fingerprints

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"strings"
)

//go:embed known_fingerprints.json
var knownJSON []byte

//go:embed bot_fingerprints.json
var botJSON []byte

//go:embed malicious_fingerprints.json
var maliciousJSON []byte

// Parsed once at init. A malformed bundle panics here, before any listener is
// opened, rather than degrading the fingerprint layer at request time.
var (
	known     = mustParse("known_fingerprints.json", knownJSON)
	bot       = mustParse("bot_fingerprints.json", botJSON)
	malicious = mustParse("malicious_fingerprints.json", maliciousJSON)
)

// Known returns the fingerprint -> browser table (Chromium, Firefox, Safari,
// ...). A hit here means the client is a recognised human browser.
func Known() map[string]string { return clone(known) }

// Bot returns the fingerprint -> tool/crawler table (Curl, GoogleBot,
// Python-Requests, ...). A hit here is informational: it labels the client for
// firewall rules, it does not block it.
func Bot() map[string]string { return clone(bot) }

// Malicious returns the fingerprint -> threat table. This is the only table
// that gates outright blocking, so it is also the one where a silently
// truncated fetch used to cost the most.
func Malicious() map[string]string { return clone(malicious) }

// parse decodes one bundled table and rejects the shapes that would make an
// entry unreachable rather than merely wrong.
//
// The checks are deliberately about reachability, not content. A fingerprint
// string is produced by firewall.Fingerprint as a comma-terminated list of
// "0x..," elements, so a key that is empty, or that does not end in a comma,
// can never be looked up: it is dead weight that reads as a populated table.
// That is exactly the failure the network fetch used to hide.
func parse(name string, raw []byte) (map[string]string, error) {
	var table map[string]string
	if err := json.Unmarshal(raw, &table); err != nil {
		return nil, fmt.Errorf("%s: not a JSON object of string to string: %w", name, err)
	}
	if len(table) == 0 {
		return nil, fmt.Errorf("%s: contains no entries", name)
	}
	for fp, label := range table {
		if fp == "" {
			return nil, fmt.Errorf("%s: has an empty fingerprint key (label %q); an empty key "+
				"is what a fully truncated ClientHello produces and would match it", name, label)
		}
		if label == "" {
			return nil, fmt.Errorf("%s: fingerprint %q has an empty label; rules compare against "+
				"the label, so an empty one is unmatchable", name, fp)
		}
		if !strings.HasSuffix(fp, ",") {
			return nil, fmt.Errorf("%s: fingerprint %q does not end in a comma; every element "+
				"emitted by firewall.Fingerprint is comma-terminated, so this entry can never "+
				"match anything", name, fp)
		}
	}
	return table, nil
}

func mustParse(name string, raw []byte) map[string]string {
	table, err := parse(name, raw)
	if err != nil {
		panic("fingerprints: bundled data is unusable: " + err.Error())
	}
	return table
}

func clone(src map[string]string) map[string]string {
	dst := make(map[string]string, len(src))
	for k, v := range src {
		dst[k] = v
	}
	return dst
}
