package fingerprints

import (
	"strings"
	"testing"
)

// TestBundledTablesParse is the build-time tripwire the //go:embed replaced the
// network fetch with. If a bundled JSON file is edited into something that will
// not parse, or that parses into entries no ClientHello can ever match, the
// package-level mustParse calls panic during init -- which means every test in
// every package that imports this one fails immediately. This test states the
// expected shape explicitly so the failure names the file instead of just
// unwinding.
func TestBundledTablesParse(t *testing.T) {
	tables := []struct {
		name  string
		table map[string]string
		want  int
	}{
		{"known_fingerprints.json", Known(), 9},
		{"bot_fingerprints.json", Bot(), 16},
		{"malicious_fingerprints.json", Malicious(), 8},
	}

	for _, tt := range tables {
		t.Run(tt.name, func(t *testing.T) {
			if got := len(tt.table); got != tt.want {
				t.Errorf("%s has %d entries, want %d; if the bundle was refreshed "+
					"deliberately, update this count and core/firewall's label test in the "+
					"same commit so the reclassification is visible in the diff",
					tt.name, got, tt.want)
			}
			for fp, label := range tt.table {
				if fp == "" || label == "" || !strings.HasSuffix(fp, ",") {
					t.Errorf("%s has an unreachable entry %q -> %q", tt.name, fp, label)
				}
			}
		})
	}
}

// TestAccessorsReturnCopies pins that a caller mutating its table cannot corrupt
// the bundle for anyone else. core/firewall assigns these straight to exported
// package vars that its own tests write to, so aliasing here would let one
// test's fixture leak into the live classification tables.
func TestAccessorsReturnCopies(t *testing.T) {
	accessors := map[string]func() map[string]string{
		"Known":     Known,
		"Bot":       Bot,
		"Malicious": Malicious,
	}

	for name, get := range accessors {
		t.Run(name, func(t *testing.T) {
			first := get()
			before := len(first)

			first["0xdead,"] = "injected"
			for k := range first {
				delete(first, k)
			}

			second := get()
			if len(second) != before {
				t.Fatalf("%s() returned %d entries after the previous copy was emptied, want %d; "+
					"the accessor is handing out the bundle itself, not a copy",
					name, len(second), before)
			}
			if _, ok := second["0xdead,"]; ok {
				t.Errorf("%s(): a write to one copy is visible in the next", name)
			}
		})
	}
}

// TestParseRejectsMalformedBundles covers the loud-failure path directly. Each
// case is a way a hand-edit or a bad refresh silently disarms part of the
// fingerprint layer; parse must return an error so mustParse turns it into a
// panic at init rather than a smaller table at request time.
func TestParseRejectsMalformedBundles(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want string // substring of the expected error
	}{
		{
			name: "not JSON at all",
			raw:  "<!DOCTYPE html>",
			want: "not a JSON object",
		},
		{
			// The exact shape a proxy error page or a truncated download has.
			name: "JSON but not an object of string to string",
			raw:  `{"0x1301,": 5}`,
			want: "not a JSON object",
		},
		{
			name: "empty object",
			raw:  `{}`,
			want: "contains no entries",
		},
		{
			name: "empty fingerprint key",
			raw:  `{"": "Chromium"}`,
			want: "empty fingerprint key",
		},
		{
			name: "empty label",
			raw:  `{"0x1301,": ""}`,
			want: "empty label",
		},
		{
			// The class the old "(0xcca9,..." typo belonged to: syntactically
			// fine, counted in len(), and permanently unmatchable.
			name: "key without a trailing comma can never match",
			raw:  `{"0x1301,0x1302": "Chromium"}`,
			want: "does not end in a comma",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			table, err := parse("test.json", []byte(tc.raw))
			if err == nil {
				t.Fatalf("parse accepted a malformed bundle and returned %v; it must fail loudly",
					table)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("parse error = %q, want it to mention %q", err, tc.want)
			}
			if !strings.Contains(err.Error(), "test.json") {
				t.Errorf("parse error = %q, want it to name the offending file", err)
			}
		})
	}
}

// TestParseAcceptsAWellFormedBundle is the positive control for the test above:
// it proves the rejections are targeted rather than parse simply erroring on
// everything.
func TestParseAcceptsAWellFormedBundle(t *testing.T) {
	table, err := parse("test.json", []byte(`{"0x1301,0x1302,0x0,": "Chromium"}`))
	if err != nil {
		t.Fatalf("parse rejected a well-formed bundle: %v", err)
	}
	if got := table["0x1301,0x1302,0x0,"]; got != "Chromium" {
		t.Errorf("parse lost the entry: got %q", got)
	}
}
