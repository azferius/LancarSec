package gofilter

import (
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// `matches` against a non-string operand.
//
// Upstream kor44/gofilter compiles the right-hand side of `matches` with
// regexp.Compile(val.(string)) -- an UNCHECKED type assertion on whatever
// checkFieldNameVsTypeValue returned. That value is only a string when the
// field is FT_STRING/FT_BYTES *and* the literal parsed as neither a quoted
// string nor colon-hex. Every other combination produced a runtime panic, and
// NewFilter has no recover(), so the panic escaped to the caller.
//
// In LancarSec both callers are config load (config.buildDomain) and live
// reload (server.ReloadConfig). A single typo in a firewall rule -- forgetting
// the quotes around a regex -- therefore killed the proxy outright, either at
// boot or, worse, in the middle of a running reload.
//
// This file pins the four operand types the vendored parser can hand back:
// net.IP, int, []byte and bool. The fix is a comma-ok assertion that reports a
// parse error naming the field and the type the operand actually produced.
// ---------------------------------------------------------------------------

// The field names mirror core/firewall/filter.go so the cases read as the real
// config.json typos an operator makes. `ip.src` is already registered FT_IP by
// filter_test.go's init; ErrFieldExist is the expected answer for it and for a
// re-run, so it is not a failure.
func init() {
	for name, kind := range map[string]ftenum{
		"ip.src":          FT_IP,
		"ip.asn":          FT_INT,
		"http.user_agent": FT_STRING,
		"proxy.attack":    FT_BOOL,
	} {
		if err := RegisterField(name, kind); err != nil && err != ErrFieldExist {
			panic("registering " + name + ": " + err.Error())
		}
	}
}

// newFilterNoPanic calls NewFilter and turns a panic into a test failure naming
// the rule, so a regression reads as "this rule panicked" instead of taking the
// whole test binary down with an unattributed stack.
func newFilterNoPanic(t *testing.T, rule string) (f *Filter, err error) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("NewFilter(%q) panicked: %v\n"+
				"the `matches` operand assertion must be comma-ok, not val.(string)", rule, r)
		}
	}()
	return NewFilter(rule)
}

// Wave 4 flips this from "panics" to "returns a parse error". Before the fix
// each of these four rules produced
// `interface conversion: interface {} is <T>, not string` out of parser.go
// case 13 and took the process with it.
func TestMatchesRejectsNonStringOperandInsteadOfPanicking(t *testing.T) {
	tests := []struct {
		name string
		rule string
		// wantType is the %T of the value checkFieldNameVsTypeValue returned;
		// naming it is the whole point of the new error, because it is the only
		// thing that tells an operator WHY their rule was rejected.
		wantType string
	}{
		{
			name:     "FT_IP operand parses to net.IP",
			rule:     "ip.src matches 1.2.3.4",
			wantType: "net.IP",
		},
		{
			name:     "FT_INT operand parses to int",
			rule:     "ip.asn matches 1234",
			wantType: "int",
		},
		{
			// FT_STRING plus a colon-hex literal takes the parseBytes arm, so
			// even a string-typed field can yield []byte.
			name:     "FT_STRING operand that looks like colon-hex parses to []byte",
			rule:     "http.user_agent matches ff:ee",
			wantType: "[]uint8",
		},
		{
			name:     "FT_BOOL operand parses to bool",
			rule:     "proxy.attack matches true",
			wantType: "bool",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f, err := newFilterNoPanic(t, tc.rule)

			if err == nil {
				t.Fatalf("NewFilter(%q) returned no error, want a parse error", tc.rule)
			}
			if f != nil {
				t.Errorf("NewFilter(%q) returned a filter alongside the error: %#v", tc.rule, f)
			}

			// The field name has to be in the message: a config.json can hold
			// dozens of rules and the error is the only pointer to which one.
			field := strings.Fields(tc.rule)[0]
			if !strings.Contains(err.Error(), field) {
				t.Errorf("error %q does not name the field %q", err, field)
			}
			if !strings.Contains(err.Error(), tc.wantType) {
				t.Errorf("error %q does not name the operand type %q", err, tc.wantType)
			}
			// And it must not be mistaken for the "bad regex" error, which is a
			// different fix on the operator's side.
			if strings.Contains(err.Error(), "reqular expresstion") {
				t.Errorf("error %q reads as an invalid-regex error; the operand was never a regex at all", err)
			}
		})
	}
}

// The rejection must be a clean parse failure, not a poisoned lexer: a second
// NewFilter on the same process has to keep working. This is what makes a live
// reload survivable -- the operator fixes the typo and reloads again.
func TestMatchesRejectionLeavesTheParserUsable(t *testing.T) {
	if _, err := newFilterNoPanic(t, "ip.asn matches 1234"); err == nil {
		t.Fatal("expected the bad rule to be rejected")
	}

	f, err := newFilterNoPanic(t, `http.user_agent matches "^curl/"`)
	if err != nil {
		t.Fatalf("a valid rule failed to parse after a rejected one: %v", err)
	}
	if !f.Apply(Message{"http.user_agent": "curl/8.4.0"}) {
		t.Error("the valid rule did not match a user agent it should have")
	}
	if f.Apply(Message{"http.user_agent": "Mozilla/5.0"}) {
		t.Error("the valid rule matched a user agent it should not have")
	}
}

// The pre-existing invalid-regex path is unchanged: a quoted-but-broken pattern
// still reports the upstream message rather than the new type error.
func TestMatchesStillReportsAnInvalidRegex(t *testing.T) {
	_, err := newFilterNoPanic(t, `http.user_agent matches "a("`)
	if err == nil {
		t.Fatal("expected an invalid-regex error")
	}
	if !strings.Contains(err.Error(), "reqular expresstion") {
		t.Errorf("error %q is not the invalid-regex error", err)
	}
}
