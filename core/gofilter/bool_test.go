package gofilter

import "testing"

// ---------------------------------------------------------------------------
// Equality against an FT_BOOL field.
//
// Upstream kor44/gofilter registers FT_BOOL, and its parser parses the operand
// with strconv.ParseBool -- so `proxy.attack eq true` compiles cleanly and the
// operand really is a Go bool. But nodeEq.applyOne has a case for every other
// registered type and NONE for bool, so the comparison fell through to the
// terminal `return false`.
//
// The result was a rule that reads exactly like it works and never does:
//
//	proxy.attack eq true     never matched, even while under attack
//	proxy.attack ne true     ALWAYS matched, because `ne` is parsed as
//	                         not(eq) and eq was always false
//
// LancarSec supplies four FT_BOOL fields to the rule engine on every request
// (proxy.cloudflare, proxy.stage_locked, proxy.attack, proxy.bypass_attack), so
// this made all four unusable in the two ways that matter: a rule meant to fire
// during an attack was inert, and its negation fired on every request in the
// world. That is the same failure shape as a field that is registered and never
// populated, and it is fixed the same way -- at the layer where it is wrong.
//
// LancarSec deviation 5; see README.md in this directory.
// ---------------------------------------------------------------------------

func init() {
	for name, kind := range map[string]ftenum{
		"probe.bool_a": FT_BOOL,
		"probe.bool_b": FT_BOOL,
	} {
		if err := RegisterField(name, kind); err != nil && err != ErrFieldExist {
			panic("registering " + name + ": " + err.Error())
		}
	}
}

func TestBoolEquality(t *testing.T) {
	msg := Message{"probe.bool_a": true, "probe.bool_b": false}

	tests := []struct {
		expr string
		want bool
	}{
		{`probe.bool_a eq true`, true},
		{`probe.bool_a eq false`, false},
		{`probe.bool_b eq false`, true},
		{`probe.bool_b eq true`, false},

		// `ne` is not its own node: the parser builds not(eq). Both directions
		// have to be checked, because the broken version answered true for
		// every one of these.
		{`probe.bool_a ne false`, true},
		{`probe.bool_a ne true`, false},
		{`probe.bool_b ne true`, true},
		{`probe.bool_b ne false`, false},
	}

	for _, tt := range tests {
		t.Run(tt.expr, func(t *testing.T) {
			f, err := NewFilter(tt.expr)
			if err != nil {
				t.Fatalf("NewFilter(%q): %v", tt.expr, err)
			}
			if got := f.Apply(msg); got != tt.want {
				t.Errorf("Apply(%q) = %v, want %v", tt.expr, got, tt.want)
			}
		})
	}
}

// An absent field still answers false for eq -- the fix must not turn a missing
// key into a match, which is what applyRange's early return guarantees.
func TestBoolEqualityOnAMissingFieldIsFalse(t *testing.T) {
	f, err := NewFilter(`probe.bool_a eq false`)
	if err != nil {
		t.Fatalf("NewFilter: %v", err)
	}
	if f.Apply(Message{}) {
		t.Error("eq matched on a message that does not carry the field")
	}
}

// A bare field name is a PRESENCE test, as in Wireshark's display filters --
// `probe.bool_b` is true because the field is there, not because its value is.
// Pinned so nobody "fixes" it into a truth test: that is upstream's documented
// semantics, and rules in the wild rely on it for non-bool fields.
func TestBareBoolFieldIsAPresenceTestNotATruthTest(t *testing.T) {
	f, err := NewFilter(`probe.bool_b`)
	if err != nil {
		t.Fatalf("NewFilter: %v", err)
	}
	if !f.Apply(Message{"probe.bool_b": false}) {
		t.Error("bare field name did not match a field that is present with value false")
	}
	if f.Apply(Message{}) {
		t.Error("bare field name matched a message that does not carry it")
	}
}
