package firewall

import (
	"testing"

	"github.com/azferius/lancarsec/core/domains"
	"github.com/azferius/lancarsec/core/gofilter"
)

// mustFilter compiles a real gofilter expression so these tests exercise the
// actual firewall DSL rather than a stub node. The firewall package's init()
// (core/firewall/filter.go) registers every field name used below.
func mustFilter(t *testing.T, expr string) *gofilter.Filter {
	t.Helper()
	f, err := gofilter.NewFilter(expr)
	if err != nil {
		t.Fatalf("gofilter.NewFilter(%q) returned error: %v", expr, err)
	}
	return f
}

// rule is a tiny constructor so the tables below stay readable.
func rule(t *testing.T, expr, action string) domains.Rule {
	t.Helper()
	return domains.Rule{Filter: mustFilter(t, expr), Action: action}
}

// TestEvalFirewallRuleActions pins the arithmetic EvalFirewallRule performs for
// every action form reachable from a config file today.
func TestEvalFirewallRuleActions(t *testing.T) {
	const matchAll = `http.path eq "/admin"`
	const matchNone = `http.path eq "/does-not-match"`

	vars := gofilter.Message{
		"http.path":   "/admin",
		"http.method": "GET",
	}

	tests := []struct {
		name   string
		expr   string
		action string
		susLv  int
		want   int
	}{
		{
			name:   "increment adds to susLv",
			expr:   matchAll,
			action: "+3",
			susLv:  0,
			want:   3,
		},
		{
			name:   "increment on a non-zero susLv accumulates",
			expr:   matchAll,
			action: "+2",
			susLv:  4,
			want:   6,
		},
		{
			name:   "decrement subtracts from susLv",
			expr:   matchAll,
			action: "-2",
			susLv:  5,
			want:   3,
		},
		{
			// BUG (wave 7 may flip this): the result is never clamped to >= 0.
			// A "-3" rule on a fresh request yields susLv -3, which every
			// downstream `susLv >= n` comparison in middleware treats as
			// "even more trusted than a whitelisted request". If wave 7 adds a
			// clamp, this assertion must be changed to expect 0.
			name:   "decrement below zero is not clamped",
			expr:   matchAll,
			action: "-3",
			susLv:  0,
			want:   -3,
		},
		{
			name:   "bare number sets susLv absolutely",
			expr:   matchAll,
			action: "7",
			susLv:  2,
			want:   7,
		},
		{
			name:   "bare zero sets susLv to zero (whitelist form)",
			expr:   matchAll,
			action: "0",
			susLv:  9,
			want:   0,
		},
		{
			// BUG (wave 4/7 may flip this): a bad action is logged to stdout and
			// then silently ignored, so a typo'd rule fails OPEN. A rule the
			// operator wrote as "+ 3" or "+three" contributes nothing and the
			// proxy keeps serving. If a later wave rejects bad actions at config
			// load, this case stops being reachable at all.
			name:   "non-numeric increment is ignored, susLv unchanged",
			expr:   matchAll,
			action: "+abc",
			susLv:  4,
			want:   4,
		},
		{
			name:   "non-numeric decrement is ignored, susLv unchanged",
			expr:   matchAll,
			action: "-abc",
			susLv:  4,
			want:   4,
		},
		{
			name:   "non-numeric bare action is ignored, susLv unchanged",
			expr:   matchAll,
			action: "block",
			susLv:  4,
			want:   4,
		},
		{
			// "+" alone leaves an empty operand for Sscan, which errors out.
			name:   "lone plus sign is ignored, susLv unchanged",
			expr:   matchAll,
			action: "+",
			susLv:  1,
			want:   1,
		},
		{
			// BUG (a later wave may flip this): an action that merely STARTS with
			// a space takes the `default` branch, and fmt.Sscan happily skips
			// leading whitespace. So " 7" is an ABSOLUTE set, while "+7" is an
			// increment -- an invisible whitespace character changes the meaning
			// of the rule. If action strings are ever trimmed/validated, this
			// must be changed to expect 2 (rejected) or 9 (increment).
			name:   "leading space makes the action absolute, not additive",
			expr:   matchAll,
			action: " 7",
			susLv:  2,
			want:   7,
		},
		{
			// BUG (a later wave may flip this): the '-' branch is checked before
			// the numeric branch, so "-5" can never mean "set susLv to -5"; it
			// always means "subtract 5". There is no syntax for an absolute
			// negative. Harmless today, but it means the action grammar is not
			// what "a bare number is absolute" suggests.
			name:   "negative bare number is a decrement, never an absolute",
			expr:   matchAll,
			action: "-5",
			susLv:  1,
			want:   -4,
		},
		{
			name:   "non-matching rule leaves susLv untouched",
			expr:   matchNone,
			action: "+9",
			susLv:  3,
			want:   3,
		},
		{
			name:   "non-matching rule with an absolute action leaves susLv untouched",
			expr:   matchNone,
			action: "1",
			susLv:  3,
			want:   3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			currDomain := domains.DomainSettings{
				Name:        "example.com",
				CustomRules: []domains.Rule{rule(t, tt.expr, tt.action)},
			}
			if got := EvalFirewallRule(currDomain, vars, tt.susLv); got != tt.want {
				t.Errorf("EvalFirewallRule(action=%q, susLv=%d) = %d, want %d",
					tt.action, tt.susLv, got, tt.want)
			}
		})
	}
}

// TestEvalFirewallRuleOrdering pins the control flow across a rule LIST, which
// is where the asymmetry between the three action branches actually bites.
func TestEvalFirewallRuleOrdering(t *testing.T) {
	const match = `http.path eq "/admin"`
	const noMatch = `http.path eq "/nope"`

	vars := gofilter.Message{"http.path": "/admin"}

	tests := []struct {
		name  string
		rules []domains.Rule
		susLv int
		want  int
	}{
		{
			name: "increments accumulate across several matching rules",
			rules: []domains.Rule{
				rule(t, match, "+1"),
				rule(t, match, "+2"),
				rule(t, match, "+4"),
			},
			susLv: 0,
			want:  7,
		},
		{
			name: "increments and decrements interleave in order",
			rules: []domains.Rule{
				rule(t, match, "+5"),
				rule(t, match, "-2"),
				rule(t, match, "+1"),
			},
			susLv: 0,
			want:  4,
		},
		{
			// The `default` (absolute) branch does `return result` on success,
			// while `+` and `-` fall through to the next rule. So an absolute
			// rule short-circuits every rule after it. This is deliberate-looking
			// but undocumented, and it means rule ORDER silently decides whether
			// later rules run at all.
			name: "an absolute action short-circuits every later rule",
			rules: []domains.Rule{
				rule(t, match, "+3"),
				rule(t, match, "2"),
				rule(t, match, "+100"),
			},
			susLv: 0,
			want:  2,
		},
		{
			// BUG (a later wave may flip this): the short-circuit only happens
			// when Sscan SUCCEEDS. A malformed absolute action falls out of the
			// switch and the loop continues, so "+100" below still applies. The
			// blast radius of a typo therefore depends on rules the operator did
			// not touch.
			name: "a malformed absolute action does NOT short-circuit",
			rules: []domains.Rule{
				rule(t, match, "+3"),
				rule(t, match, "drop"),
				rule(t, match, "+100"),
			},
			susLv: 0,
			want:  103,
		},
		{
			name: "non-matching rules are skipped, matching ones still apply",
			rules: []domains.Rule{
				rule(t, noMatch, "9"),
				rule(t, match, "+2"),
				rule(t, noMatch, "+50"),
				rule(t, match, "+3"),
			},
			susLv: 1,
			want:  6,
		},
		{
			name:  "an empty rule list returns susLv verbatim",
			rules: nil,
			susLv: 4,
			want:  4,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			currDomain := domains.DomainSettings{Name: "example.com", CustomRules: tt.rules}
			if got := EvalFirewallRule(currDomain, vars, tt.susLv); got != tt.want {
				t.Errorf("EvalFirewallRule(susLv=%d) = %d, want %d", tt.susLv, got, tt.want)
			}
		})
	}
}

// TestEvalFirewallRuleEmptyActionPanics pins the current contract for an empty
// Action string.
//
// BUG (wave 4 flips this): `rule.Action[:1]` slices an empty string and panics
// with "slice bounds out of range". A config containing
//
//	{"expression": "http.path eq \"/x\"", "action": ""}
//
// therefore takes the whole proxy down the first time that rule MATCHES -- not
// at config load, so it is a latent, traffic-triggered crash. `net/http`
// recovers the handler panic, but core/firewall/general.go's bare Lock()/Unlock()
// pairs on the hot path mean the recovered panic can leave the global mutex held.
//
// When wave 4 validates actions at config load (or wave 7 guards the slice),
// this test must be changed from "asserts it panics" to whatever the new
// contract is -- most likely "the rule is rejected at load and never reaches
// EvalFirewallRule".
func TestEvalFirewallRuleEmptyActionPanics(t *testing.T) {
	currDomain := domains.DomainSettings{
		Name:        "example.com",
		CustomRules: []domains.Rule{rule(t, `http.path eq "/admin"`, "")},
	}
	vars := gofilter.Message{"http.path": "/admin"}

	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("EvalFirewallRule with an empty Action did not panic; " +
				"if a wave fixed this, update this test to the new contract")
		}
		// Do not assert the exact runtime message; only that it panicked.
		t.Logf("pinned panic: %v", r)
	}()

	_ = EvalFirewallRule(currDomain, vars, 0)
	t.Fatal("unreachable: EvalFirewallRule returned instead of panicking")
}

// TestEvalFirewallRuleEmptyActionNonMatchingIsSafe documents the flip side: the
// empty-action panic is guarded by rule.Filter.Apply, so a never-matching rule
// with an empty action is harmless. That is precisely why the defect survives
// review -- it does not reproduce until the right request arrives.
func TestEvalFirewallRuleEmptyActionNonMatchingIsSafe(t *testing.T) {
	currDomain := domains.DomainSettings{
		Name:        "example.com",
		CustomRules: []domains.Rule{rule(t, `http.path eq "/never"`, "")},
	}
	vars := gofilter.Message{"http.path": "/admin"}

	if got := EvalFirewallRule(currDomain, vars, 2); got != 2 {
		t.Errorf("EvalFirewallRule = %d, want 2", got)
	}
}

// TestEvalFirewallRuleIntField exercises a non-string field type end to end, so
// the test suite covers more of the DSL surface than string equality.
func TestEvalFirewallRuleIntField(t *testing.T) {
	currDomain := domains.DomainSettings{
		Name:        "example.com",
		CustomRules: []domains.Rule{rule(t, `ip.requests > 100`, "+2")},
	}

	tests := []struct {
		name     string
		requests int
		want     int
	}{
		{name: "under the threshold", requests: 50, want: 0},
		{name: "on the threshold is not greater-than", requests: 100, want: 0},
		{name: "over the threshold", requests: 101, want: 2},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vars := gofilter.Message{"ip.requests": tt.requests}
			if got := EvalFirewallRule(currDomain, vars, 0); got != tt.want {
				t.Errorf("EvalFirewallRule(ip.requests=%d) = %d, want %d",
					tt.requests, got, tt.want)
			}
		})
	}
}

// TestEvalFirewallRuleMissingField pins what happens when a rule references a
// registered field that the middleware never actually puts into the Message.
//
// BUG (documented in docs/ARCHITECTURE.md; a later wave flips this): five DSL
// fields -- ip.country, ip.asn, http.body among them -- are registered in
// core/firewall/filter.go but never supplied by the middleware. A positive rule
// on such a field silently never fires (fails OPEN), and its NEGATION fires on
// EVERY request (fails CLOSED, blocking everyone). Both halves are pinned here.
func TestEvalFirewallRuleMissingField(t *testing.T) {
	// Deliberately does NOT contain "ip.country".
	vars := gofilter.Message{"http.path": "/admin"}

	positive := domains.DomainSettings{
		Name:        "example.com",
		CustomRules: []domains.Rule{rule(t, `ip.country eq "CN"`, "+5")},
	}
	if got := EvalFirewallRule(positive, vars, 0); got != 0 {
		t.Errorf("positive geo rule: EvalFirewallRule = %d, want 0 (rule fails open today)", got)
	}

	negative := domains.DomainSettings{
		Name:        "example.com",
		CustomRules: []domains.Rule{rule(t, `ip.country ne "US"`, "+5")},
	}
	if got := EvalFirewallRule(negative, vars, 0); got != 5 {
		t.Errorf("negated geo rule: EvalFirewallRule = %d, want 5 "+
			"(rule matches every request today, because the field is absent)", got)
	}
}
