package firewall

import (
	"strconv"
	"strings"
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
// WAVE 13: a Rule now carries the action already parsed, exactly as the config
// pipeline builds it. Constructing one here without parsing would test a state
// the pipeline cannot produce.
func rule(t *testing.T, expr, action string) domains.Rule {
	t.Helper()
	op, value, err := domains.ParseAction(action)
	if err != nil {
		t.Fatalf("domains.ParseAction(%q): %v", action, err)
	}
	return domains.Rule{Filter: mustFilter(t, expr), Action: action, Op: op, Value: value}
}

// WAVE 13: FLIPPED, and the table shrank. It used to include "+abc", "-abc",
// "block", "+" and " 7" as cases EvalFirewallRule tolerated by logging to
// stdout and carrying on — a typo'd rule failed OPEN, and " 7" silently meant
// something different from "+7" because fmt.Sscan skips leading whitespace.
// Those forms are refused by domains.ParseAction at config load now, so they
// cannot reach this function; TestParseActionRejectsMalformedActions is where
// they live.
//
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
			// The FIRST matching absolute rule wins, because `default` returns
			// immediately. Every later absolute rule is dead. This is the single
			// place where evaluation ORDER changes the ANSWER rather than just
			// the arithmetic path taken to it -- increments and decrements are
			// commutative, so a reordered rule list is invisible everywhere else.
			//
			// A wave that reverses the loop, sorts rules by cost, or drains the
			// slice from the tail flips this from 1 to 9.
			name: "the first matching absolute rule wins, later absolutes are dead",
			rules: []domains.Rule{
				rule(t, match, "1"),
				rule(t, match, "9"),
			},
			susLv: 0,
			want:  1,
		},
		{
			// The operator-facing shape of the same fact. A config that reads
			// "trust this healthcheck, then be paranoid about everything else"
			// grants susLv 0. Reversed, the paranoid rule is reached first and
			// the healthcheck is challenged. Both rules match, both are
			// absolute, and nothing anywhere logs which one won.
			name: "config order decides the policy when two absolute rules both match",
			rules: []domains.Rule{
				rule(t, match, "0"),  // allow-healthcheck
				rule(t, match, "50"), // deny-all
			},
			susLv: 0,
			want:  0,
		},
		{
			// Mixed list: the increments before the first absolute are computed
			// and then thrown away, and the absolute AFTER it never runs.
			name: "increments before the first absolute are discarded, later absolutes never run",
			rules: []domains.Rule{
				rule(t, match, "+2"),
				rule(t, match, "3"),
				rule(t, match, "8"),
				rule(t, match, "+100"),
			},
			susLv: 0,
			want:  3,
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

// WAVE 13: two tests and the captureStdout helper were deleted here.
//
// TestEvalFirewallRuleReportsRuleIndexInOrder pinned the diagnostic
// EvalFirewallRule printed to stdout for a malformed action, including the
// rule index, because that print was "the only signal an operator gets that a
// rule is broken -- there is no validation at config load". There is now:
// domains.ParseAction runs in validate AND in build, so a malformed action
// never becomes a Rule and the per-request print is gone (it was also a log
// amplifier under a flood, and back-pressure into the request path whenever
// stdout blocked). Its second job, an independent tripwire on iteration order,
// is covered by TestEvalFirewallRuleOrdering's "first absolute action wins"
// case: two set actions in sequence give different answers front-to-back than
// back-to-front.
//
// TestEvalFirewallRuleEmptyActionPanics and its NonMatchingIsSafe counterpart
// pinned the traffic-triggered crash from rule.Action[:1] on an empty string.
// The switch is on a parsed operator now, so there is no slice to overrun; the
// refusal itself is TestParseActionRejectsMalformedActions below.

// TestParseActionRejectsMalformedActions is where every action form that used
// to reach the request path and misbehave now ends: at config load.
func TestParseActionRejectsMalformedActions(t *testing.T) {
	for _, action := range []string{
		"",                     // panicked the request goroutine on match
		"+",                    // empty operand
		"-",                    //
		"+abc",                 // logged per request and silently ignored
		"-abc",                 //
		"block",                //
		" 7",                   // Sscan skipped the space: " 7" != "+7", invisibly
		"7 ",                   //
		"+7x",                  //
		"1.5",                  // not an integer suspicion level
		"++1",                  //
		"+-1",                  // sign is the operator; no re-signing
		"99999999999999999999", // past the 31-bit ceiling
	} {
		t.Run("action="+strconv.Quote(action), func(t *testing.T) {
			if op, value, err := domains.ParseAction(action); err == nil {
				t.Errorf("ParseAction(%q) = (%v, %d, nil), want an error", action, op, value)
			}
		})
	}
}

// The forms an operator may actually write, and what they parse to.
func TestParseActionAcceptsEveryDocumentedForm(t *testing.T) {
	tests := []struct {
		action string
		op     domains.RuleOp
		value  int
	}{
		{"0", domains.RuleSet, 0},
		{"3", domains.RuleSet, 3},
		{"+2", domains.RuleAdd, 2},
		{"-5", domains.RuleSub, 5},
		{"+0", domains.RuleAdd, 0},
		{"-0", domains.RuleSub, 0},
	}
	for _, tt := range tests {
		t.Run(tt.action, func(t *testing.T) {
			op, value, err := domains.ParseAction(tt.action)
			if err != nil {
				t.Fatalf("ParseAction(%q): %v", tt.action, err)
			}
			if op != tt.op || value != tt.value {
				t.Errorf("ParseAction(%q) = (%v, %d), want (%v, %d)", tt.action, op, value, tt.op, tt.value)
			}
		})
	}
}

// TestEvalFirewallRuleIntField exercises a non-string field type end to end, so
// the test suite covers more of the DSL surface than string equality.
func TestEvalFirewallRuleIntField(t *testing.T) {
	currDomain := domains.DomainSettings{
		Name:        "example.com",
		CustomRules: []domains.Rule{rule(t, `ip.http_requests > 100`, "+2")},
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
			vars := gofilter.Message{"ip.http_requests": tt.requests}
			if got := EvalFirewallRule(currDomain, vars, 0); got != tt.want {
				t.Errorf("EvalFirewallRule(ip.http_requests=%d) = %d, want %d",
					tt.requests, got, tt.want)
			}
		})
	}
}

// WAVE 13: FLIPPED. This used to pin the fail-open: five DSL fields
// (ip.country, ip.asn, ip.requests, http.headers, http.body) were registered in
// core/firewall/filter.go but never supplied by the middleware, so a positive
// rule on one of them silently never fired and its NEGATION fired on every
// request on earth. Both halves were asserted here as current behaviour.
//
// The five names are gone from the registry, so such a rule no longer compiles
// and no longer reaches EvalFirewallRule at all: it is refused at config load,
// naming the field. What is pinned now is that refusal.
func TestUnsuppliedFieldsAreNotRegistered(t *testing.T) {
	for _, expr := range []string{
		`ip.country eq "CN"`,
		`ip.country ne "US"`,
		`ip.asn eq 13335`,
		`ip.requests > 100`,
		`http.headers contains "x-forwarded-for"`,
		`http.body contains "select"`,
	} {
		t.Run(expr, func(t *testing.T) {
			f, err := gofilter.NewFilter(expr)
			if err == nil {
				t.Fatalf("gofilter.NewFilter(%q) compiled; a field the request path never supplies must be refused at load, not fail open at runtime (filter=%v)", expr, f != nil)
			}
			if !strings.Contains(err.Error(), "does not exists") {
				t.Errorf("error = %q, want it to name the unknown field", err)
			}
		})
	}
}

// The counterpart: every name the registry DOES carry must compile. Without
// this, "fix" the fail-open by deleting the whole registry and the test above
// still passes.
func TestRegisteredFieldsCompile(t *testing.T) {
	operand := map[gofilter.FieldType]string{
		gofilter.FT_STRING: `eq "x"`,
		gofilter.FT_IP:     `eq 1.2.3.4`,
		gofilter.FT_INT:    `eq 1`,
		gofilter.FT_BOOL:   `eq true`,
	}
	for name, kind := range Fields {
		rhs, ok := operand[kind]
		if !ok {
			t.Fatalf("field %q has type %v, which this test does not know how to write an operand for", name, kind)
		}
		if _, err := gofilter.NewFilter(name + " " + rhs); err != nil {
			t.Errorf("registered field %q does not compile: %v", name, err)
		}
	}
}
