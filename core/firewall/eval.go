package firewall

import (
	"github.com/azferius/lancarsec/core/domains"

	"github.com/azferius/lancarsec/core/gofilter"
)

// EvalFirewallRule folds the operator's rules into a suspicion level.
//
// WAVE 13: the action is read from the pre-parsed Op/Value that config build
// produced. It used to be re-derived here, per matching rule, per request:
// rule.Action[:1] to pick the operator and fmt.Sscan to read the number —
// reflection and an allocation on the hot path, on the one code path an
// attacker can drive as fast as they like. A parse failure also printed to
// stdout on every request, which under a flood is a log amplifier and, when
// stdout blocks, back-pressure into the request path.
//
// The slice was also unguarded: an empty action panicked the request goroutine
// the first time its rule MATCHED — latent until the right request arrived.
// The syntax now has exactly one parser (domains.ParseAction) and it runs at
// config load, so a rule that reaches this function is a rule that parsed.
func EvalFirewallRule(currDomain domains.DomainSettings, variables gofilter.Message, susLv int) int {
	result := susLv
	for _, rule := range currDomain.CustomRules {
		if !rule.Filter.Apply(variables) {
			continue
		}
		switch rule.Op {
		case domains.RuleAdd:
			result += rule.Value
		case domains.RuleSub:
			result -= rule.Value
		default:
			// A set action is final: it replaces the level and stops the walk.
			return rule.Value
		}
	}
	return result
}
