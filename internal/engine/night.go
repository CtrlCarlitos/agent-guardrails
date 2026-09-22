package engine

import "github.com/CtrlCarlitos/agent-guardrails/internal/policy"

// The asks preserved here -- outward reach (ADR-0018) and unclassified tools
// -- are read from policy.NeverRelaxable rather than listed again, because an
// operator-issued command grant is the same kind of relaxation through a
// narrower door and must honour the same set. Two copies of this list is
// exactly the shape of thing that rots when one is edited and the other is
// not, so there is one copy and both mechanisms read it.
func ApplyNightMode(v policy.Verdict, active bool) policy.Verdict {
	if !active || v.Decision != policy.Ask || policy.NeverRelaxable(v.RuleID) {
		return v
	}
	return policy.Verdict{
		Decision:     policy.Allow,
		RuleID:       "ask-allowed-by-night-mode",
		OriginRuleID: v.RuleID,
		Reason:       "allowed by active night mode",
	}
}
