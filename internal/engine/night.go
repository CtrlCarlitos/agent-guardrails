package engine

import "github.com/CtrlCarlitos/agent-guardrails/internal/policy"

func ApplyNightMode(v policy.Verdict, active bool) policy.Verdict {
	if !active || v.Decision != policy.Ask {
		return v
	}
	return policy.Verdict{
		Decision:     policy.Allow,
		RuleID:       "ask-allowed-by-night-mode",
		OriginRuleID: v.RuleID,
		Reason:       "allowed by active night mode",
	}
}
