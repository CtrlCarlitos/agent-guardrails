package engine

import "github.com/CtrlCarlitos/agent-guardrails/internal/policy"

// nightPreservedAsks are never relaxed: outward reach (ADR-0018) and
// unclassified tools stay operator decisions even overnight.
var nightPreservedAsks = map[string]bool{
	"capability-external":   true,
	"capability-web-search": true,
	"unknown-native-tool":   true,
}

func ApplyNightMode(v policy.Verdict, active bool) policy.Verdict {
	if !active || v.Decision != policy.Ask || nightPreservedAsks[v.RuleID] {
		return v
	}
	return policy.Verdict{
		Decision:     policy.Allow,
		RuleID:       "ask-allowed-by-night-mode",
		OriginRuleID: v.RuleID,
		Reason:       "allowed by active night mode",
	}
}
