package engine

import (
	"time"

	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
)

// GrantRuleID marks an allow that exists only because an operator issued a
// grant for this exact command. It is deliberately not an ordinary allow: a
// grant must make an action louder in the record, not quieter, so
// `guardrail audit --verdicts` can answer "what did this grant actually
// authorize" and not only "a grant existed".
const GrantRuleID = "ask-allowed-by-operator-grant"

// ApplyCommandGrant rewrites an Ask into an Allow when the operator has issued
// a grant for exactly this (repository, rule, command).
//
// It only ever looks at an Ask. A Deny stays a Deny and an Allow is already
// one, so deny invariance is inherited by construction rather than restated as
// a second rule that could be forgotten. The exclusion check runs here as well
// as at issuance, so a grant recorded by hand -- or left behind by an older
// binary that did not know a rule had become un-grantable -- still cannot
// relax outward reach.
func ApplyCommandGrant(v policy.Verdict, tc ToolCall, op *policy.OperatorConfig, now time.Time) policy.Verdict {
	if v.Decision != policy.Ask || tc.Command == "" || tc.RepoRoot == "" {
		return v
	}
	if !op.AllowsCommand(tc.RepoRoot, v.RuleID, tc.Command, now) {
		return v
	}
	return policy.Verdict{
		Decision:     policy.Allow,
		RuleID:       GrantRuleID,
		OriginRuleID: v.RuleID,
		Reason:       "allowed by an operator-issued grant for this exact command",
	}
}
