package engine

import (
	"testing"

	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
)

func TestApplyNightModeOnlyRewritesAsk(t *testing.T) {
	tests := []struct {
		name   string
		active bool
		input  policy.Verdict
		want   policy.Verdict
	}{
		{
			name:   "active ask",
			input:  policy.Verdict{Decision: policy.Ask, RuleID: "P1.git-push-protected", Reason: "push needs approval"},
			active: true,
			want: policy.Verdict{
				Decision:     policy.Allow,
				RuleID:       "ask-allowed-by-night-mode",
				OriginRuleID: "P1.git-push-protected",
				Reason:       "allowed by active night mode",
			},
		},
		{
			name:   "inactive ask",
			input:  policy.Verdict{Decision: policy.Ask, RuleID: "P1.git-push-protected", Reason: "push needs approval"},
			active: false,
			want:   policy.Verdict{Decision: policy.Ask, RuleID: "P1.git-push-protected", Reason: "push needs approval"},
		},
		{
			name:   "active allow",
			input:  policy.Verdict{Decision: policy.Allow, RuleID: "default-allow", Reason: "no rule matched"},
			active: true,
			want:   policy.Verdict{Decision: policy.Allow, RuleID: "default-allow", Reason: "no rule matched"},
		},
		{
			name:   "active deny",
			input:  policy.Verdict{Decision: policy.Deny, RuleID: "P1.rm-rf", Reason: "destructive command"},
			active: true,
			want:   policy.Verdict{Decision: policy.Deny, RuleID: "P1.rm-rf", Reason: "destructive command"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ApplyNightMode(tt.input, tt.active); got != tt.want {
				t.Fatalf("ApplyNightMode(%+v, %v) = %+v, want %+v", tt.input, tt.active, got, tt.want)
			}
		})
	}
}
