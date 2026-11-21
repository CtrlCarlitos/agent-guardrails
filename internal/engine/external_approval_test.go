package engine

import (
	"testing"
	"time"

	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
	"github.com/CtrlCarlitos/agent-guardrails/internal/session"
)

func TestConsequentialCommandRequiresFreshApproval(t *testing.T) {
	for _, tc := range []struct{ command, rule string }{
		{"npm publish", "P6.publish"},
		{"gh release delete v1", "P6.publish"},
		{"git push --tags && npm publish", "P6.publish"},
		{"wrangler deploy", "P6.deploy"},
		{"kubectl delete pod app", "P6.cluster-mutate"},
		{"terraform apply", "P6.cloud-mutate"},
	} {
		t.Run(tc.command, func(t *testing.T) {
			v := evalCred(t, tc.command)
			want := func(stage string, got policy.Verdict) {
				t.Helper()
				if got.Decision != policy.Ask || got.RuleID != tc.rule {
					t.Errorf("%s: got %+v, want ask/%s", stage, got, tc.rule)
				}
			}
			want("evaluation", v)
			want("Night", ApplyNightMode(v, true))
			if !policy.NeverGrantable(tc.rule) {
				t.Errorf("%s is still grantable", tc.rule)
			}
			now := time.Now()
			st := &session.State{}
			want("initial OpenCode approval", ApplyOpenCodeApproval(v, "key", st, now))
			want("OpenCode retry", ApplyOpenCodeApproval(v, "key", st, now))
			if got := ApplyOpenCodeHostApproval(v, "key", st, now); got.Decision != policy.Allow || got.OriginRuleID != tc.rule {
				t.Errorf("host-confirmed approval: got %+v", got)
			}
			pol := pathPol()
			pol.Waived = map[string]bool{tc.rule: true}
			want("waived policy", Evaluate(ToolCall{Plane: "claude", Tool: "Bash",
				Capability: policy.CapabilityCommand, Command: tc.command, CWD: "/repo", RepoRoot: "/repo"}, pol))
		})
	}
	if v := evalCred(t, "npm publish && git push --force"); v.Decision != policy.Deny || v.RuleID != "P1.git-push-force" {
		t.Errorf("stronger deny: got %+v, want deny/P1.git-push-force", v)
	}
}
