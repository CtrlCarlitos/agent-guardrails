package adapter

import (
	"strings"
	"testing"

	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
)

func TestGuidanceAskRequiresAuthorizationForExactAction(t *testing.T) {
	v := policy.Verdict{Decision: policy.Ask, Reason: "external egress needs approval"}
	got := Guidance(v, `bash {"command":"curl https://example.test"}`)
	for _, want := range []string{
		"Operator authorization required: external egress needs approval.",
		`Request authorization for this exact action: bash {"command":"curl https://example.test"}.`,
		"If the operator approves, retry this exact tool call within 10 minutes. If the authorization expires, stop and wait for the operator to return — say what you were doing and that approval expired; do not keep retrying.",
		"Do not alter or broaden the action.",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("Guidance() = %q, missing %q", got, want)
		}
	}
}

func TestGuidanceDenyIsActionablePerRule(t *testing.T) {
	cases := []struct {
		ruleID string
		reason string
		wants  []string
	}{
		{
			ruleID: "capability-deny",
			wants:  []string{"outside the Guardrail boundary on this plane", "Do not retry it", "in-session tools", "tell the operator", "continue"},
		},
		{
			ruleID: "capability-delegation-unverified",
			wants:  []string{"Do not delegate", "perform the work yourself in this session", "continue"},
		},
		{
			ruleID: "unknown-native-tool",
			wants:  []string{"unclassified", "supported tool", "continue"},
		},
		{
			ruleID: "capability-input-missing",
			wants:  []string{"could not be projected", "explicit file paths", "continue"},
		},
		{
			ruleID: "capability-input-invalid",
			wants:  []string{"could not be projected", "full HTTP URL", "continue"},
		},
		{
			ruleID: "P4.secret-path",
			wants:  []string{"secret_allow", "Exclude this path", "continue the rest of the task"},
		},
		{
			ruleID: "P5.self-config",
			wants:  []string{"Guardrail-protected", "operator", "Continue other work"},
		},
		{
			ruleID: "P6.egress",
			wants:  []string{"not authorized", "Batch the exact domains", "guardrail egress grant", "continue offline work"},
		},
		{
			ruleID: "P1.rm-rf",
			wants:  []string{"Destructive", "do not retry", "reversible alternative", "continue the task"},
		},
		{
			ruleID: "P1.git-push-force",
			wants:  []string{"Destructive", "do not retry", "continue the task"},
		},
		{
			ruleID: "P2.git-reset-hard",
			wants:  []string{"Protected git state", "git revert", "continue"},
		},
		{
			ruleID: "P2.git-protected-path",
			wants:  []string{"Protected git state", "continue"},
		},
		{
			ruleID: "P4.symlink-escape",
			wants:  []string{"Symlink escape", "real target path", "continue"},
		},
		{
			ruleID: "P6.download-pipe-shell",
			wants:  []string{"piped into a shell", "Download to a file", "separate reviewed step"},
		},
		{
			ruleID: "P4.secret-in-text",
			wants:  []string{"mentioned in the command's text", "not a shell literal", "Write or Edit tool", "continue"},
		},
		{
			ruleID: "P5.self-config",
			reason: "interpreter input mentions guardrail night control; Guardrail cannot tell a mention from an invocation",
			wants:  []string{"mention", "Write or Edit tool", "continue"},
		},
	}
	for _, tc := range cases {
		reason := tc.reason
		if reason == "" {
			reason = "unit-test reason"
		}
		v := policy.Verdict{Decision: policy.Deny, RuleID: tc.ruleID, Reason: reason}
		got := Guidance(v, `bash {"command":"x"}`)
		prefix := "Guardrail denied this action: " + reason + "."
		if !strings.HasPrefix(got, prefix) {
			t.Errorf("%s: Guidance() = %q, want prefix %q", tc.ruleID, got, prefix)
		}
		if strings.Contains(got, "Choose a safe alternative") {
			t.Errorf("%s: Guidance() = %q contains dead-end phrase", tc.ruleID, got)
		}
		for _, want := range tc.wants {
			if !strings.Contains(got, want) {
				t.Errorf("%s: Guidance() = %q, missing %q", tc.ruleID, got, want)
			}
		}
	}
}

func TestGuidanceDenyFallbackStillDirectsWork(t *testing.T) {
	v := policy.Verdict{Decision: policy.Deny, RuleID: "P9.something-new", Reason: "future rule"}
	got := Guidance(v, `bash {"command":"x"}`)
	if !strings.Contains(got, "Guardrail denied this action: future rule.") {
		t.Fatalf("Guidance() = %q, missing denial prefix", got)
	}
	if strings.Contains(got, "Choose a safe alternative") || strings.Contains(got, "It cannot be authorized.") {
		t.Fatalf("Guidance() = %q, fallback is a dead end", got)
	}
	for _, want := range []string{"Do not retry this exact call", "other means", "operator"} {
		if !strings.Contains(got, want) {
			t.Fatalf("Guidance() = %q, missing %q", got, want)
		}
	}
}
