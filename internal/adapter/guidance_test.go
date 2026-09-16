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
		"If the operator approves, retry this exact tool call once.",
		"Do not alter or broaden the action.",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("Guidance() = %q, missing %q", got, want)
		}
	}
}

func TestGuidanceDenyCannotBeAuthorized(t *testing.T) {
	v := policy.Verdict{Decision: policy.Deny, Reason: "destructive path is protected"}
	got := Guidance(v, `bash {"command":"rm -rf /"}`)
	if got != "Guardrail denied this action: destructive path is protected. It cannot be authorized. Choose a safe alternative." {
		t.Fatalf("Guidance() = %q", got)
	}
}
