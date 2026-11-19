package engine

import (
	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
	"testing"
)

func TestDeliveryCannotAuthorizeItself(t *testing.T) {
	for _, command := range []string{
		"guardrail delivery enable --github owner/repo",
		"guardrail.exe delivery enable --github owner/repo",
		"script -qc 'guardrail delivery enable --github owner/repo' /dev/null",
		"guardrail delivery status enable",
	} {
		v := evalBash(t, command)
		if v == nil || v.Decision != policy.Deny || v.RuleID != "P5.self-config" {
			t.Errorf("self-authorization %q: %+v", command, v)
		}
	}
	for _, command := range []string{
		"guardrail delivery status",
		"guardrail delivery finish --pr 123 --head 1111111111111111111111111111111111111111",
		// #616: help is read-only; only enable/revoke change posture. A
		// session must be able to discover the operations and flags.
		"guardrail delivery --help",
		"guardrail delivery -h",
		"guardrail delivery help",
		"guardrail delivery",
	} {
		if v := evalBash(t, command); v != nil && v.RuleID == "P5.self-config" {
			t.Errorf("executor/status blocked: %s %+v", command, v)
		}
	}
}
