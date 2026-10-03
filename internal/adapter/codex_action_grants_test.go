package adapter

import (
	"strings"
	"testing"

	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
)

func TestWindowsAndPOSIXCodexAskWithoutRequestDoesNotPromiseACommandGrant(t *testing.T) {
	text := CodexAskGuidance(policy.Verdict{Decision: policy.Ask, RuleID: "P5.ci-infra-lockfile", Reason: "private store unavailable"}, false)
	if strings.Contains(text, "single-use grant") || strings.Contains(text, "approvals grant") {
		t.Fatalf("a patch without a request has no command grant: %s", text)
	}
	if !strings.Contains(text, "No exact-action approval request was recorded") {
		t.Fatalf("missing actionable store failure: %s", text)
	}
}
