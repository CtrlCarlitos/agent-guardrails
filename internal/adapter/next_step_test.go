package adapter

import (
	"strings"
	"testing"

	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
)

// NextStep is what `guardrail explain` prints as the fix (#106). It must be
// the continuation the model was given, not a second copy that can drift, so
// every verdict's Guidance has to contain it verbatim.
func TestNextStepIsTheContinuationGuidanceGave(t *testing.T) {
	verdicts := []policy.Verdict{
		{Decision: policy.Deny, RuleID: "P1.rm-rf", Reason: "recursive delete"},
		{Decision: policy.Deny, RuleID: "P6.egress", Reason: "network access to a non-allowlisted host: example.test"},
		{Decision: policy.Deny, RuleID: "P4.secret-path", Reason: "secret"},
		{Decision: policy.Deny, RuleID: "some-future-rule", Reason: "new"},
		{Decision: policy.Ask, RuleID: "P6.package-install", Reason: "new JS dependency"},
		{Decision: policy.Ask, RuleID: "capability-external", Reason: "outward reach"},
		{Decision: policy.Ask, RuleID: "operator-action", Reason: "x", OperatorAction: "night-on"},
	}
	for _, v := range verdicts {
		step := NextStep(v)
		if step == "" {
			t.Errorf("NextStep(%s %s) is empty; every non-allow verdict must name a next step", v.Decision, v.RuleID)
			continue
		}
		if got := Guidance(v, "Bash {}"); !strings.Contains(got, step) {
			t.Errorf("Guidance(%s %s) does not contain NextStep %q:\n%s", v.Decision, v.RuleID, step, got)
		}
	}
	if got := NextStep(policy.Verdict{Decision: policy.Allow}); got != "" {
		t.Errorf("NextStep(allow) = %q, want empty", got)
	}
}

func TestNextStepForBrokeredOperatorActionNamesTheRequest(t *testing.T) {
	v := policy.Verdict{Decision: policy.Complete, RuleID: "operator-action", OperatorAction: "web-host-grant", RequestID: "req-123"}
	got := NextStep(v)
	for _, want := range []string{"web-host-grant", "req-123", "do not re-run this command"} {
		if !strings.Contains(got, want) {
			t.Errorf("NextStep(complete) = %q, missing %q", got, want)
		}
	}
	if got != operatorActionGuidance(v) {
		t.Errorf("NextStep(complete) must be the Claude operator-action guidance verbatim:\n got %q\nwant %q", got, operatorActionGuidance(v))
	}
}
