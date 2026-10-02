package adapter

import (
	"strings"
	"testing"

	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
)

// #449: after prompt mode (ADR-0033) became the default and the Windows
// broker landed, several agent-facing strings still steered agents away from
// asking, or named no concrete next step.
func TestGuidanceAuditSteersAgentsToTheirNextStep(t *testing.T) {
	must := func(name, got string, want ...string) {
		t.Helper()
		for _, w := range want {
			if !strings.Contains(got, w) {
				t.Errorf("%s lacks %q: %q", name, w, got)
			}
		}
	}
	mustNot := func(name, got string, bad ...string) {
		t.Helper()
		for _, b := range bad {
			if strings.Contains(got, b) {
				t.Errorf("%s still says %q: %q", name, b, got)
			}
		}
	}

	// A: an ask that names an operator action is not passkey-only.
	a := NextStep(policy.Verdict{Decision: policy.Ask, RuleID: "some-ask", OperatorAction: "plane-enable"})
	mustNot("operator-action ask", a, "not through chat")
	must("operator-action ask", a, "host", "approval URL", "terminal")

	// B: the lifecycle line lets the agent run the exact command so the host asks.
	b := PlaneLifecycleLine("claude", "absent", 0)
	mustNot("lifecycle line", b, "tell the operator to run")
	must("lifecycle line", b, "`guardrail plane enable claude`", "on its own", "asks the operator")
	drift := PlaneLifecycleLine("claude", "guardrail hook registered", 2)
	mustNot("lifecycle drift line", drift, "the operator should run")
	must("lifecycle drift line", drift, "`guardrail plane enable claude`", "asks the operator")

	// C: the session posture says what to do on an ask and on a deny.
	c := PostureText(nil, nil)
	must("posture", c, "On an ask", "retry the exact call on its own", "On a deny", "next step")
	// #491: and how to write commands that do not ask at all. It must not
	// suggest moving logic into a script file: a script's contents are an
	// unseen execution path (ADR-0033), so that would step around the
	// analysis rather than satisfy it.
	must("posture", c, "literal absolute paths", "`git -C <dir>`")
	mustNot("posture", c, "script file", "script")

	// D: the self-config deny names a concrete command.
	d := NextStep(policy.Verdict{Decision: policy.Deny, RuleID: "P5.self-config"})
	mustNot("self-config deny", d, "terminal recovery command")
	must("self-config deny", d, "`guardrail doctor`")
}
