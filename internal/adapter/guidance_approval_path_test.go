package adapter

import (
	"strings"
	"testing"

	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
)

// Agents stall on Asks that should resolve in seconds because the guidance
// says "request authorization" and they read that as "find a technical
// approval mechanism" (#129). Observed: a P5.ci-infra-lockfile ask sent an
// agent hunting for a URL and concluding "no approval path"; a
// P2.git-push-delete ask sent another to `guardrail approvals list`.
//
// Deny verdicts already get per-rule continuations through denyNextStep. Ask
// verdicts had one generic sentence for every rule, which is the gap.

// A policy ask has no URL, no daemon and no approvals command. Saying so
// explicitly is the fix: the failure was agents looking for machinery that
// does not exist, not agents missing an instruction.
func TestPolicyAskNamesTheConversationalPath(t *testing.T) {
	for _, rule := range []string{
		"P5.ci-infra-lockfile",
		"P2.git-push-delete",
		"P1.chmod",
		"P6.package-install",
		"P6.publish",
	} {
		v := policy.Verdict{Decision: policy.Ask, RuleID: rule, Reason: "needs approval"}
		got := Guidance(v, `bash {"command":"x"}`)
		if !strings.Contains(got, "conversational") {
			t.Errorf("%s ask does not name the conversational path:\n%s", rule, got)
		}
		// The specific wrong turns the issue recorded, ruled out by name.
		for _, wrongTurn := range []string{"approval URL", "guardrail approvals"} {
			if !strings.Contains(got, wrongTurn) {
				t.Errorf("%s ask does not rule out %q, which is where agents went:\n%s", rule, wrongTurn, got)
			}
		}
	}
}

// An operator action really does go through the broker with a passkey. That
// one has a URL, and the guidance must surface it rather than send the agent
// to chat.
func TestBrokerAskNamesTheURLPath(t *testing.T) {
	v := policy.Verdict{
		Decision:       policy.Ask,
		RuleID:         "operator-action",
		Reason:         "operator action requires approval",
		OperatorAction: "egress-grant",
		ApprovalURL:    "http://localhost:8765/approve/abc",
		RequestID:      "abc",
	}
	got := Guidance(v, `bash {"command":"guardrail egress grant"}`)
	if !strings.Contains(got, "http://localhost:8765/approve/abc") {
		t.Errorf("broker ask does not surface the approval URL:\n%s", got)
	}
	if strings.Contains(got, "conversational") {
		t.Errorf("broker ask was described as conversational, which sends the agent to chat instead of the passkey:\n%s", got)
	}
}

// The path is decided by whether the verdict actually carries broker state,
// not by a rule-name list that would rot as rules are added.
func TestApprovalPathIsStructuralNotARuleList(t *testing.T) {
	withURL := policy.Verdict{Decision: policy.Ask, RuleID: "anything-at-all",
		Reason: "r", ApprovalURL: "http://localhost:1/x"}
	if strings.Contains(Guidance(withURL, "a"), "conversational") {
		t.Error("a verdict carrying an approval URL was called conversational")
	}

	withAction := policy.Verdict{Decision: policy.Ask, RuleID: "anything-at-all",
		Reason: "r", OperatorAction: "night-off"}
	if strings.Contains(Guidance(withAction, "a"), "conversational") {
		t.Error("a verdict carrying an operator action was called conversational")
	}

	plain := policy.Verdict{Decision: policy.Ask, RuleID: "brand-new-rule", Reason: "r"}
	if !strings.Contains(Guidance(plain, "a"), "conversational") {
		t.Error("a new rule with no broker state should default to the conversational path")
	}
}

// The existing contract is load-bearing across four plane tests; the path
// sentence is added to it, not substituted for it.
func TestAskGuidanceKeepsItsExistingContract(t *testing.T) {
	v := policy.Verdict{Decision: policy.Ask, RuleID: "P1.chmod", Reason: "needs approval"}
	got := Guidance(v, `bash {"command":"chmod -R 777 /tmp"}`)
	for _, want := range []string{
		"Operator authorization required: needs approval.",
		`Request authorization for this exact action: bash {"command":"chmod -R 777 /tmp"}.`,
		"If the operator approves, retry this exact tool call within 10 minutes.",
		"Do not alter or broaden the action.",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("ask guidance dropped an existing sentence %q:\n%s", want, got)
		}
	}
}

// A deny is not an approval path at all, and must not grow one.
func TestDenyGuidanceDoesNotGainAnApprovalPath(t *testing.T) {
	v := policy.Verdict{Decision: policy.Deny, RuleID: "P1.rm-rf", Reason: "destructive"}
	got := Guidance(v, "a")
	if strings.Contains(got, "conversational") {
		t.Errorf("deny guidance describes an approval path:\n%s", got)
	}
}
