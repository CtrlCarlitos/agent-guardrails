package adapter

import (
	"strings"
	"testing"

	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
)

// #125, measured on every plane: an egress deny sent the agent to a grant
// with placeholder hosts that, once approved, still left curl denied (a grant
// authorizes `guardrail fetch`, not curl), and a native web-fetch deny told
// the agent to "complete the work by other means". Both taught agents to stop
// trying. The model-facing text (after the 512-rune bound) must carry the
// fetch path, the grant, and the instruction not to self-censor.
func TestEgressDenyGuidanceLeadsToGuardrailFetchAndTheGrant(t *testing.T) {
	cases := []policy.Verdict{
		{Decision: policy.Deny, RuleID: "P6.egress",
			Reason: "network access to a non-allowlisted host: starship.rs; grant: " + policy.WebHostGrantCommand("starship.rs")},
		{Decision: policy.Deny, RuleID: "web-fetch-native-deny",
			Reason: "native web fetch cannot verify redirect destinations; use guardrail fetch"},
	}
	for _, v := range cases {
		got := guidanceForModel(v, `WebFetch {"url":"https://starship.rs/presets/","prompt":"summarize the presets page"}`)
		// The rule ID is how the agent reports the verdict; the longer next
		// step must not push it past the model-facing bound.
		for _, want := range []string{"guardrail fetch", "guardrail egress grant", "passkey", "Do not skip a fetch because an earlier one was denied.", "rule ID (" + v.RuleID + ")"} {
			if !strings.Contains(got, want) {
				t.Errorf("%s guidance missing %q:\n%s", v.RuleID, want, got)
			}
		}
		for _, stale := range []string{"api.example.com", "Complete the work by other means"} {
			if strings.Contains(got, stale) {
				t.Errorf("%s guidance still says %q:\n%s", v.RuleID, stale, got)
			}
		}
	}
	egress := guidanceForModel(cases[0], "Bash {}")
	if !strings.Contains(egress, "not curl or wget") {
		t.Errorf("P6.egress guidance must say a grant does not unblock curl:\n%s", egress)
	}
}
