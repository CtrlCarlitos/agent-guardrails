package engine

import (
	"testing"

	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
)

// `approvals grant` and `approvals approve` authorize things for the session
// that asked. Until #416 only the CLI's hard-coded operatorTerminal=false kept
// a session from running them; the Engine allowed every spelling below,
// including the terminal-faking wrappers. Wiring the real terminal check into
// the CLI is only safe once these are denied here.
func TestSessionCannotGrantOrApproveItself(t *testing.T) {
	for _, command := range []string{
		`guardrail approvals grant --repo /r --rule P6.egress --command 'curl x'`,
		`guardrail approvals approve abc123`,
		`guardrail.exe approvals approve abc123`,
		`GUARDRAIL approvals grant --repo /r --rule X --command y`,
		`script -qc 'guardrail approvals grant --repo /r --rule X --command y' /dev/null`,
		`unbuffer guardrail approvals approve abc123`,
		`winpty guardrail approvals grant --repo /r --rule X --command y`,
		`python3 -c "import pty; pty.spawn(['guardrail','approvals','approve','abc'])"`,
		`true && guardrail approvals approve abc123`,
	} {
		v := evalBash(t, command)
		if v == nil || v.Decision != policy.Deny || v.RuleID != "P5.self-config" {
			t.Errorf("%q -> %+v, want deny/P5.self-config", command, v)
		}
	}
	// Reading grants and giving them up change nothing a session could abuse.
	for _, command := range []string{
		`guardrail approvals list`,
		`guardrail approvals list --grants`,
		`guardrail approvals revoke --repo /r --rule X --command y`,
	} {
		if v := evalBash(t, command); v != nil && v.RuleID == "P5.self-config" {
			t.Errorf("%q -> %+v, want no self-config verdict", command, v)
		}
	}
}
