package engine

import (
	"testing"

	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
)

// PowerShell accepts an en dash, em dash or horizontal bar wherever a
// parameter takes a hyphen. The parameter reader only knew the hyphen, so
// `Remove-Item –Recurse –Force` showed it no -Recurse and no -Force, and the
// rule that owns recursive deletes never ran.
func TestWindowsPowerShellUnicodeDashParametersAreRead(t *testing.T) {
	outside := outsideRepoTarget()
	for _, dash := range []string{"-", "\u2013", "\u2014", "\u2015"} {
		cases := []struct{ cmd, rule string }{
			{"Remove-Item " + dash + "Recurse " + dash + "Force " + outside, "P1.rm-rf"},
			{"Remove-Item " + dash + "rec " + dash + "fo " + outside, "P1.rm-rf"},
			{"Set-ExecutionPolicy " + dash + "ExecutionPolicy Bypass", "P1.execution-policy"},
			{"pwsh " + dash + "EncodedCommand ZQBjAGgAbwA=", "P6.dynamic-eval"},
			{"powershell " + dash + "e ZQBjAGgAbwA=", "P6.dynamic-eval"},
		}
		for _, c := range cases {
			v := evalEnv(t, c.cmd)
			if v.RuleID != c.rule || v.Decision == policy.Allow {
				t.Errorf("%q: got %s %s (%s), want %s", c.cmd, v.Decision, v.RuleID, v.Reason, c.rule)
			}
		}
	}
}

// -WhatIf is PowerShell's dry run and removes nothing; it must still be read
// as -WhatIf under any dash, not turn into an operand.
func TestWindowsPowerShellUnicodeDashWhatIfIsStillADryRun(t *testing.T) {
	for _, dash := range []string{"-", "\u2013"} {
		cmd := "Remove-Item " + dash + "Recurse " + dash + "Force " + dash + "WhatIf notes.txt"
		if v := evalEnv(t, cmd); v.RuleID == "P1.rm-rf" {
			t.Errorf("%q: got %s %s, want no P1.rm-rf verdict", cmd, v.Decision, v.RuleID)
		}
	}
}
