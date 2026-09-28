package engine

import (
	"testing"

	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
)

func evalOn(tool, command string) policy.Verdict {
	root := repoRootForHost()
	return Evaluate(ToolCall{Plane: "opencode", Tool: tool, NativeTool: tool, Capability: policy.CapabilityCommand,
		Command: command, CWD: root, RepoRoot: root}, cmdPol())
}

// `2>$null` is PowerShell's discard: $null is a constant that cannot be
// reassigned. Every command carrying it asked P3.unresolved, including a plain
// `rg --files … 2>$null | Out-String` an OpenCode agent ran on Windows
// (audit 2026-09-28), which the agent then worked around instead of running.
func TestNullRedirectIsADiscard(t *testing.T) {
	for _, tool := range []string{"Bash", "PowerShell"} {
		for _, command := range []string{
			`rg --files -g '!*.zsh' scripts dot_config 2>$null | Out-String`,
			`rg foo 2>$null`,
			`grep -rn foo scripts 2>$null`,
			`ls 2>$null`,
			`ls >$null`,
			`ls *>$null`,
			`Get-ChildItem 2>$NULL`,
			`rg foo 2>$Null`,
		} {
			if v := evalOn(tool, command); v.Decision != policy.Allow {
				t.Errorf("%s %q -> %s %s, want allow", tool, command, v.Decision, v.RuleID)
			}
		}
	}
}

// Only the exact `$null` word is a discard; a same-command assignment to it is
// still resolved and judged as the write it is, and look-alikes stay unknown.
func TestNullRedirectLookAlikesStayJudged(t *testing.T) {
	for _, command := range []string{
		`ls >$nullx`,
		`ls >${null}x`,
		`ls >$null/x`,
		`ls >"$null.txt"`,
		`ls >$HOME`,
	} {
		if v := evalOn("Bash", command); v.Decision == policy.Allow {
			t.Errorf("%q -> allow, want the unresolved target judged", command)
		}
	}
	if v := evalOn("Bash", `null=/etc/passwd; ls >$null`); v.Decision == policy.Allow {
		t.Errorf("an assigned $null redirect was allowed: %s %s", v.Decision, v.RuleID)
	}
}

// rg --pre runs the named program on every file searched, so `rg --pre rm x ~`
// deletes files a direct rm would be asked about. rg itself stays allowed.
func TestRgPreprocessorAsks(t *testing.T) {
	for _, command := range []string{
		`rg --pre rm foo ~`,
		`rg --pre=rm foo`,
		`rg --pre ./x.sh foo`,
		`rg -i --pre /tmp/evil foo .`,
		`rg.exe --pre cat foo`,
	} {
		if v := evalOn("Bash", command); v.Decision != policy.Ask || v.RuleID != "P1.rg-preprocessor" {
			t.Errorf("%q -> %s %s, want ask P1.rg-preprocessor", command, v.Decision, v.RuleID)
		}
	}
	for _, command := range []string{
		`rg --files -g '!*.zsh' scripts`,
		`rg -n foo .`,
		`rg --no-pre foo`,
		`rg --pre-glob '*.gz' foo`,
		`rg -- --pre`,
		`grep -rn -- --pre .`,
	} {
		if v := evalOn("Bash", command); v.RuleID == "P1.rg-preprocessor" {
			t.Errorf("%q -> %s %s, want no preprocessor verdict", command, v.Decision, v.RuleID)
		}
	}
}
