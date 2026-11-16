package engine

import (
	"strings"
	"testing"

	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
)

// #605: the escalated deny (#559/ADR-0035) must name the cheapest handoff,
// not only "the operator's terminal". On Claude Code the operator can run the
// exact command in-session with `! <command>`, and the same call in the
// host's default permission mode is an ask. Other planes keep the terminal
// sentence: they have no known in-session escape.

func escalate(t *testing.T, plane, tool, command string) policy.Verdict {
	t.Helper()
	v := Evaluate(ToolCall{Tool: tool, Plane: plane, Command: command, CWD: "/repo", RepoRoot: "/repo", HostAutoApproves: true}, pathPol())
	if v.RuleID != "host-auto-ask-escalated" {
		t.Fatalf("%s %q: verdict %+v, want host-auto-ask-escalated", plane, command, v)
	}
	return v
}

func TestEscalatedAskOnClaudeNamesTheBangHandoffAndDefaultMode(t *testing.T) {
	v := escalate(t, "claude", "Bash", "git push origin main")
	for _, want := range []string{"`! git push origin main`", "default permission mode"} {
		if !strings.Contains(v.Reason, want) {
			t.Errorf("reason lacks %q:\n%s", want, v.Reason)
		}
	}
}

func TestEscalatedAskOnOtherPlanesKeepsTheTerminalSentence(t *testing.T) {
	for _, plane := range []string{"opencode", "antigravity", "codex"} {
		v := escalate(t, plane, "Bash", "git push origin main")
		if !strings.Contains(v.Reason, "in their terminal") {
			t.Errorf("%s: reason lost the terminal sentence:\n%s", plane, v.Reason)
		}
		if strings.Contains(v.Reason, "`!") {
			t.Errorf("%s: reason names Claude Code's ! escape:\n%s", plane, v.Reason)
		}
	}
}

// #605 part 2: an unresolvable command is usually read-only. The useful next
// step is to make it resolvable, so the guidance says that before it says
// "ask the operator". Both live shapes from the issue are covered: a compound
// PowerShell call interpolating $LASTEXITCODE and a bash substitution around
// `gh run list`; tokenize-failed is the same class.
func TestEscalatedUnresolvedLeadsWithMakingItResolvable(t *testing.T) {
	for _, c := range []struct{ tool, cmd, origin string }{
		{"PowerShell", `hostname; git status; $LASTEXITCODE; Write-Output "exit $LASTEXITCODE"`, "P3.unresolved"},
		{"Bash", `run=$(gh run list --limit 1 --json databaseId -q '.[0].databaseId'); gh run view $run`, "P3.unresolved"},
		{"PowerShell", `& $exe --version`, "tokenize-failed"},
	} {
		for _, plane := range []string{"claude", "opencode"} {
			v := escalate(t, plane, c.tool, c.cmd)
			if v.OriginRuleID != c.origin {
				t.Fatalf("%q: origin %q, want %q", c.cmd, v.OriginRuleID, c.origin)
			}
			split := strings.Index(v.Reason, "separate")
			operator := strings.Index(v.Reason, "operator")
			if split == -1 || operator == -1 || split > operator {
				t.Errorf("%s %q: reason must lead with splitting into resolvable commands, then the operator:\n%s", plane, c.cmd, v.Reason)
			}
		}
	}
}
