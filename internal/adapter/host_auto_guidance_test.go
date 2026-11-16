package adapter

import (
	"strings"
	"testing"

	"github.com/CtrlCarlitos/agent-guardrails/internal/engine"
	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
)

// #605: what the agent reads is the model-facing text after the 512-rune
// bound. The handoff must survive that bound, the rule ID must still be
// reportable, and the deny's next step must not contradict the handoff with
// the generic "involve the operator only if this exact step is required".
func TestEscalatedDenyGuidanceCarriesTheHandoffWithinTheModelBound(t *testing.T) {
	cases := []struct {
		plane, tool, cmd string
		want             []string
	}{
		{"claude", "Bash", "git worktree remove .worktrees/feature-x",
			[]string{"`! git worktree remove .worktrees/feature-x`", "default permission mode"}},
		{"opencode", "Bash", "git worktree remove .worktrees/feature-x",
			[]string{"in their terminal"}},
		{"claude", "PowerShell", `hostname; git status; $LASTEXITCODE; Write-Output "exit $LASTEXITCODE"`,
			[]string{"separate", "`!`"}},
		// The longest command quoted inline (48 runes) with the longest
		// common origin rule must still leave the rule ID reportable.
		{"claude", "Bash", "git worktree remove .worktrees/" + strings.Repeat("x", 48-len("git worktree remove .worktrees/")),
			[]string{"`! git worktree remove .worktrees/xxx", "default permission mode"}},
		// Past the bound the command is not quoted; the handoff still is.
		{"claude", "Bash", "git worktree remove .worktrees/" + strings.Repeat("y", 80),
			[]string{"`! <the exact command>`", "default permission mode"}},
	}
	for _, c := range cases {
		tc := engine.ToolCall{Tool: c.tool, Plane: c.plane, Command: c.cmd, CWD: "/repo", RepoRoot: "/repo", HostAutoApproves: true}
		v := engine.Evaluate(tc, &policy.Policy{})
		if v.RuleID != "host-auto-ask-escalated" {
			t.Fatalf("%s %q: verdict %+v", c.plane, c.cmd, v)
		}
		got := guidanceForModel(v, c.cmd)
		for _, want := range append(c.want, "rule ID (host-auto-ask-escalated)") {
			if !strings.Contains(got, want) {
				t.Errorf("%s %q: model guidance lacks %q:\n%s", c.plane, c.cmd, want, got)
			}
		}
		if strings.Contains(got, "Complete the work by other means") {
			t.Errorf("%s: next step contradicts the handoff:\n%s", c.plane, got)
		}
	}
}
