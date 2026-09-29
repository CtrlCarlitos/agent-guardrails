package adapter

import (
	"strings"
	"testing"

	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
)

// TestWindowsAskGuidanceOffersInSessionApproval pins #446. Since #164 every
// Windows ask ended "in-session approval is not yet available: the operator
// can run this exact action from a terminal instead", meant to be removed when
// the ADR-0021 broker landed. It landed and was never removed. An OpenCode
// agent on Windows (2026-09-29, P2.git-worktree-remove) read it as "approval
// cannot work here", handed the commands to the operator's terminal instead
// of asking, and when the operator said "approved" retried a different,
// extended command, which asked again. The exact-retry approval works on
// Windows: the same machine recorded `ask-approved-by-retry` that day.
func TestWindowsAskGuidanceOffersInSessionApproval(t *testing.T) {
	v := policy.Verdict{Decision: policy.Ask, RuleID: "P2.git-worktree-remove", Reason: "git worktree remove discards a working tree"}
	got := Guidance(v, `bash {"command":"git worktree remove .worktrees/x"}`)
	for _, stale := range []string{"not yet available", "from a terminal instead"} {
		if strings.Contains(got, stale) {
			t.Errorf("ask guidance still sends the agent to the operator's terminal (%q): %q", stale, got)
		}
	}
	for _, want := range []string{
		"say what you need to the operator",
		"retry the exact call once they approve",
		// The retry must be the same command alone: adding a step makes it a
		// new action, which asks again.
		"on its own",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("ask guidance lacks %q: %q", want, got)
		}
	}
}
