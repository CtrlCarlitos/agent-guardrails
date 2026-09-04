package engine

import (
	"testing"

	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
)

func evalGitSafety(t *testing.T, cmd string) *policy.Verdict {
	t.Helper()
	return checkBash(ToolCall{Tool: "Bash", Command: cmd, CWD: "/repo", RepoRoot: "/repo"}, bashPol())
}

func TestGitResetHardDenied(t *testing.T) {
	for _, c := range []string{"git reset --hard", "git reset --hard HEAD~3", "git reset --keep"} {
		v := evalGitSafety(t, c)
		if v == nil || v.Decision != policy.Deny || v.RuleID != "P2.git-reset-hard" {
			t.Errorf("%q -> %+v, want deny/P2.git-reset-hard", c, v)
		}
	}
	if v := evalGitSafety(t, "git reset --soft HEAD~1"); v != nil {
		t.Errorf("git reset --soft should be nil, got %+v", v)
	}
}

func TestGitConfigWriteDenied(t *testing.T) {
	for _, c := range []string{
		"git config user.email x@y.com",
		"git config --global user.name bot",
		"git config core.hooksPath /tmp/evil",
	} {
		v := evalGitSafety(t, c)
		if v == nil || v.Decision != policy.Deny || v.RuleID != "P2.git-config-write" {
			t.Errorf("%q -> %+v, want deny/P2.git-config-write", c, v)
		}
	}
	for _, c := range []string{"git config user.email", "git config --get user.name", "git config --list"} {
		if v := evalGitSafety(t, c); v != nil {
			t.Errorf("%q (read) -> %+v, want nil", c, v)
		}
	}
}
