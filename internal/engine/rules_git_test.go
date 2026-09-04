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
	for _, c := range []string{"git reset --hard", "git reset --hard HEAD~3", "git reset --keep", "/usr/bin/git reset --hard"} {
		v := evalGitSafety(t, c)
		if v == nil || v.Decision != policy.Deny || v.RuleID != "P2.git-reset-hard" {
			t.Errorf("%q -> %+v, want deny/P2.git-reset-hard", c, v)
		}
	}
	if v := evalGitSafety(t, "git reset --soft HEAD~1"); v != nil {
		t.Errorf("git reset --soft should be nil, got %+v", v)
	}
}

func TestGitAskTier(t *testing.T) {
	cases := map[string]string{
		"git checkout .":                        "P2.git-checkout-restore",
		"git checkout -- .":                     "P2.git-checkout-restore",
		"git restore .":                         "P2.git-checkout-restore",
		"git branch -D feature/x":               "P2.git-branch-delete",
		"git branch --delete --force feature/x": "P2.git-branch-delete",
		"git commit --amend":                    "P2.git-history-rewrite",
		"git filter-branch --tree-filter x":     "P2.git-history-rewrite",
		"git filter-repo --invert-paths":        "P2.git-history-rewrite",
		"git reflog expire --expire=now --all":  "P2.git-history-rewrite",
		"git gc --prune=now":                    "P2.git-history-rewrite",
		"git remote add origin https://x":       "P2.git-remote-add",
		"git remote set-url origin https://x":   "P2.git-remote-add",
		"git stash clear":                       "P2.git-stash-clear",
		"git stash drop":                        "P2.git-stash-clear",
	}
	for c, id := range cases {
		v := evalGitSafety(t, c)
		if v == nil || v.Decision != policy.Ask || v.RuleID != id {
			t.Errorf("%q -> %+v, want ask/%s", c, v, id)
		}
	}
	for _, c := range []string{"git checkout main", "git branch -d merged-branch", "git remote -v", "git stash list"} {
		if v := evalGitSafety(t, c); v != nil {
			t.Errorf("%q -> %+v, want nil", c, v)
		}
	}
}

func TestGitPushProtected(t *testing.T) {
	for _, c := range []string{"git push origin main", "git push origin master", "git push --tags"} {
		v := evalGitSafety(t, c)
		if v == nil || v.Decision != policy.Ask || v.RuleID != "P2.git-push-protected" {
			t.Errorf("%q -> %+v, want ask/P2.git-push-protected", c, v)
		}
	}
	if v := evalGitSafety(t, "git push origin feature/x"); v != nil {
		t.Errorf("feature branch push -> %+v, want nil", v)
	}
	// force-push to main is still P1's deny, not this ask — most-severe wins regardless.
	v := evalGitSafety(t, "git push --force origin main")
	if v == nil || v.Decision != policy.Deny {
		t.Errorf("force push to main -> %+v, want deny (P1 wins)", v)
	}
}

func TestForceWithLeaseDenied(t *testing.T) {
	for _, c := range []string{"git push --force-with-lease origin main", "git push --force-with-lease origin feature/x"} {
		v := evalGitSafety(t, c)
		if v == nil || v.Decision != policy.Deny || v.RuleID != "P1.git-push-force" {
			t.Errorf("%q -> %+v, want deny/P1.git-push-force", c, v)
		}
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

func TestGitRulesSurvivePrefixes(t *testing.T) {
	prefixes := []string{"", "-C . ", "-c a.b=c ", "-C . -c a.b=c "}
	cases := map[string]struct {
		decision policy.Decision
		ruleID   string
	}{
		"git push --force origin main":    {policy.Deny, "P1.git-push-force"},
		"git clean -fd":                   {policy.Deny, "P1.git-clean"},
		"git reset --hard":                {policy.Deny, "P2.git-reset-hard"},
		"git config user.email x@y.com":   {policy.Deny, "P2.git-config-write"},
		"git checkout .":                  {policy.Ask, "P2.git-checkout-restore"},
		"git branch -D feature/x":         {policy.Ask, "P2.git-branch-delete"},
		"git commit --amend":              {policy.Ask, "P2.git-history-rewrite"},
		"git remote add origin https://x": {policy.Ask, "P2.git-remote-add"},
		"git stash clear":                 {policy.Ask, "P2.git-stash-clear"},
		"git push origin main":            {policy.Ask, "P2.git-push-protected"},
	}
	for cmd, want := range cases {
		for _, pfx := range prefixes {
			full := "git " + pfx + cmd[len("git "):]
			v := evalGitSafety(t, full)
			if v == nil {
				t.Errorf("%q -> nil, want %s/%s", full, want.decision, want.ruleID)
				continue
			}
			if v.Decision != want.decision || v.RuleID != want.ruleID {
				t.Errorf("%q -> %s/%s, want %s/%s", full, v.Decision, v.RuleID, want.decision, want.ruleID)
			}
		}
	}
}

func TestGitPrefixesDontCreateFalsePositives(t *testing.T) {
	prefixes := []string{"", "-C . ", "-c a.b=c "}
	safe := []string{"git status", "git log --oneline -5", "git diff", "git fetch"}
	for _, cmd := range safe {
		for _, pfx := range prefixes {
			full := "git " + pfx + cmd[len("git "):]
			if v := evalGitSafety(t, full); v != nil {
				t.Errorf("%q -> %+v, want nil", full, v)
			}
		}
	}
}
