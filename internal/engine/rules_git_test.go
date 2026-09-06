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

func TestGitAdditionalDestructiveVerbsAsk(t *testing.T) {
	cases := map[string]string{
		`git update-ref -d refs/heads/main`:    "P2.git-ref-delete",
		`git worktree remove --force old`:      "P2.git-worktree-remove",
		`git switch --discard-changes feature`: "P2.git-discard",
		`git rm -r src`:                        "P2.git-rm",
		`git rm -f generated.go`:               "P2.git-rm",
		`git rm -rf build`:                     "P2.git-rm",
	}
	for command, ruleID := range cases {
		v := evalGitSafety(t, command)
		if v == nil || v.Decision != policy.Ask || v.RuleID != ruleID {
			t.Errorf("%q -> %+v, want ask/%s", command, v, ruleID)
		}
	}
}

func TestGitAdditionalDestructiveVerbOptionValuesDoNotAsk(t *testing.T) {
	for _, command := range []string{
		`git update-ref refs/heads/d refs/heads/main`,
		`git update-ref -m -d refs/heads/topic deadbeef`,
		`git worktree list`,
		`git switch discard-changes`,
		`git switch --conflict --discard-changes topic`,
		`git rm --cached generated.go`,
		`git rm --pathspec-from-file -f`,
	} {
		if v := evalGitSafety(t, command); v != nil {
			t.Errorf("%q -> %+v, want nil", command, v)
		}
	}
}

func TestGitAdditionalDestructiveVerbsHonorUniqueLongOptionAbbreviations(t *testing.T) {
	cases := map[string]string{
		`git switch --discard-c feature`: "P2.git-discard",
		`git rm --forc generated.go`:     "P2.git-rm",
	}
	for command, ruleID := range cases {
		v := evalGitSafety(t, command)
		if v == nil || v.Decision != policy.Ask || v.RuleID != ruleID {
			t.Errorf("%q -> %+v, want ask/%s", command, v, ruleID)
		}
	}
}

func TestGitAdditionalVerbAmbiguousPrefixesAndOptionValuesDoNotAsk(t *testing.T) {
	for _, command := range []string{
		`git switch --d feature`,
		`git switch --conf --discard-changes topic`,
		`git rm --pathspec-from-f --force`,
	} {
		if v := evalGitSafety(t, command); v != nil {
			t.Errorf("%q -> %+v, want nil", command, v)
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

func TestGitPushRefspecForms(t *testing.T) {
	deny := []string{`git push origin +main`, `git push origin +HEAD:refs/heads/main`}
	for _, c := range deny {
		v := evalBash(t, c)
		if v == nil || v.Decision != policy.Deny || v.RuleID != "P2.git-push-force" {
			t.Errorf("%q -> %+v, want deny/P2.git-push-force (+refspec is a force push)", c, v)
		}
	}
	ask := map[string]string{
		`git push origin :main`:                    "P2.git-push-delete",
		`git push origin main:main`:                "P2.git-push-protected",
		`git push origin dev:main`:                 "P2.git-push-protected",
		`git push origin HEAD:refs/heads/main`:     "P2.git-push-protected",
		`git push origin HEAD:refs/heads/master`:   "P2.git-push-protected",
		`git push origin :refs/heads/feature-gone`: "P2.git-push-delete",
		`git push --repo default origin main`:      "P2.git-push-protected",
		`git push --repo=default origin main`:      "P2.git-push-protected",
	}
	for c, id := range ask {
		v := evalBash(t, c)
		if v == nil || v.Decision != policy.Ask || v.RuleID != id {
			t.Errorf("%q -> %+v, want ask/%s", c, v, id)
		}
	}
	if v := evalBash(t, `git push origin dev:feature-x`); v != nil {
		t.Errorf("non-protected refspec -> %+v, want nil", v)
	}
}

func TestGitPushRefspecParsingSkipsRemoteAndOptionValues(t *testing.T) {
	for _, c := range []string{
		`git push main feature-x`,
		`git push -o main origin feature-x`,
		`git push --push-option main origin feature-x`,
		`git push origin -o main feature-x`,
		`git push --repo main feature-x`,
	} {
		if v := evalBash(t, c); v != nil {
			t.Errorf("%q -> %+v, want nil", c, v)
		}
	}
}

func TestGitPushRepoOptionMakesFollowingOperandARefspec(t *testing.T) {
	cases := map[string]struct {
		decision policy.Decision
		ruleID   string
	}{
		`git push --repo origin +main`:          {policy.Deny, "P2.git-push-force"},
		`git push --repo=origin +main`:          {policy.Deny, "P2.git-push-force"},
		`git push --repo origin :main`:          {policy.Ask, "P2.git-push-delete"},
		`git push --repo=origin dev:main`:       {policy.Ask, "P2.git-push-protected"},
		`git push --repo origin --tags`:         {policy.Ask, "P2.git-push-protected"},
		`git push --tags --repo=origin feature`: {policy.Ask, "P2.git-push-protected"},
	}
	for command, want := range cases {
		v := evalBash(t, command)
		if v == nil || v.Decision != want.decision || v.RuleID != want.ruleID {
			t.Errorf("%q -> %+v, want %s/%s", command, v, want.decision, want.ruleID)
		}
	}

	for _, command := range []string{
		`git push --repo origin feature`,
		`git push --repo=origin dev:feature`,
	} {
		if v := evalBash(t, command); v != nil {
			t.Errorf("%q -> %+v, want nil", command, v)
		}
	}
}

func TestGitPushForceRefspecOutranksEarlierAsk(t *testing.T) {
	for _, c := range []string{
		`git push origin main +feature`,
		`git push origin :old +feature`,
	} {
		v := evalBash(t, c)
		if v == nil || v.Decision != policy.Deny || v.RuleID != "P2.git-push-force" {
			t.Errorf("%q -> %+v, want deny/P2.git-push-force", c, v)
		}
	}
}

func TestGitPushDeleteFlagsAsk(t *testing.T) {
	for _, c := range []string{
		`git push -d origin old`,
		`git push --delete origin old`,
		`git push origin -d old`,
		`git push origin --delete old`,
	} {
		v := evalBash(t, c)
		if v == nil || v.Decision != policy.Ask || v.RuleID != "P2.git-push-delete" {
			t.Errorf("%q -> %+v, want ask/P2.git-push-delete", c, v)
		}
	}
}

func TestGitPushForceParsingIgnoresValuesAndLiteralOperands(t *testing.T) {
	for _, c := range []string{
		`git push -o --force origin feature`,
		`git push -o--force origin feature`,
		`git push --push-option --force origin feature`,
		`git push --push-option=--force origin feature`,
		`git push -- --force`,
		`git push origin -- --force`,
		`git push -- -f`,
		`git push -of origin feature`,
	} {
		if v := evalBash(t, c); v != nil {
			t.Errorf("%q -> %+v, want nil", c, v)
		}
	}
}

func TestGitPushForceControlsStillDeny(t *testing.T) {
	for _, c := range []string{
		`git push -f origin feature`,
		`git push -qf origin feature`,
		`git push -fq origin feature`,
		`git push --force origin feature`,
		`git push --force-with-lease origin feature`,
		`git push --force-with-lease=main:expect origin feature`,
	} {
		v := evalBash(t, c)
		if v == nil || v.Decision != policy.Deny || v.RuleID != "P1.git-push-force" {
			t.Errorf("%q -> %+v, want deny/P1.git-push-force", c, v)
		}
	}
}

func TestGitPushUniqueLongOptionAbbreviations(t *testing.T) {
	cases := map[string]struct {
		decision policy.Decision
		ruleID   string
	}{
		`git push --force-w origin feature`:              {policy.Deny, "P1.git-push-force"},
		`git push --force-w=main:expect origin feature`:  {policy.Deny, "P1.git-push-force"},
		`git push --dele origin old`:                     {policy.Ask, "P2.git-push-delete"},
		`git push --ta`:                                  {policy.Ask, "P2.git-push-protected"},
		`git push --no-force-w --force-w origin feature`: {policy.Deny, "P1.git-push-force"},
		`git push --no-dele --dele origin old`:           {policy.Ask, "P2.git-push-delete"},
		`git push --no-ta --ta`:                          {policy.Ask, "P2.git-push-protected"},
	}
	for c, want := range cases {
		v := evalBash(t, c)
		if v == nil || v.Decision != want.decision || v.RuleID != want.ruleID {
			t.Errorf("%q -> %+v, want %s/%s", c, v, want.decision, want.ruleID)
		}
	}
}

func TestGitPushAbbreviatedValueOptionsConsumeValues(t *testing.T) {
	for _, c := range []string{
		`git push --push-o --force origin feature`,
		`git push --push-o=--force origin feature`,
		`git push --receive-p --force origin feature`,
		`git push --push-o`,
		`git push --repo`,
	} {
		if v := evalBash(t, c); v != nil {
			t.Errorf("%q -> %+v, want nil", c, v)
		}
	}
}

func TestGitPushAmbiguousLongOptionPrefixesDoNotSetState(t *testing.T) {
	for _, c := range []string{
		`git push --for origin feature`,
		`git push --d origin feature`,
		`git push --t origin feature`,
	} {
		if v := evalBash(t, c); v != nil {
			t.Errorf("%q -> %+v, want nil (ambiguous option must not resolve)", c, v)
		}
	}
}

func TestGitPushBooleanNegationIsSequential(t *testing.T) {
	allow := []string{
		`git push --force --no-force origin feature`,
		`git push -f --no-force origin feature`,
		`git push --force-with-lease --no-force-with-lease origin feature`,
		`git push --force-w --no-force-w origin feature`,
		`git push --delete --no-delete origin feature`,
		`git push -d --no-delete origin feature`,
		`git push --tags --no-tags origin feature`,
	}
	for _, c := range allow {
		if v := evalBash(t, c); v != nil {
			t.Errorf("%q -> %+v, want nil (last negated option wins)", c, v)
		}
	}

	deny := []string{
		`git push --no-force --force origin feature`,
		`git push --no-force -f origin feature`,
		`git push --force-with-lease --no-force origin feature`,
		`git push --force --no-force-with-lease origin feature`,
	}
	for _, c := range deny {
		v := evalBash(t, c)
		if v == nil || v.Decision != policy.Deny || v.RuleID != "P1.git-push-force" {
			t.Errorf("%q -> %+v, want deny/P1.git-push-force", c, v)
		}
	}

	ask := map[string]string{
		`git push --no-delete --delete origin old`: "P2.git-push-delete",
		`git push --no-tags --tags`:                "P2.git-push-protected",
	}
	for c, ruleID := range ask {
		v := evalBash(t, c)
		if v == nil || v.Decision != policy.Ask || v.RuleID != ruleID {
			t.Errorf("%q -> %+v, want ask/%s", c, v, ruleID)
		}
	}
}

func TestGitPushNegatedOptionsDoNotConsumeRepository(t *testing.T) {
	for _, c := range []string{
		`git push --force --no-force origin main`,
		`git push --delete --no-delete origin main`,
		`git push --tags --no-tags origin main`,
		`git push --push-option value --no-push-option origin main`,
		`git push --repo default --no-repo origin main`,
		`git push --recurse-submodules check --no-recurse-submodules origin main`,
	} {
		v := evalBash(t, c)
		if v == nil || v.Decision != policy.Ask || v.RuleID != "P2.git-push-protected" {
			t.Errorf("%q -> %+v, want ask/P2.git-push-protected", c, v)
		}
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

func TestGitSpaceFormGlobalOptions(t *testing.T) {
	deny := []string{
		`git --git-dir /r/.git push --force origin main`,
		`git --work-tree /r --git-dir /r/.git clean -fdx`,
		`git --git-dir /r/.git config --global core.hooksPath /tmp/evil`,
		`git --work-tree /r reset --hard`,
		`git --exec-path /x clean -fdx`,
		`git --attr-source HEAD push --force`,
		`git --super-prefix x reset --hard`,
		`git --config-env=k=V push --force`,
	}
	for _, c := range deny {
		v := evalBash(t, c)
		if v == nil || v.Decision != policy.Deny {
			t.Errorf("%q -> %+v, want deny", c, v)
		}
	}
}

func TestGitKnownValuelessGlobalsStillParse(t *testing.T) {
	for _, c := range []string{`git --no-pager reset --hard`, `git -p reset --hard`, `git -P reset --hard`, `git --bare reset --hard`} {
		v := evalBash(t, c)
		if v == nil || v.Decision != policy.Deny {
			t.Errorf("%q -> %+v, want deny (valueless global must not shift the subcommand)", c, v)
		}
	}
}

func TestGitUnknownGlobalFailsClosed(t *testing.T) {
	for _, c := range []string{
		`git --some-future-option x reset --hard`,
		`git --future=x status`,
		`git -- status`,
	} {
		v := evalBash(t, c)
		if v == nil || v.Decision != policy.Ask || v.RuleID != "P2.git-unknown-global" {
			t.Errorf("%q -> %+v, want ask/P2.git-unknown-global", c, v)
		}
	}
}

func TestGitUnknownGlobalDoesNotDowngradeKnownDeny(t *testing.T) {
	cases := map[string]string{
		`git --future=x reset --hard`:                         "P2.git-reset-hard",
		`git --future=x config --global core.hooksPath /evil`: "P2.git-config-write",
		`git --future=x push --force origin main`:             "P1.git-push-force",
	}
	for c, ruleID := range cases {
		v := evalBash(t, c)
		if v == nil || v.Decision != policy.Deny || v.RuleID != ruleID {
			t.Errorf("%q -> %+v, want deny/%s", c, v, ruleID)
		}
	}
}

func TestGitAttachedShortGlobalsReachRules(t *testing.T) {
	cases := map[string]string{
		`git -C/r reset --hard`:                          "P2.git-reset-hard",
		`git -ca=b config --global core.hooksPath /evil`: "P2.git-config-write",
		`git -C/r push --force origin main`:              "P1.git-push-force",
	}
	for c, ruleID := range cases {
		v := evalBash(t, c)
		if v == nil || v.Decision != policy.Deny || v.RuleID != ruleID {
			t.Errorf("%q -> %+v, want deny/%s", c, v, ruleID)
		}
	}
}

func TestGitReadOnlyStillAllowed(t *testing.T) {
	for _, c := range []string{
		`git status`,
		`git --no-pager log --oneline`,
		`git -p log --oneline`,
		`git -C . diff`,
		`git -C/r diff`,
		`git -ca=b status`,
	} {
		if v := evalBash(t, c); v != nil {
			t.Errorf("%q -> %+v, want nil", c, v)
		}
	}
}
