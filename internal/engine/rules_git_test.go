package engine

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
)

func evalGitSafety(t *testing.T, cmd string) *policy.Verdict {
	t.Helper()
	repo := t.TempDir()
	initGitRepository(t, repo, false)
	return checkBash(ToolCall{Tool: "Bash", Command: cmd, CWD: repo, RepoRoot: repo}, bashPol())
}

func initGitRepository(t *testing.T, path string, bare bool) {
	t.Helper()
	args := []string{"init", "--quiet"}
	if bare {
		args = append(args, "--bare")
	}
	args = append(args, path)
	if output, err := exec.Command("git", args...).CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v: %s", args, err, output)
	}
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
	for _, c := range []string{
		"git push origin main",
		"git push origin master",
		"git push --tags",
		"git push --repo origin --tags",
		"git push --tags --repo=origin feature",
	} {
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

func TestGitPushFirstPositionalOperandIsAlwaysRepository(t *testing.T) {
	for _, command := range []string{
		`git push --repo=origin +main`,
		`git push +main --repo=origin`,
		`git push --repo origin +main`,
		`git push +main --repo origin`,
		`git push --rep=origin +main`,
		`git push +main --rep origin`,
		`git push --repo=origin -- +main`,
		`git push +main -- --repo=origin`,
		`git push --no-repo +main`,
		`git push +main --no-repo`,
		`git push main feature --repo=origin`,
		`git push --repo=origin main feature`,
	} {
		if v := evalBash(t, command); v != nil {
			t.Errorf("%q -> %+v, want nil", command, v)
		}
	}
}

func TestGitPushPositionalRepositoryPrecedesRepoOption(t *testing.T) {
	cases := map[string]struct {
		decision policy.Decision
		ruleID   string
	}{
		`git push --repo=backup origin +main`:                 {policy.Deny, "P2.git-push-force"},
		`git push origin +main --repo=backup`:                 {policy.Deny, "P2.git-push-force"},
		`git push --repo backup origin +HEAD:refs/heads/main`: {policy.Deny, "P2.git-push-force"},
		`git push origin +HEAD:refs/heads/main --rep backup`:  {policy.Deny, "P2.git-push-force"},
		`git push --repo=backup origin :main`:                 {policy.Ask, "P2.git-push-delete"},
		`git push origin :refs/heads/old --repo backup`:       {policy.Ask, "P2.git-push-delete"},
		`git push --repo=backup origin dev:main`:              {policy.Ask, "P2.git-push-protected"},
		`git push origin HEAD:refs/heads/master --rep=backup`: {policy.Ask, "P2.git-push-protected"},
		`git push --repo=backup -- origin +main`:              {policy.Deny, "P2.git-push-force"},
		`git push --no-repo origin +main`:                     {policy.Deny, "P2.git-push-force"},
	}
	for command, want := range cases {
		v := evalBash(t, command)
		if v == nil || v.Decision != want.decision || v.RuleID != want.ruleID {
			t.Errorf("%q -> %+v, want %s/%s", command, v, want.decision, want.ruleID)
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

func TestGitConfigReadsRemainAllowed(t *testing.T) {
	for _, c := range []string{
		"git config user.email",
		"git config --get user.name",
		"git config --global --get user.name",
		"git config --system --list",
		"git config --file /tmp/config --get user.name",
		"git config -f/tmp/config --get user.name",
		"git config --blob HEAD:.gitmodules --get submodule.x.url",
		"git config --list",
	} {
		if v := evalGitSafety(t, c); v != nil {
			t.Errorf("%q (read) -> %+v, want nil", c, v)
		}
	}
}

func TestGitConfigLocalWritesClassifyEveryKey(t *testing.T) {
	for _, command := range []string{
		`git config user.email x@y.com`,
		`git config USER.Name bot`,
		`git config init.defaultBranch main`,
		`git config commit.gpgsign true`,
		`git config advice.detachedHead false`,
		`git config color.ui auto`,
		`git config user.email -hidden`,
		`git config -- user.email x@y.com`,
	} {
		if v := evalGitSafety(t, command); v != nil {
			t.Errorf("%q -> %+v, want allow", command, v)
		}
	}

	for _, command := range []string{
		`git config core.hooksPath /tmp/evil`,
		`git config CORE.FSMONITOR /tmp/evil`,
		`git config core.sshCommand evil`,
		`git config core.pager evil`,
		`git config core.editor evil`,
		`git config credential.helper evil`,
		`git config include.path /tmp/evil`,
		`git config includeIf.gitdir:/repo.path /tmp/evil`,
		`git config alias.status !evil`,
	} {
		v := evalGitSafety(t, command)
		if v == nil || v.Decision != policy.Deny || v.RuleID != "P2.git-config-write" {
			t.Errorf("%q -> %+v, want deny/P2.git-config-write", command, v)
		}
	}

	v := evalGitSafety(t, `git config merge.tool custom`)
	if v == nil || v.Decision != policy.Ask || v.RuleID != "P2.git-config-write" {
		t.Fatalf("unclassified local key -> %+v, want ask/P2.git-config-write", v)
	}
}

func TestGitConfigWriteScopesDoNotChangeReadsAndFailClosed(t *testing.T) {
	for _, command := range []string{
		`git config --global user.email x@y.com`,
		`git config --system color.ui auto`,
		`git config --file /tmp/config user.email x@y.com`,
		`git config --file=/tmp/config user.email x@y.com`,
		`git config -f /tmp/config user.email x@y.com`,
		`git config -f/tmp/config user.email x@y.com`,
		`git config --global --edit`,
	} {
		v := evalGitSafety(t, command)
		if v == nil || v.Decision != policy.Deny || v.RuleID != "P2.git-config-write" {
			t.Errorf("%q -> %+v, want deny/P2.git-config-write", command, v)
		}
	}

	for _, command := range []string{
		`git config --worktree user.email x@y.com`,
		`git config --worktree merge.tool custom`,
		`git config --edit`,
	} {
		v := evalGitSafety(t, command)
		if v == nil || v.Decision != policy.Ask || v.RuleID != "P2.git-config-write" {
			t.Errorf("%q -> %+v, want ask/P2.git-config-write", command, v)
		}
	}

	v := evalGitSafety(t, `git config --worktree core.hooksPath /tmp/evil`)
	if v == nil || v.Decision != policy.Deny || v.RuleID != "P2.git-config-write" {
		t.Fatalf("dangerous worktree key -> %+v, want deny/P2.git-config-write", v)
	}
}

func TestGitConfigMutationOperationsAndSections(t *testing.T) {
	for _, command := range []string{
		`git config --add user.email x@y.com`,
		`git config --add user.email -hidden`,
		`git config --replace-all color.ui auto`,
		`git config --unset advice.detachedHead`,
		`git config --unset-all user.email`,
		`git config --rename-section user color`,
		`git config --remove-section advice`,
	} {
		if v := evalGitSafety(t, command); v != nil {
			t.Errorf("%q -> %+v, want allow", command, v)
		}
	}

	for _, command := range []string{
		`git config --remove-section core`,
		`git config --rename-section core user`,
		`git config --rename-section user core`,
		`git config --rename-section credential color`,
		`git config --remove-section alias`,
	} {
		v := evalGitSafety(t, command)
		if v == nil || v.Decision != policy.Deny || v.RuleID != "P2.git-config-write" {
			t.Errorf("%q -> %+v, want deny/P2.git-config-write", command, v)
		}
	}

	for _, command := range []string{
		`git config --rename-section user merge`,
		`git config --remove-section merge`,
	} {
		v := evalGitSafety(t, command)
		if v == nil || v.Decision != policy.Ask || v.RuleID != "P2.git-config-write" {
			t.Errorf("%q -> %+v, want ask/P2.git-config-write", command, v)
		}
	}
}

func TestGitConfigMalformedAndUnknownOptionsAsk(t *testing.T) {
	for _, command := range []string{
		`git config --add user.email`,
		`git config --replace-all user.email`,
		`git config --rename-section user`,
		`git config --remove-section`,
		`git config --get`,
		`git config --future-option user.email x@y.com`,
		`git config -Z user.email x@y.com`,
		`git config user.email x@y.com extra extra`,
	} {
		v := evalGitSafety(t, command)
		if v == nil || v.Decision != policy.Ask || v.RuleID != "P2.git-config-write" {
			t.Errorf("%q -> %+v, want ask/P2.git-config-write", command, v)
		}
	}
}

func TestGitConfigLocalWritesRequireTheToolCallRepository(t *testing.T) {
	repo := t.TempDir()
	other := t.TempDir()
	initGitRepository(t, repo, false)
	initGitRepository(t, other, false)
	subdirectory := filepath.Join(repo, "sub")
	if err := os.Mkdir(subdirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	approved := `config user.email x@y.com`
	for _, command := range []string{
		`git ` + approved,
		`git -C . ` + approved,
		fmt.Sprintf(`git -C %q %s`, repo, approved),
		fmt.Sprintf(`git -C%q %s`, repo, approved),
		fmt.Sprintf(`git --git-dir %q %s`, filepath.Join(repo, ".git"), approved),
		fmt.Sprintf(`git --git-dir=%q %s`, filepath.Join(repo, ".git"), approved),
	} {
		tc := ToolCall{Tool: "Bash", Command: command, CWD: repo, RepoRoot: repo}
		if v := checkBash(tc, bashPol()); v != nil {
			t.Errorf("%q -> %+v, want allow in ToolCall repository", command, v)
		}
	}
	tc := ToolCall{Tool: "Bash", Command: `git ` + approved, CWD: subdirectory, RepoRoot: repo}
	if v := checkBash(tc, bashPol()); v != nil {
		t.Errorf("git config from repository subdirectory -> %+v, want allow", v)
	}

	foreignBare := filepath.Join(repo, "foreign.git")
	initGitRepository(t, foreignBare, true)

	for _, command := range []string{
		fmt.Sprintf(`git -C %q %s`, other, approved),
		fmt.Sprintf(`git --git-dir %q %s`, filepath.Join(other, ".git"), approved),
		fmt.Sprintf(`GIT_DIR=%q git %s`, filepath.Join(other, ".git"), approved),
		fmt.Sprintf(`env GIT_DIR=%q git %s`, filepath.Join(other, ".git"), approved),
		fmt.Sprintf(`git --git-dir=%q %s`, foreignBare, approved),
	} {
		tc := ToolCall{Tool: "Bash", Command: command, CWD: repo, RepoRoot: repo}
		v := checkBash(tc, bashPol())
		if v == nil || v.Decision != policy.Ask || v.RuleID != "P2.git-config-write" {
			t.Errorf("%q -> %+v, want ask/P2.git-config-write for another repository", command, v)
		}
	}

	tc = ToolCall{Tool: "Bash", Command: `GIT_DIR="$TARGET" git ` + approved, CWD: repo, RepoRoot: repo}
	v := checkBash(tc, bashPol())
	if v == nil || v.Decision != policy.Ask || v.RuleID != "P3.unresolved" {
		t.Errorf("dynamic GIT_DIR -> %+v, want ask/P3.unresolved", v)
	}

	command := fmt.Sprintf(`GIT_DIR=%q; printf -v GIT_DIR %q; git %s`, filepath.Join(repo, ".git"), filepath.Join(other, ".git"), approved)
	tc = ToolCall{Tool: "Bash", Command: command, CWD: repo, RepoRoot: repo}
	v = checkBash(tc, bashPol())
	if v == nil || v.Decision != policy.Ask || v.RuleID != "P3.unresolved" {
		t.Errorf("mutated GIT_DIR -> %+v, want ask/P3.unresolved", v)
	}
}

func TestGitConfigIdentityNeverExecutesAttemptedGitPath(t *testing.T) {
	repo := t.TempDir()
	initGitRepository(t, repo, false)
	attacker := filepath.Join(t.TempDir(), "git")
	marker := filepath.Join(t.TempDir(), "executed")
	script := fmt.Sprintf("#!/bin/sh\nprintf touched > %q\nprintf '%%s\\n' %q\n", marker, filepath.Join(repo, ".git"))
	if err := os.WriteFile(attacker, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}

	command := fmt.Sprintf(`%q config user.email x@y.com`, attacker)
	tc := ToolCall{Tool: "Bash", Command: command, CWD: repo, RepoRoot: repo}
	if v := checkBash(tc, bashPol()); v != nil {
		t.Fatalf("attacker-path Git config -> %+v, want trusted-probe allow", v)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("policy evaluation executed attempted Git path; marker stat error = %v", err)
	}
}

func TestGitIdentityProbeTimesOutAndFailsClosed(t *testing.T) {
	probe := filepath.Join(t.TempDir(), "git")
	if err := os.WriteFile(probe, []byte("#!/bin/sh\nsleep 2\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	_, ok := gitCommonDirectory(probe, nil, t.TempDir(), nil, true)
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("Git identity probe took %s, want bounded execution", elapsed)
	}
	if ok {
		t.Fatal("timed-out Git identity probe succeeded, want fail closed")
	}
}

func TestUnrelatedVariableMutationsDoNotTaintGitIdentity(t *testing.T) {
	repo := t.TempDir()
	initGitRepository(t, repo, false)
	for _, command := range []string{
		`printf -v TARGET /etc; git config user.email x@y.com`,
		`read TARGET < /repo/input; git config user.email x@y.com`,
		`declare TARGET=/etc; git config user.email x@y.com`,
	} {
		tc := ToolCall{Tool: "Bash", Command: command, CWD: repo, RepoRoot: repo}
		if v := checkBash(tc, bashPol()); v != nil {
			t.Errorf("%q -> %+v, want allow", command, v)
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
		"git config core.hooksPath /evil": {policy.Deny, "P2.git-config-write"},
		"git config user.email x@y.com":   {policy.Allow, ""},
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
			if want.decision == policy.Allow {
				if v != nil {
					t.Errorf("%q -> %+v, want allow", full, v)
				}
				continue
			}
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
