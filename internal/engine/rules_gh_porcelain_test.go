package engine

import (
	"testing"

	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
)

// The `gh api` rule (#252) reads the method out of a flag and classifies the
// endpoint. Every porcelain equivalent reached the same endpoints with no
// method flag to read, and was allowed -- measured on 772392d, the whole
// porcelain surface was allow.
//
// That left the Engine weaker than its own backstop. The declarative floor
// (ADR-0022) already denies `gh repo delete` and asks on `gh secret set`,
// `gh pr merge`, `gh release create` and `gh workflow run`; the floor exists
// for when the Engine is unreachable, so the Engine being the more permissive
// of the two is backwards. It also meant the porcelain was ungated entirely on
// every plane that does not carry Claude's settings floor, and that a mutation
// reached the audit log as an ordinary allow with no rule attribution.
//
// The porcelain spelling is also the easier one. `gh repo delete o/r --yes` is
// what an agent reaches for; `gh api -X DELETE repos/o/r` is what it reaches
// for only if the first one is blocked.

func ghVerdict(t *testing.T, command string) policy.Verdict {
	t.Helper()
	return evalCred(t, command)
}

func assertGh(t *testing.T, command string, want policy.Decision, ruleID string) {
	t.Helper()
	v := ghVerdict(t, command)
	if v.Decision != want || (ruleID != "" && v.RuleID != ruleID) {
		t.Errorf("%q -> %s/%s, want %s/%s", command, v.Decision, v.RuleID, want, ruleID)
	}
}

// Deleting the repository is not a settings change the operator can undo by
// changing it back. The floor already denies this spelling; the Engine now
// agrees rather than being the softer of the two.
func TestGhRepoDeleteDenies(t *testing.T) {
	for _, command := range []string{
		"gh repo delete o/r",
		"gh repo delete o/r --yes",
		"gh repo delete",
	} {
		assertGh(t, command, policy.Deny, "P2.gh-repo-delete")
	}
}

// Secrets, variables, rulesets and repo settings are the protections
// themselves. These are asks, not denies: the operator is allowed to change
// their own settings, they just have to be the one deciding (#228).
func TestGhProtectionPorcelainAsks(t *testing.T) {
	for _, command := range []string{
		"gh secret set MY_SECRET --body x",
		"gh secret delete MY_SECRET",
		"gh secret set MY_SECRET --org myorg",
		"gh variable set FOO --body x",
		"gh variable delete FOO",
		"gh repo edit --visibility public",
		"gh repo edit o/r --enable-issues=false",
		"gh ruleset delete 1",
	} {
		assertGh(t, command, policy.Ask, "P2.gh-protection")
	}
}

// Archiving, renaming and transferring are repository administration under the
// same ambient token, and each changes where the repository lives or whether
// it accepts work at all.
func TestGhRepoAdministrationAsks(t *testing.T) {
	for _, command := range []string{
		"gh repo archive o/r",
		"gh repo unarchive o/r",
		"gh repo rename newname",
		"gh repo transfer o/r newowner",
	} {
		assertGh(t, command, policy.Ask, "P2.gh-repo-admin")
	}
}

// Widening the ambient token's scopes is the act that makes every other gate
// reachable, so it is its own family rather than folded into protections.
func TestGhAuthScopeChangeAsks(t *testing.T) {
	for _, command := range []string{
		"gh auth refresh -s admin:org",
		"gh auth refresh --scopes admin:org,delete_repo",
		"gh auth login --scopes admin:org",
		"gh auth switch",
		"gh auth switch --user other",
	} {
		assertGh(t, command, policy.Ask, "P2.gh-auth-scope")
	}
}

// A release is a published artifact set: creating one publishes, deleting or
// editing one rewrites what consumers already fetched. This reuses the
// existing publish family (#235) rather than inventing a gh-shaped twin, so an
// operator waiving publishing waives it once.
func TestGhReleaseMutationsAskAsPublishing(t *testing.T) {
	for _, command := range []string{
		"gh release create v1.0.0",
		"gh release delete v1.0.0",
		"gh release edit v1.0.0 --draft=false",
		"gh release upload v1.0.0 file.zip",
	} {
		assertGh(t, command, policy.Ask, "P6.publish")
	}
}

// Merging a pull request writes to the protected branch the ruleset exists to
// protect, and dispatching a workflow runs code with the repository's secrets.
func TestGhMergeAndWorkflowDispatchAsk(t *testing.T) {
	for _, command := range []string{
		"gh pr merge 1",
		"gh pr merge 1 --squash",
		"gh pr merge --admin 1",
	} {
		assertGh(t, command, policy.Ask, "P2.gh-pr-merge")
	}
	for _, command := range []string{
		"gh workflow run deploy.yml",
		"gh workflow enable deploy.yml",
		"gh workflow disable deploy.yml",
	} {
		assertGh(t, command, policy.Ask, "P2.gh-workflow-dispatch")
	}
}

// The read twins are the larger half of the set on purpose. `gh` is how the
// fleet checks CI, and prompting on every view is how an operator learns to
// click through the prompts that matter.
func TestGhReadsStayAllowed(t *testing.T) {
	for _, command := range []string{
		"gh repo view o/r",
		"gh repo list",
		"gh secret list",
		"gh variable list",
		"gh variable get FOO",
		"gh release list",
		"gh release view v1.0.0",
		"gh release download v1.0.0",
		"gh pr list",
		"gh pr view 1",
		"gh pr checks 1",
		"gh workflow list",
		"gh workflow view deploy.yml",
		"gh run view 1",
		"gh run list",
		"gh auth status",
		"gh ruleset list",
		"gh ruleset view 1",
		"gh issue list",
		"gh api repos/o/r/rulesets",
	} {
		assertGh(t, command, policy.Allow, "")
	}
}

// Creating a repository is not destroying one, and the families this rule does
// not own must not be swept in by a prefix match on the verb.
func TestGhUnrelatedSubcommandsStayAllowed(t *testing.T) {
	for _, command := range []string{
		"gh repo create newrepo --public",
		"gh repo clone o/r",
		"gh repo sync",
		"gh issue create --title x",
		"gh pr create --title x",
		"gh pr close 1",
		"gh browse",
	} {
		assertGh(t, command, policy.Allow, "")
	}
}

// The env-prefix taxonomy.
//
// Measured before any of this was written: the shell-state machinery already
// strips assignment prefixes before a rule sees the command, so
// `NPM_TOKEN=… npm publish` already asked and `GH_TOKEN=… rm -rf /etc` already
// denied. The prefix was never the gap -- `gh repo delete` was allowed with no
// prefix at all. These cases exist so that stays true: a credential prefix
// must not become a way to spell past a rule that now fires.
func TestCredentialPrefixesDoNotBypassTheRule(t *testing.T) {
	for _, c := range []struct {
		command string
		want    policy.Decision
		ruleID  string
	}{
		{"GH_TOKEN=abc gh repo delete o/r", policy.Deny, "P2.gh-repo-delete"},
		{"GITHUB_TOKEN=abc gh repo delete o/r", policy.Deny, "P2.gh-repo-delete"},
		{"GH_TOKEN=abc gh secret set S --body x", policy.Ask, "P2.gh-protection"},
		{"GH_ENTERPRISE_TOKEN=abc gh pr merge 1", policy.Ask, "P2.gh-pr-merge"},
		// multiple assignments, including a non-credential one
		{"NODE_ENV=production GH_TOKEN=abc gh release delete v1", policy.Ask, "P6.publish"},
		{"AWS_ACCESS_KEY_ID=a AWS_SECRET_ACCESS_KEY=b terraform apply", policy.Ask, "P6.cloud-mutate"},
		// the `env` command form
		{"env GH_TOKEN=abc gh repo delete o/r", policy.Deny, "P2.gh-repo-delete"},
		{"env -i GH_TOKEN=abc gh repo delete o/r", policy.Deny, "P2.gh-repo-delete"},
		{"/usr/bin/env GH_TOKEN=abc gh secret delete S", policy.Ask, "P2.gh-protection"},
		// export chains: the assignment is its own statement, and the command
		// that follows is judged on its own merits either way
		{"export GH_TOKEN=abc; gh repo delete o/r", policy.Deny, "P2.gh-repo-delete"},
		{"export GH_TOKEN=abc && gh secret set S --body x", policy.Ask, "P2.gh-protection"},
		// read twins keep their allow under a credential prefix
		{"GH_TOKEN=abc gh repo view o/r", policy.Allow, ""},
		{"GH_TOKEN=abc gh secret list", policy.Allow, ""},
		{"AWS_SECRET_ACCESS_KEY=b terraform plan", policy.Allow, ""},
		// an ordinary build prefix stays ordinary
		{"NODE_ENV=production npm run build", policy.Allow, ""},
		{"CGO_ENABLED=0 go build ./...", policy.Allow, ""},
	} {
		assertGh(t, c.command, c.want, c.ruleID)
	}
}
