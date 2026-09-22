package genconfig

import "testing"

// The Engine parses `gh api` and sees the HTTP method (#252). The porcelain
// subcommands reach the same endpoints without any method flag to parse:
// `gh secret set` is a PUT to `actions/secrets`, `gh repo edit --visibility`
// is a PATCH on the repo. Those are shape-level, which is what a floor glob
// can actually match, so they belong here rather than in the parser.
//
// The selection follows #228's own reasoning: what asks is either a change to
// *which authority is in play* or an act that is irreversible or outward
// facing. Reads and lists stay allow, because `gh` is how the fleet checks CI
// and prompting on inspection is how an operator learns to stop reading.

func porcelainDecision(t *testing.T, command string) string {
	t.Helper()
	frag := ClaudeConfig(secretPol(), "guardrail")
	perms := frag["permissions"].(map[string]any)
	return claudeNativeDecision(perms, "Bash("+command+")")
}

// Secrets and variables: writing one hands a value to CI, deleting one breaks
// it. Both directions ask, or the ask is evadable by choosing the other verb.
func TestGhSecretAndVariableMutationsAsk(t *testing.T) {
	for _, command := range []string{
		"gh secret set MY_TOKEN",
		"gh secret set MY_TOKEN --body xyz",
		"gh secret delete MY_TOKEN",
		"gh variable set MY_VAR --body xyz",
		"gh variable delete MY_VAR",
		// org and repo scoping still reaches the same act
		"gh secret set MY_TOKEN --org CtrlCarlitos",
		"gh secret set MY_TOKEN --repo owner/repo",
	} {
		if got := porcelainDecision(t, command); got != "ask" {
			t.Errorf("%q -> %q, want ask", command, got)
		}
	}
}

// Repository-level acts under the operator's admin authority. `gh repo delete`
// already denies; these are the same authority with a softer blast radius, so
// they ask rather than deny.
func TestGhRepoMutationsAsk(t *testing.T) {
	for _, command := range []string{
		"gh repo edit --visibility public",
		"gh repo edit owner/repo --default-branch trunk",
		"gh repo archive owner/repo",
		"gh repo rename new-name",
		"gh repo transfer owner/repo neworg",
	} {
		if got := porcelainDecision(t, command); got != "ask" {
			t.Errorf("%q -> %q, want ask", command, got)
		}
	}
}

// Changing which authority is in play. These do not mutate a repository at
// all: they change who the agent *is*, which is the shape #228 calls out as
// its own family. A second logged-in account is one command away.
func TestGhAuthChangesAsk(t *testing.T) {
	for _, command := range []string{
		"gh auth switch",
		"gh auth switch --user other-account",
		"gh auth login",
		"gh auth login --scopes admin:org",
		"gh auth refresh -s admin:org",
		"gh auth logout",
		// account-level persistence that outlives a token rotation
		"gh ssh-key add ~/.ssh/id_ed25519.pub",
		"gh gpg-key add key.asc",
	} {
		if got := porcelainDecision(t, command); got != "ask" {
			t.Errorf("%q -> %q, want ask", command, got)
		}
	}
}

// Published artifacts. `gh release create` and `delete` already ask from
// #232; editing or clobbering an uploaded asset mutates a published set.
func TestGhReleaseEditAsks(t *testing.T) {
	for _, command := range []string{
		"gh release edit v1.0.0 --draft=false",
		"gh release upload v1.0.0 asset.zip --clobber",
	} {
		if got := porcelainDecision(t, command); got != "ask" {
			t.Errorf("%q -> %q, want ask", command, got)
		}
	}
}

// The line that keeps the floor usable. Every one of these is how somebody
// reads CI state, and each was chosen because it shares a prefix with
// something above -- `gh secret list` against `gh secret set`, `gh auth
// status` against `gh auth switch` -- so a glob that is one character too
// greedy shows up here.
func TestGhPorcelainReadsStayAllow(t *testing.T) {
	for _, command := range []string{
		"gh secret list",
		"gh variable list",
		"gh repo view owner/repo",
		"gh repo list CtrlCarlitos",
		"gh repo clone owner/repo",
		"gh auth status",
		"gh auth token",
		"gh ssh-key list",
		"gh gpg-key list",
		"gh release view v1.0.0",
		"gh release list",
		"gh release download v1.0.0",
		"gh workflow list",
		"gh run list",
		"gh pr view 123",
		"gh pr list",
		"gh issue list",
	} {
		if got := porcelainDecision(t, command); got != "" && got != "allow" {
			t.Errorf("%q -> %q, want allow: reading is not mutating", command, got)
		}
	}
}

// The shape lesson from #232 and the guard from #249: a bare trailing star
// cannot match an argument containing a separator, and several of these take
// `owner/repo`. Pinned here as well as in the guard, because this family is
// where the mistake would be easiest to repeat.
func TestGhPorcelainGlobsCrossSeparators(t *testing.T) {
	for _, command := range []string{
		"gh repo edit owner/repo --visibility public",
		"gh repo archive owner/repo",
		"gh repo transfer owner/repo neworg",
		"gh secret set MY_TOKEN --repo owner/repo",
		"gh ssh-key add /home/u/.ssh/id_ed25519.pub",
	} {
		if got := porcelainDecision(t, command); got != "ask" {
			t.Errorf("%q -> %q, want ask: a slash-bearing argument must not evade the glob", command, got)
		}
	}
}

// Both planes, one source.
func TestGhPorcelainGlobsReachOpencode(t *testing.T) {
	frag := OpencodeConfig(secretPol(), "/opt/guardrail/guardrail.js")
	bash := frag["permission"].(map[string]any)["bash"].(orderedPermissionRules)
	for _, glob := range []string{
		"gh secret set{,**}",
		"gh repo edit{,**}",
		"gh auth switch{,**}",
	} {
		if got, ok := bash[glob]; !ok || got != "ask" {
			t.Errorf("OpenCode floor %q = %q (present=%v), want ask", glob, got, ok)
		}
	}
}
