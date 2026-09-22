package engine

import (
	"testing"

	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
)

// M2 and M3 from the #282 four-seat gap analysis.
//
// Both were found the same way: three of the four declarative floors gate
// these commands, and the Engine allowed them. With the floors retiring
// (ADR-0028) the Engine has to carry the policy itself.

// M2: adding a key to the GitHub account grants durable access that outlives
// the session and the token that created it.
//
// The Engine appeared to cover part of this already, but only by accident:
// `gh ssh-key add ~/.ssh/id_ed25519.pub` denied because `P4.secret-path` saw a
// secret-tier *argument*, not because anything understood the command. Point
// it at a key sitting anywhere else and it allowed. A rule that depends on the
// spelling of an argument is not a rule about the action.
func TestGhAccountKeyMutationsAsk(t *testing.T) {
	for _, command := range []string{
		"gh ssh-key add /tmp/key.pub",
		"gh ssh-key add key.pub",
		"gh ssh-key add ./build/deploy.pub --title ci",
		"gh gpg-key add key.asc",
		"gh gpg-key add ./signing.asc",
		// Both verbs of the pair, for the reason the floor lists both: an ask
		// on `add` alone is evadable by reaching for `delete`, and removing
		// the operator's own key is its own kind of damage.
		"gh ssh-key delete 123",
		"gh gpg-key delete 123",
	} {
		assertGh(t, command, policy.Ask, "P2.gh-account-key")
	}
}

// A secret-tier argument still denies. Deny outranks ask, so the stricter
// verdict wins and the new rule does not weaken the path that already worked.
func TestSecretKeyPathStillDeniesRatherThanAsking(t *testing.T) {
	for _, command := range []string{
		"gh ssh-key add ~/.ssh/id_ed25519.pub",
		"gh ssh-key add /home/u/.ssh/id_rsa.pub",
	} {
		if v := ghVerdict(t, command); v.Decision != policy.Deny {
			t.Errorf("%q -> %s/%s, want deny: a secret-tier path must not be softened to an ask", command, v.Decision, v.RuleID)
		}
	}
}

// M3: logging out destroys the credential the session is running on.
//
// `login` and `refresh` without a scope flag stay allowed -- that is the
// deliberate divergence from #228, because re-authorizing the scopes a token
// already holds is not widening them, and asking for it trains the operator to
// click through the ones that do. Logout is not a scope question at all.
func TestGhAuthLogoutAsks(t *testing.T) {
	for _, command := range []string{
		"gh auth logout",
		"gh auth logout --hostname github.com",
		"gh auth logout -h github.com -u octocat",
	} {
		assertGh(t, command, policy.Ask, "P2.gh-auth-logout")
	}
}

// The #228 divergence is deliberate and stays. This test is what fails if
// someone later "tidies up" the auth family by making all of it ask.
func TestGhAuthLoginAndRefreshStayAllowedWithoutScopeFlags(t *testing.T) {
	for _, command := range []string{
		"gh auth login",
		"gh auth login --hostname github.com",
		"gh auth refresh",
		"gh auth refresh --hostname github.com",
	} {
		assertGh(t, command, policy.Allow, "")
	}
	// Widening still asks, under the rule that already owned it.
	for _, command := range []string{
		"gh auth refresh -s admin:org",
		"gh auth login --scopes admin:org,delete_repo",
	} {
		assertGh(t, command, policy.Ask, "P2.gh-auth-scope")
	}
}

// The read twins. `gh` is how the fleet checks state, and prompting on a list
// is how an operator learns to click through the prompts that matter.
func TestGhAccountKeyAndAuthReadsStayAllowed(t *testing.T) {
	for _, command := range []string{
		"gh ssh-key list",
		"gh gpg-key list",
		"gh auth status",
		"gh auth token",
	} {
		assertGh(t, command, policy.Allow, "")
	}
}

// A credential prefix must not become a way to spell past either new rule,
// the same property pinned for the rest of the porcelain in #228.
func TestCredentialPrefixesDoNotBypassTheAccountRules(t *testing.T) {
	for _, c := range []struct {
		command string
		ruleID  string
	}{
		{"GH_TOKEN=abc gh ssh-key add /tmp/key.pub", "P2.gh-account-key"},
		{"GH_TOKEN=abc gh gpg-key add key.asc", "P2.gh-account-key"},
		{"GH_TOKEN=abc gh auth logout", "P2.gh-auth-logout"},
		{"env GH_TOKEN=abc gh ssh-key delete 1", "P2.gh-account-key"},
		{"export GH_TOKEN=abc; gh auth logout", "P2.gh-auth-logout"},
	} {
		assertGh(t, c.command, policy.Ask, c.ruleID)
	}
}
