package engine

import (
	"testing"

	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
)

// #430 (measured on #277): `gh auth login --with-token` was allowed: a session could log in
// as another account unchallenged, while `gh auth switch`, the same act,
// already asked. A person signing in answers prompts; --with-token needs no
// person.
func TestGhAuthLoginWithTokenAsks(t *testing.T) {
	for _, command := range []string{
		"gh auth login --with-token < token.txt",
		"gh auth login --hostname github.com --with-token",
		"cat t | gh auth login --with-token",
		"gh.exe auth login --with-token < t",
	} {
		v := evalGh(t, command)
		if v.Decision != policy.Ask || v.RuleID != "P2.gh-auth-scope" {
			t.Errorf("%q -> %s %s, want ask P2.gh-auth-scope", command, v.Decision, v.RuleID)
		}
	}
	// Interactive sign-in and status stay allowed, as pinned in
	// TestGhAuthLoginAndRefreshStayAllowedWithoutScopeFlags.
	for _, command := range []string{
		"gh auth login",
		"gh auth login --web",
		"gh auth status",
	} {
		if v := evalGh(t, command); v.Decision != policy.Allow {
			t.Errorf("%q -> %s %s, want allow", command, v.Decision, v.RuleID)
		}
	}
}
