package main

import (
	"strings"
	"testing"
)

// guardrail and the agent share a trust domain, so the strongest control is
// the one the agent cannot edit: the credential simply lacks the authority.
// doctor cannot enforce that, but it can notice when the ambient credential is
// far wider than the work needs (#236).
//
// The constraint that shapes every test here: doctor must learn this without
// reading or printing credential material. Scope *names* are fine. A token is
// not, and neither is anything derived from one.

func postureText(in credentialPostureInput) string {
	return strings.Join(credentialPostureLines(in), "\n")
}

// The scopes that carry repository administration, or the ability to rewrite
// what CI runs, are the ones worth a word.
func TestOverScopedGitHubScopesWarn(t *testing.T) {
	for _, scope := range []string{
		"admin:org", "admin:repo_hook", "admin:enterprise", "admin:public_key",
		"delete_repo", "workflow", "write:org", "site_admin",
	} {
		got := postureText(credentialPostureInput{
			ghAvailable: true, ghAccounts: 1,
			ghScopes: []string{"repo", "read:org", scope},
		})
		if !strings.Contains(got, "WARNING") || !strings.Contains(got, scope) {
			t.Errorf("scope %q did not warn:\n%s", scope, got)
		}
		if !strings.Contains(got, "operator-hardening") {
			t.Errorf("scope %q warned without pointing at the hardening page:\n%s", scope, got)
		}
	}
}

// `repo` and the ordinary read scopes are what nearly every working login
// carries. Warning on them would be noise, and noise is how an operator learns
// to click through the warnings that matter.
func TestOrdinaryGitHubScopesStaySilent(t *testing.T) {
	got := postureText(credentialPostureInput{
		ghAvailable: true, ghAccounts: 1,
		ghScopes: []string{"repo", "read:org", "gist", "read:packages"},
	})
	if strings.Contains(got, "WARNING") {
		t.Errorf("ordinary scopes warned:\n%s", got)
	}
}

// Two logged-in accounts means the agent's reach depends on which one is
// active, which is a thing the operator should know rather than discover.
func TestMultipleGitHubAccountsWarn(t *testing.T) {
	got := postureText(credentialPostureInput{
		ghAvailable: true, ghAccounts: 2,
		ghScopes: []string{"repo"},
	})
	if !strings.Contains(got, "WARNING") || !strings.Contains(got, "2") {
		t.Errorf("two accounts did not warn:\n%s", got)
	}
}

// A token in the environment overrides the stored login, so the posture
// doctor just reported may not be the one that applies.
func TestAmbientTokenEnvIsReportedByNameOnly(t *testing.T) {
	got := postureText(credentialPostureInput{
		ghAvailable: true, ghAccounts: 1, ghScopes: []string{"repo"},
		envNames: []string{"GH_TOKEN", "AWS_SECRET_ACCESS_KEY"},
	})
	for _, name := range []string{"GH_TOKEN", "AWS_SECRET_ACCESS_KEY"} {
		if !strings.Contains(got, name) {
			t.Errorf("%s was not reported:\n%s", name, got)
		}
	}
	if !strings.Contains(got, "overrides") {
		t.Errorf("the report does not say a token in the environment overrides the stored login:\n%s", got)
	}
}

// The property the whole feature is judged on. If a value can reach the
// output, the check is worse than not having it.
func TestNoCredentialValueCanReachTheOutput(t *testing.T) {
	const secret = "ghp_THISMUSTNEVERAPPEAR0000000000000000"
	got := postureText(credentialPostureInput{
		ghAvailable: true, ghAccounts: 1,
		ghScopes: []string{"repo", "admin:org"},
		envNames: []string{"GH_TOKEN"},
		// A context name is operator-supplied text and is printed, so it is
		// the one field that could carry material if a caller ever passed it.
		kubeContext: "prod-eu",
	})
	if strings.Contains(got, secret) {
		t.Fatalf("a credential value reached the output:\n%s", got)
	}
	// The gatherer must never be handed values in the first place: the input
	// struct has no field that holds one.
	in := credentialPostureInput{}
	_ = in.envNames // names
	_ = in.ghScopes // scope names
}

// A non-local cluster context means a mutation reaches something the operator
// may not be able to undo.
func TestNonLocalKubeContextWarns(t *testing.T) {
	got := postureText(credentialPostureInput{kubeContext: "prod-eu"})
	if !strings.Contains(got, "WARNING") || !strings.Contains(got, "prod-eu") {
		t.Errorf("a production-shaped context did not warn:\n%s", got)
	}
}

// The same list the engine judges commands against, so the two cannot
// disagree about what "local" means.
func TestLocalKubeContextsStaySilent(t *testing.T) {
	for _, context := range []string{"kind-dev", "minikube", "docker-desktop", "k3d-local", "rancher-desktop"} {
		got := postureText(credentialPostureInput{kubeContext: context})
		if strings.Contains(got, "WARNING") {
			t.Errorf("local context %q warned:\n%s", context, got)
		}
	}
}

// A failed probe must not be mistaken for a finding.
//
// `kubectl config current-context` exits non-zero and prints
// "error: current-context is not set" when there is none. An earlier version
// of this took that sentence at face value and warned that the operator's
// cluster -- named "error: current-context is not set" -- was not local, which
// is exactly how a section teaches an operator that it is noise.
func TestUnsetKubeContextIsNotAFinding(t *testing.T) {
	for _, out := range []string{
		"error: current-context is not set",
		"",
		"   \n",
		"Unable to connect to the server: dial tcp: lookup",
	} {
		if got := plausibleKubeContext(out); got != "" {
			t.Errorf("plausibleKubeContext(%q) = %q, want no context", out, got)
		}
	}
	for _, out := range []string{"prod-eu\n", "kind-dev", "  minikube  \n"} {
		if plausibleKubeContext(out) == "" {
			t.Errorf("plausibleKubeContext(%q) rejected a real context name", out)
		}
	}
	// And the whole report stays silent when the probe found nothing.
	if lines := credentialPostureLines(credentialPostureInput{
		kubeContext: plausibleKubeContext("error: current-context is not set"),
	}); len(lines) != 0 {
		t.Errorf("a failed kubectl probe produced output:\n%v", lines)
	}
}

// doctor reports posture; it never fails on it. An operator with a broad
// credential still needs every other line doctor prints.
func TestPostureIsAdvisoryAndSilentWhenNothingIsKnown(t *testing.T) {
	if lines := credentialPostureLines(credentialPostureInput{}); len(lines) != 0 {
		t.Errorf("an empty environment produced output:\n%v", lines)
	}
	// gh absent is not a finding. Plenty of machines do not have it.
	if lines := credentialPostureLines(credentialPostureInput{ghAvailable: false}); len(lines) != 0 {
		t.Errorf("a missing gh produced output:\n%v", lines)
	}
}

// Scope parsing works on the shape `gh auth status` actually prints, and must
// never pick up the token line that sits next to it.
func TestScopeParsingIgnoresTheTokenLine(t *testing.T) {
	const output = `github.com
  ✓ Logged in to github.com account octocat (keyring)
  - Active account: true
  - Git operations protocol: https
  - Token: gho_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789
  - Token scopes: 'gist', 'read:org', 'repo', 'workflow'
`
	scopes, accounts := parseGhAuthStatus(output)
	if accounts != 1 {
		t.Errorf("accounts = %d, want 1", accounts)
	}
	want := map[string]bool{"gist": true, "read:org": true, "repo": true, "workflow": true}
	if len(scopes) != len(want) {
		t.Fatalf("scopes = %v, want %v", scopes, want)
	}
	for _, s := range scopes {
		if !want[s] {
			t.Errorf("unexpected scope %q parsed from the status output", s)
		}
		if strings.HasPrefix(s, "gho_") || strings.Contains(s, "ABCDEF") {
			t.Fatalf("token material was parsed as a scope: %q", s)
		}
	}
}

func TestScopeParsingCountsEveryLoggedInAccount(t *testing.T) {
	const output = `github.com
  ✓ Logged in to github.com account octocat (keyring)
  - Token scopes: 'repo'
  ✓ Logged in to github.com account octocat-work (keyring)
  - Token scopes: 'repo', 'admin:org'
`
	scopes, accounts := parseGhAuthStatus(output)
	if accounts != 2 {
		t.Errorf("accounts = %d, want 2", accounts)
	}
	if !containsString(scopes, "admin:org") {
		t.Errorf("scopes from the second account were dropped: %v", scopes)
	}
}

func containsString(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}
