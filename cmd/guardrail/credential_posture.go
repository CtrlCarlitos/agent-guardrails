package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"
	"time"

	"github.com/CtrlCarlitos/agent-guardrails/internal/engine"
	"github.com/CtrlCarlitos/agent-guardrails/internal/safetext"
)

// Credential posture (#236).
//
// guardrail and the agent share a trust domain. Rules catch mistakes and leave
// an audit trail, but the strongest control is the one the agent cannot edit:
// the credential simply lacks the authority. guardrail cannot grant that --
// only the operator can, at the provider -- so what it can do is notice when
// the ambient credential is much wider than the work needs, and say where to
// read about narrowing it.
//
// The rule that shapes this whole file: **doctor must learn this without
// reading or printing credential material.** Scope names are fine, account
// counts are fine, variable names are fine. A token is not, and neither is
// anything derived from one. credentialPostureInput has no field that can hold
// a secret, which is the structural version of that promise rather than a
// discipline someone has to remember.
//
// Everything here warns and nothing fails. An operator running a broad
// credential still needs every other line doctor prints.

const hardeningDoc = "docs/operator-hardening.md"

// overScopedGitHubScopes carry repository administration, or the ability to
// rewrite what CI runs with the repository's secrets.
//
// `repo` is deliberately absent. It is what nearly every working login
// carries, so warning on it would be noise -- and noise is how an operator
// learns to click through the warnings that matter. The hardening page makes
// the fine-grained-PAT case for narrowing it; a doctor warning is for the
// scopes that are surprising to be carrying.
var overScopedGitHubScopes = map[string]bool{
	"delete_repo": true,
	"workflow":    true,
	"write:org":   true,
	"site_admin":  true,
}

// credentialEnvNames are reported when present. Only the name is read; the
// value is never touched.
var credentialEnvNames = []string{
	"GH_TOKEN", "GITHUB_TOKEN", "GH_ENTERPRISE_TOKEN",
	"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN",
	"GOOGLE_APPLICATION_CREDENTIALS", "AZURE_CLIENT_SECRET",
	"NPM_TOKEN", "CLOUDFLARE_API_TOKEN", "DIGITALOCEAN_ACCESS_TOKEN",
}

// credentialPostureInput is what doctor learned, and is deliberately unable to
// carry a credential: names and counts only.
type credentialPostureInput struct {
	ghAvailable bool
	ghAccounts  int
	ghScopes    []string
	envNames    []string
	kubeContext string
}

// credentialPostureLines renders the posture report. It is pure so the
// reporting can be tested without a gh login, a cluster, or a real token
// anywhere near the test.
func credentialPostureLines(in credentialPostureInput) []string {
	var lines []string

	if in.ghAvailable {
		if wide := wideGitHubScopes(in.ghScopes); len(wide) > 0 {
			lines = append(lines, fmt.Sprintf(
				"  WARNING: the gh login carries %s. An agent running under it can change what those scopes control, including the protections meant to bound it. See %s for the fine-grained-token setup.",
				strings.Join(wide, ", "), hardeningDoc))
		}
		if in.ghAccounts > 1 {
			lines = append(lines, fmt.Sprintf(
				"  WARNING: %d gh accounts are logged in. Which one an agent acts as depends on the active account and on the environment, so the reach of a call is not fixed by this report. See %s.",
				in.ghAccounts, hardeningDoc))
		}
	}

	if len(in.envNames) > 0 {
		lines = append(lines, fmt.Sprintf(
			"  credential variables set (names only, values never read): %s. A token in the environment overrides the stored login, so the posture above may not be the one that applies.",
			strings.Join(in.envNames, ", ")))
	}

	if in.kubeContext != "" && !engine.KubeContextNameIsLocal(in.kubeContext) {
		lines = append(lines, fmt.Sprintf(
			"  WARNING: kubectl's current context is %s, which is not a known-local cluster. Commands that do not name a context act against it. See %s.",
			safetext.SingleLine(in.kubeContext), hardeningDoc))
	}

	return lines
}

func wideGitHubScopes(scopes []string) []string {
	var wide []string
	for _, scope := range scopes {
		// Every `admin:*` scope is administration by construction, which is
		// more durable than listing the ones that exist today.
		if overScopedGitHubScopes[scope] || strings.HasPrefix(scope, "admin:") {
			wide = append(wide, scope)
		}
	}
	sort.Strings(wide)
	return wide
}

// parseGhAuthStatus reads scope names and an account count out of
// `gh auth status` output.
//
// It reads only the `Token scopes:` and `Logged in to` lines. The `Token:`
// line sits between them and carries the material itself; it is never parsed,
// and a test pins that no token text can be mistaken for a scope.
func parseGhAuthStatus(output string) (scopes []string, accounts int) {
	seen := map[string]bool{}
	for _, line := range strings.Split(output, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.Contains(trimmed, "Logged in to") {
			accounts++
			continue
		}
		_, rest, ok := strings.Cut(trimmed, "Token scopes:")
		if !ok {
			continue
		}
		for _, raw := range strings.Split(rest, ",") {
			scope := strings.Trim(strings.TrimSpace(raw), "'\"")
			if scope != "" && !seen[scope] {
				seen[scope] = true
				scopes = append(scopes, scope)
			}
		}
	}
	sort.Strings(scopes)
	return scopes, accounts
}

// gatherCredentialPosture collects what can be learned locally.
//
// Both probes are bounded and best-effort: doctor is a diagnostic an operator
// runs when something is already confusing, so it must not hang on a network
// call or fail because a CLI is missing. An unavailable probe reports nothing
// rather than reporting "fine".
func gatherCredentialPosture() credentialPostureInput {
	in := credentialPostureInput{}
	for _, name := range credentialEnvNames {
		if _, ok := os.LookupEnv(name); ok {
			in.envNames = append(in.envNames, name)
		}
	}
	if out, ok := runPostureProbe("gh", "auth", "status"); ok {
		in.ghAvailable = true
		in.ghScopes, in.ghAccounts = parseGhAuthStatus(out)
	}
	if out, ok := runPostureProbe("kubectl", "config", "current-context"); ok {
		in.kubeContext = plausibleKubeContext(out)
	}
	return in
}

// plausibleKubeContext accepts only output that is actually a context name.
//
// `kubectl config current-context` exits non-zero and prints
// "error: current-context is not set" when there is none, and a probe that
// took stderr at face value reported that sentence as the operator's cluster
// and warned that it was not local. A warning naming a cluster that does not
// exist is worse than no warning: it is the kind of thing that teaches an
// operator this section is noise.
func plausibleKubeContext(out string) string {
	name := strings.TrimSpace(out)
	if name == "" || strings.ContainsAny(name, " \t\r\n") {
		return ""
	}
	return name
}

// runPostureProbe runs a local CLI and returns its output only if it
// succeeded.
//
// Bounded and best-effort on purpose: doctor is what an operator runs when
// something is already confusing, so it must not hang on a network call or
// fail because a CLI is missing. A probe that did not succeed reports nothing,
// never "fine" -- an absent signal and a clean signal must not look the same.
func runPostureProbe(name string, args ...string) (string, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	// `gh auth status` prints to stderr on some versions and stdout on
	// others, so both are read; neither is echoed anywhere.
	out, err := cmd.CombinedOutput()
	if err != nil || ctx.Err() != nil {
		return "", false
	}
	return string(out), true
}

// postureGatherer is the seam tests replace so the host's gh and kubectl do
// not decide their outcome.
var postureGatherer = gatherCredentialPosture

// printCredentialPosture returns how many of the lines it printed are
// warnings. The informational line about credential variables is not one.
func printCredentialPosture(stdout interface{ Write([]byte) (int, error) }) int {
	lines := credentialPostureLines(postureGatherer())
	if len(lines) == 0 {
		return 0
	}
	fmt.Fprintln(stdout, "credential posture:")
	warnings := 0
	for _, line := range lines {
		fmt.Fprintln(stdout, line)
		if strings.HasPrefix(line, "  WARNING:") {
			warnings++
		}
	}
	return warnings
}
