package main

import (
	"context"
	"errors"
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
	ghProbe     ghAuthProbe
	envNames    []string
	kubeContext string
}

// ghAuthState is the outcome taxonomy of the `gh auth status` probe (#544):
// an absent signal, a clean signal, and each failure mode mean different
// things to an operator debugging a stalled GitHub workflow, and an
// inconclusive check must never read as "unauthenticated".
type ghAuthState int

const (
	// ghAuthUnavailable is the zero value: gh is not installed or not on
	// PATH. Informational, not a warning.
	ghAuthUnavailable ghAuthState = iota
	ghAuthHealthy
	ghAuthNoAccount
	ghAuthInvalid
	ghAuthInconclusive
)

func (s ghAuthState) isFailure() bool {
	return s == ghAuthNoAccount || s == ghAuthInvalid
}

// errGhAuthStatus marks gh's own non-zero exit from `gh auth status`, which
// carries meaning (gh writes the failure shape to its output), as distinct
// from transport failures — a timeout, a failure to start — which are
// inconclusive.
var errGhAuthStatus = errors.New("gh auth status exited non-zero")

// ghAuthProbe is one bounded `gh auth status` run. Output is combined
// stdout+stderr and is never echoed; only classifications and account
// names derived from it are reported.
type ghAuthProbe struct {
	ran          bool
	ok           bool
	output       string
	exitError    error
	inconclusive bool // started but did not conclude (timeout, signal)
}

// state classifies the probe. It reads only failure-shape markers: gh's
// "You are not logged into any GitHub hosts." sentence, and its per-account
// "✗" / "Token for … is invalid." markers. Anything else that fails is
// inconclusive, never unauthenticated.
func (p ghAuthProbe) state() ghAuthState {
	switch {
	case p.inconclusive:
		return ghAuthInconclusive
	case !p.ran:
		return ghAuthUnavailable
	case p.ok:
		return ghAuthHealthy
	case p.exitError == nil:
		return ghAuthInconclusive
	case strings.Contains(p.output, "not logged into any"):
		return ghAuthNoAccount
	case strings.Contains(p.output, "is invalid"), strings.Contains(p.output, "✗"):
		return ghAuthInvalid
	}
	return ghAuthInconclusive
}

// unusableActiveAccount names the account gh marked invalid, when the
// output says which one. Account names only; token lines are never parsed.
func (p ghAuthProbe) unusableActiveAccount() string {
	for _, line := range strings.Split(p.output, "\n") {
		trimmed := strings.TrimSpace(line)
		if account, ok := strings.CutPrefix(trimmed, "- Token for "); ok {
			if name, _, found := strings.Cut(account, " is invalid"); found {
				return name
			}
		}
	}
	return ""
}

// ghAuthLine renders the probe's outcome. It is the one place the taxonomy
// becomes operator text, shaped by #544: name the condition and the
// recovery check, never a cause that was not established, and a healthy
// CLI says nothing about connector or capability authorization.
func ghAuthLine(p ghAuthProbe) string {
	switch p.state() {
	case ghAuthHealthy:
		return "  gh authentication: healthy (CLI login only; this says nothing about MCP connectors or guardrail capabilities)"
	case ghAuthNoAccount:
		return "  WARNING: gh has no authenticated account. GitHub CLI workflows will fail before any guardrail policy is consulted; run `gh auth login`."
	case ghAuthInvalid:
		if account := p.unusableActiveAccount(); account != "" {
			return "  WARNING: gh authentication is invalid or unverified for the active account " + safetext.SingleLine(account) + ". Check with `gh auth status` in your terminal before blaming a guardrail denial; the cause is not established here."
		}
		return "  WARNING: gh authentication is invalid or unverified. Check with `gh auth status` in your terminal before blaming a guardrail denial; the cause is not established here."
	case ghAuthUnavailable:
		// Deliberately silent, like every unavailable probe in this file:
		// a machine without gh must not read as a finding ("an absent
		// signal and a clean signal must not look the same"). The state
		// exists in the taxonomy so callers can distinguish it.
		return ""
	case ghAuthInconclusive:
		return "  gh authentication could not be verified from here (probe timed out or failed to run); this is not a finding of missing authentication. Verify with `gh auth status` in your terminal."
	}
	return ""
}

// credentialPostureLines renders the posture report. It is pure so the
// reporting can be tested without a gh login, a cluster, or a real token
// anywhere near the test.
func credentialPostureLines(in credentialPostureInput) []string {
	var lines []string

	if line := ghAuthLine(in.ghProbe); line != "" {
		lines = append(lines, line)
	}
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
	in.ghProbe = probeGhAuth()
	if in.ghProbe.state() == ghAuthHealthy {
		in.ghAvailable = true
		in.ghScopes, in.ghAccounts = parseGhAuthStatus(in.ghProbe.output)
	}
	if out, ok := runPostureProbe("kubectl", "config", "current-context"); ok {
		in.kubeContext = plausibleKubeContext(out)
	}
	return in
}

// probeGhAuth runs the one bounded `gh auth status` probe and classifies
// its outcome (#544). gh's own non-zero exit carries the failure shape in
// its output; a timeout or a failure to start carries nothing and must stay
// inconclusive rather than read as unauthenticated.
func probeGhAuth() ghAuthProbe {
	if _, err := exec.LookPath("gh"); err != nil {
		return ghAuthProbe{}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "gh", "auth", "status").CombinedOutput()
	probe := ghAuthProbe{ran: true, ok: err == nil, output: string(out)}
	switch {
	case err == nil:
	case ctx.Err() != nil:
		probe.ran, probe.inconclusive = false, true
	default:
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			probe.exitError = errGhAuthStatus
		} else {
			probe.ran, probe.inconclusive = false, true
		}
	}
	return probe
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
