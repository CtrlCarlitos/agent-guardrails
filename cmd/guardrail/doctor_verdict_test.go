package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The credential probes run the host's gh and kubectl, so a verdict test that
// let them through would go red on a machine with a wide token.
func useNoCredentialPosture(t *testing.T) {
	t.Helper()
	orig := postureGatherer
	t.Cleanup(func() { postureGatherer = orig })
	postureGatherer = func() credentialPostureInput { return credentialPostureInput{} }
}

func verdictSandbox(t *testing.T) string {
	t.Helper()
	driftSandbox(t)
	t.Setenv("GUARDRAIL_CONFIG", "")
	t.Setenv(updateRunEnv, "")
	stubOperatorEnrolled(t, true)
	useNoCredentialPosture(t)
	useInstalledPlanes(t)
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	return home
}

func lastLine(s string) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	return lines[len(lines)-1]
}

func countPrefix(s, prefix string) int {
	n := 0
	for _, line := range strings.Split(s, "\n") {
		if strings.HasPrefix(line, prefix) {
			n++
		}
	}
	return n
}

func TestDoctorVerdictLineWording(t *testing.T) {
	for n, want := range map[int]string{
		0: "verdict: healthy",
		1: "verdict: 1 problem (see above)",
		2: "verdict: 2 problems (see above)",
		9: "verdict: 9 problems (see above)",
	} {
		if got := doctorVerdictLine(n); got != want {
			t.Errorf("doctorVerdictLine(%d) = %q, want %q", n, got, want)
		}
	}
}

func TestPlaneStateIsProblem(t *testing.T) {
	for state, want := range map[string]bool{
		"no settings.json":          false,
		"no hooks.json":             false,
		"guardrail hook registered": false,
		"guardrail hook registered but NEVER OBSERVED FIRING — x":                                            false,
		"guardrail hooks registered, unenforced: Windows command_execution PreToolUse dispatch not observed": false,
		"present, hook NOT registered":                      true,
		"present, integration NOT registered":               true,
		"present, disabled":                                 true,
		"unparseable (bad json)":                            true,
		"unreadable: access denied":                         true,
		"guardrail hook registered but CANNOT SPAWN — path": true,
	} {
		if got := planeStateIsProblem(state); got != want {
			t.Errorf("planeStateIsProblem(%q) = %v, want %v", state, got, want)
		}
	}
}

func TestDoctorEndsWithHealthyOnACleanMachine(t *testing.T) {
	verdictSandbox(t)
	enableForDrift(t, "claude")
	useInstalledPlanes(t, "claude")

	var out, errb bytes.Buffer
	if code := cmdDoctor(nil, &out, &errb); code != 0 {
		t.Fatalf("exit = %d, stderr=%q", code, errb.String())
	}
	if got := lastLine(out.String()); got != "verdict: healthy" {
		t.Fatalf("last line = %q, want the healthy verdict:\n%s", got, out.String())
	}
	if n := countPrefix(out.String(), "verdict:"); n != 1 {
		t.Fatalf("%d verdict lines, want exactly 1:\n%s", n, out.String())
	}
}

// The issue's example: an unregistered settings file and an overlay warning
// are two problems, and the plain doctor still exits 0.
func TestDoctorCountsAnUnregisteredPlaneAndAnOverlayWarning(t *testing.T) {
	home := verdictSandbox(t)
	if err := os.MkdirAll(filepath.Join(home, ".claude"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".claude", "settings.json"), []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GUARDRAIL_CONFIG", filepath.Join(home, "missing.toml"))

	var out, errb bytes.Buffer
	if code := cmdDoctor(nil, &out, &errb); code != 0 {
		t.Fatalf("plain doctor must stay exit 0, got %d; stderr=%q", code, errb.String())
	}
	if got := lastLine(out.String()); got != "verdict: 2 problems (see above)" {
		t.Fatalf("last line = %q, want 2 problems:\n%s", got, out.String())
	}
}

func TestDoctorCountsEveryPolicyWarning(t *testing.T) {
	home := verdictSandbox(t)
	overlay := filepath.Join(home, "overlay.toml")
	body := "[slots]\nsecret_allow = [\".env\"]\negress_allowlist = [\"*\"]\n"
	if err := os.WriteFile(overlay, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GUARDRAIL_CONFIG", overlay)

	var out, errb bytes.Buffer
	cmdDoctor(nil, &out, &errb)
	bullets := countPrefix(out.String(), "  - guardrail:")
	if bullets < 2 {
		t.Fatalf("fixture produced %d policy warnings, want at least 2:\n%s", bullets, out.String())
	}
	if want := doctorVerdictLine(bullets); lastLine(out.String()) != want {
		t.Fatalf("last line = %q, want %q:\n%s", lastLine(out.String()), want, out.String())
	}
}

func TestDoctorCountsAWideCredentialWarning(t *testing.T) {
	verdictSandbox(t)
	orig := postureGatherer
	t.Cleanup(func() { postureGatherer = orig })
	postureGatherer = func() credentialPostureInput {
		return credentialPostureInput{ghAvailable: true, ghScopes: []string{"workflow"}}
	}
	var out, errb bytes.Buffer
	cmdDoctor(nil, &out, &errb)
	if got := lastLine(out.String()); got != "verdict: 1 problem (see above)" {
		t.Fatalf("last line = %q:\n%s", got, out.String())
	}
}

// --coverage keeps its exit-1 semantics and its finding is a problem, so the
// verdict comes after the coverage block, not before it.
func TestDoctorCoverageFindingIsCountedAndVerdictComesLast(t *testing.T) {
	home := verdictSandbox(t)
	bundle := filepath.Join(home, "claude-bundle")
	if err := os.WriteFile(bundle, []byte(doctorCoverageBundle), 0o755); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	code := cmdDoctor([]string{"--coverage", "claude", "--bundle", bundle}, &out, &errb)
	if code != 1 {
		t.Fatalf("exit = %d, want 1; stderr=%q", code, errb.String())
	}
	if got := lastLine(out.String()); got != "verdict: 1 problem (see above)" {
		t.Fatalf("last line = %q:\n%s", got, out.String())
	}
}

func TestDoctorCoverageWithFullCoverageIsHealthy(t *testing.T) {
	home := verdictSandbox(t)
	bundle := filepath.Join(home, "claude-bundle")
	if err := os.WriteFile(bundle, []byte(`var tools=["Bash","Read","Write","Edit","Glob"];`), 0o755); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	if code := cmdDoctor([]string{"--coverage", "claude", "--bundle", bundle}, &out, &errb); code != 0 {
		t.Fatalf("exit = %d; stderr=%q", code, errb.String())
	}
	if got := lastLine(out.String()); got != "verdict: healthy" {
		t.Fatalf("last line = %q:\n%s", got, out.String())
	}
}

// A bad argument is a usage error, not a diagnosis.
func TestDoctorUsageErrorPrintsNoVerdict(t *testing.T) {
	verdictSandbox(t)
	var out, errb bytes.Buffer
	if code := cmdDoctor([]string{"--bogus"}, &out, &errb); code != 2 {
		t.Fatalf("exit = %d, want 2", code)
	}
	if strings.Contains(out.String(), "verdict:") {
		t.Fatalf("usage error printed a verdict:\n%s", out.String())
	}
}
