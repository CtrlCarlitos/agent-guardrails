package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/CtrlCarlitos/agent-guardrails/internal/engine"
	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
	"github.com/CtrlCarlitos/agent-guardrails/internal/testenv"
)

func registerAntigravityForStatusTest(t *testing.T, home string) string {
	t.Helper()
	origSpawner := antigravityHookSpawner
	t.Cleanup(func() { antigravityHookSpawner = origSpawner })
	antigravityHookSpawner = func(string) error { return nil }
	enableForDrift(t, "antigravity")
	useInstalledPlanes(t, "antigravity")
	return filepath.Join(home, ".gemini", "config", "hooks.json")
}

func TestWindowsAndPOSIXStatusExitsOneWhenUnprovenAndZeroWhenProven(t *testing.T) {
	home := verdictSandbox(t)
	state, err := stateBaseDir()
	if err != nil {
		t.Fatal(err)
	}
	hooksPath := registerAntigravityForStatusTest(t, home)

	// Before selftest has passed, guardrail status must exit 1 and name the unproven plane.
	var out, errb bytes.Buffer
	code := run([]string{"status"}, strings.NewReader(""), &out, &errb)
	if code != 1 {
		t.Fatalf("status before selftest exited %d, want 1\nstdout:\n%s\nstderr:\n%s", code, out.String(), errb.String())
	}
	for _, want := range []string{"claude:", "opencode:", "antigravity: unproven", "codex:", "verdict:"} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("status output missing %q:\n%s", want, out.String())
		}
	}

	// Recording a passing selftest writes proof.json under the state root.
	if err := recordSelftestPass(version); err != nil {
		t.Fatalf("recordSelftestPass: %v", err)
	}
	proofFile := filepath.Join(state, "guardrail", "proof.json")
	if _, err := os.Stat(proofFile); err != nil {
		t.Fatalf("proof.json not written at %s: %v", proofFile, err)
	}

	out.Reset()
	errb.Reset()
	code = run([]string{"status"}, strings.NewReader(""), &out, &errb)
	if code != 0 {
		t.Fatalf("status after selftest exited %d, want 0\nstdout:\n%s\nstderr:\n%s", code, out.String(), errb.String())
	}
	if !strings.Contains(out.String(), "antigravity: proven") {
		t.Fatalf("expected antigravity: proven, got:\n%s", out.String())
	}
	if got := lastLine(out.String()); got != "verdict: healthy" {
		t.Fatalf("last line = %q, want verdict: healthy\n%s", got, out.String())
	}

	// Disabling hooks breaks registration; status must exit 1 again.
	if err := os.WriteFile(hooksPath, []byte(`{"guardrail":{"enabled":false}}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	errb.Reset()
	code = run([]string{"status"}, strings.NewReader(""), &out, &errb)
	if code != 1 {
		t.Fatalf("status after disabling antigravity exited %d, want 1\nstdout:\n%s", code, out.String())
	}
	if !strings.Contains(out.String(), "antigravity: unproven") {
		t.Fatalf("expected antigravity: unproven after disable, got:\n%s", out.String())
	}
}

func TestWindowsAndPOSIXStatusJSONAndUsageError(t *testing.T) {
	home := verdictSandbox(t)
	registerAntigravityForStatusTest(t, home)

	if err := recordSelftestPass(version); err != nil {
		t.Fatalf("recordSelftestPass: %v", err)
	}

	var out, errb bytes.Buffer
	code := run([]string{"status", "--json"}, strings.NewReader(""), &out, &errb)
	if code != 0 {
		t.Fatalf("status --json exited %d, want 0\nstdout:\n%s\nstderr:\n%s", code, out.String(), errb.String())
	}
	var report StatusReport
	if err := json.Unmarshal(out.Bytes(), &report); err != nil {
		t.Fatalf("status --json invalid JSON: %v\n%s", err, out.String())
	}
	if !report.Proven || report.Verdict != "verdict: healthy" {
		t.Fatalf("report = %+v, want proven + healthy", report)
	}
	if report.Proof.GuardrailVersion != version || report.Proof.SelftestPassedAt == "" {
		t.Fatalf("proof missing version/selftest_passed_at: %+v", report.Proof)
	}
	agy := report.Proof.Planes["antigravity"]
	if !agy.Proven || !agy.LifecycleRegistered || !agy.FloorCurrent || !strings.HasPrefix(agy.SettingsHash, "sha256:") {
		t.Fatalf("antigravity proof incomplete: %+v", agy)
	}

	out.Reset()
	errb.Reset()
	if code := run([]string{"status", "--unknown-flag"}, strings.NewReader(""), &out, &errb); code != 2 {
		t.Fatalf("unknown flag exited %d, want 2", code)
	}
}

func TestWindowsAndPOSIXProofMigratesLegacySelftestMarker(t *testing.T) {
	setClaudeHome(t, "")
	t.Setenv("PATH", t.TempDir())
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	testenv.SetConfig(t, t.TempDir())
	t.Setenv("GUARDRAIL_CONFIG", "")
	state := t.TempDir()
	testenv.SetState(t, state)

	if err := os.MkdirAll(filepath.Join(state, "guardrail"), 0o700); err != nil {
		t.Fatal(err)
	}
	// Legacy marker from older version -> unproven posture line naming run guardrail status.
	if err := os.WriteFile(filepath.Join(state, "guardrail", "selftest-passed"), []byte("v0.0.1-older\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	line := unifiedProofPosture(version)
	if !strings.Contains(line, "unproven for "+version) || !strings.Contains(line, "v0.0.1-older") || !strings.Contains(line, "run guardrail status") {
		t.Fatalf("unifiedProofPosture with older marker = %q", line)
	}

	// Legacy marker matching current version -> migrated as proven, posture stays silent.
	if err := os.WriteFile(filepath.Join(state, "guardrail", "selftest-passed"), []byte(version+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if line := unifiedProofPosture(version); line != "" {
		t.Fatalf("migrated current legacy marker should silence posture, got %q", line)
	}
}

func TestWindowsAndPOSIXSessionStartUnifiedProofPosture(t *testing.T) {
	const marked = `{"hooks":{"PreToolUse":[{"id":"guardrail-claude-pre","matcher":"*","hooks":[{"type":"command","command":"guardrail hook claude"}]}]}}`
	setClaudeHome(t, marked)
	setClaudeBundle(t, sessionCoverageBundle)
	testenv.SetConfig(t, t.TempDir())
	t.Setenv("GUARDRAIL_CONFIG", "")
	state := t.TempDir()
	testenv.SetState(t, state)

	// Unproven (both uncontracted tool and missing selftest): ONE consolidated posture line.
	ctx := sessionStartContext(t, state)
	unprovenCount := 0
	for _, ln := range strings.Split(ctx, "\n") {
		if strings.HasPrefix(ln, "guardrail: unproven for ") {
			unprovenCount++
		}
	}
	if unprovenCount != 1 {
		t.Fatalf("expected exactly 1 unified unproven line, got %d in:\n%s", unprovenCount, ctx)
	}
	for _, want := range []string{"Claude Code 2.1.280", "FutureTool", "run guardrail status"} {
		if !strings.Contains(ctx, want) {
			t.Fatalf("unified posture missing %q:\n%s", want, ctx)
		}
	}

	// Clean bundle + recorded proof -> completely silent.
	setClaudeBundle(t, "// Version: 2.1.281\nvar tools=[\"Bash\",\"Read\",\"Write\",\"Edit\",\"Glob\"];\n")
	if err := recordSelftestPass(version); err != nil {
		t.Fatalf("recordSelftestPass: %v", err)
	}
	if ctx := sessionStartContext(t, state); strings.Contains(ctx, "guardrail: unproven") {
		t.Fatalf("proven state must stay silent, got:\n%s", ctx)
	}

	// Modifying Claude settings.json invalidates the stored settings hash -> unproven again.
	home, _ := os.UserHomeDir()
	settingsPath := filepath.Join(home, ".claude", "settings.json")
	if err := os.WriteFile(settingsPath, []byte(`{"hooks":{"PreToolUse":[]},"edited":true}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if ctx := sessionStartContext(t, state); !strings.Contains(ctx, "guardrail: unproven for "+version) || !strings.Contains(ctx, "run guardrail status") {
		t.Fatalf("settings hash drift must surface unified unproven line, got:\n%s", ctx)
	}
}

func TestWindowsAndPOSIXStatusAllowedInMediatedSessions(t *testing.T) {
	base, err := policy.LoadBase()
	if err != nil {
		t.Fatal(err)
	}
	v := engine.Evaluate(engine.ToolCall{
		Plane:      "antigravity",
		Tool:       "Bash",
		NativeTool: "run_command",
		Capability: "command",
		Command:    "guardrail status",
		CWD:        t.TempDir(),
	}, base)
	if v.Decision != policy.Allow {
		t.Fatalf("guardrail status in mediated session -> %+v, want allow", v)
	}
}
