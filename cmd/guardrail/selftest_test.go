package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/CtrlCarlitos/agent-guardrails/internal/testenv"
)

func runSelftest(t *testing.T, stdout, stderr *strings.Builder) int {
	t.Helper()
	return cmdSelftest([]string{}, stdout, stderr)
}

func TestSelftestPassesOnHealthyEnvironment(t *testing.T) {
	testenv.SetHome(t, t.TempDir())
	testenv.SetConfig(t, t.TempDir())
	testenv.SetState(t, t.TempDir())
	var out, errb strings.Builder
	if code := runSelftest(t, &out, &errb); code != 0 {
		t.Fatalf("exit = %d stderr %q stdout %q", code, errb.String(), out.String())
	}
	got := out.String()
	for _, want := range []string{
		"claude: probes pass",
		"opencode: probes pass",
		"antigravity: probes pass",
		"codex: probes pass",
		"selftest: all probes passed",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("output missing %q:\n%s", want, got)
		}
	}
}

func TestSelftestFailsWhenAProbeVerdictDrifts(t *testing.T) {
	testenv.SetHome(t, t.TempDir())
	testenv.SetConfig(t, t.TempDir())
	testenv.SetState(t, t.TempDir())
	orig := selftestProbes
	tampered := append([]selftestProbe(nil), orig...)
	tampered[0].WantDecision = "never"
	selftestProbes = tampered
	t.Cleanup(func() { selftestProbes = orig })

	var out, errb strings.Builder
	if code := runSelftest(t, &out, &errb); code != 1 {
		t.Fatalf("exit = %d, want 1; stdout %q", code, out.String())
	}
	if !strings.Contains(out.String(), "failed") {
		t.Fatalf("output missing failure report:\n%s", out.String())
	}
}

func TestSelftestIsIdempotentAcrossRuns(t *testing.T) {
	testenv.SetHome(t, t.TempDir())
	testenv.SetConfig(t, t.TempDir())
	testenv.SetState(t, t.TempDir())
	for run := 0; run < 2; run++ {
		var out, errb strings.Builder
		if code := runSelftest(t, &out, &errb); code != 0 {
			t.Fatalf("run %d exit = %d; stdout %q stderr %q", run, code, out.String(), errb.String())
		}
	}
}
func TestSelftestAntigravityProbesPass(t *testing.T) {
	testenv.SetHome(t, t.TempDir())
	testenv.SetConfig(t, t.TempDir())
	testenv.SetState(t, t.TempDir())
	var out, errb strings.Builder
	if code := runSelftest(t, &out, &errb); code != 0 {
		t.Fatalf("exit = %d stderr %q stdout %q", code, errb.String(), out.String())
	}
	if !strings.Contains(out.String(), "antigravity: probes pass (7)") {
		t.Fatalf("expected antigravity: probes pass (7), got:\n%s", out.String())
	}
}

func TestSelftestRecordsThePassedVersionInTheStateDir(t *testing.T) {
	testenv.SetHome(t, t.TempDir())
	testenv.SetConfig(t, t.TempDir())
	state := t.TempDir()
	testenv.SetState(t, state)
	var out, errb strings.Builder
	if code := runSelftest(t, &out, &errb); code != 0 {
		t.Fatalf("exit = %d stderr %q", code, errb.String())
	}
	raw, err := os.ReadFile(filepath.Join(state, "guardrail", "selftest-passed"))
	if err != nil {
		t.Fatalf("marker not written: %v", err)
	}
	if got := strings.TrimSpace(string(raw)); got != version {
		t.Fatalf("marker = %q, want %q", got, version)
	}
	if got := selftestPassedVersion(); got != version {
		t.Fatalf("selftestPassedVersion() = %q, want %q", got, version)
	}
}

func TestSelftestDoesNotRecordAFailedRun(t *testing.T) {
	testenv.SetHome(t, t.TempDir())
	testenv.SetConfig(t, t.TempDir())
	state := t.TempDir()
	testenv.SetState(t, state)
	orig := selftestProbes
	tampered := append([]selftestProbe(nil), orig...)
	tampered[0].WantDecision = "never"
	selftestProbes = tampered
	t.Cleanup(func() { selftestProbes = orig })
	var out, errb strings.Builder
	runSelftest(t, &out, &errb)
	if _, err := os.Stat(filepath.Join(state, "guardrail", "selftest-passed")); err == nil {
		t.Fatal("a failed selftest must not record a pass")
	}
}

// The three Claude probes added for #37 / ADR-0013 / ADR-0018 pin verdicts
// by rule, which the Claude hook only exposes through its audit record.
func TestSelftestClaudeProbesPinRuleIDs(t *testing.T) {
	want := map[string][2]string{
		"serena secret mutation denies (registry projection)": {"deny", "P4.secret-path"},
		"subagent delegation allows (inherited)":              {"allow", "delegation-inherited"},
		"CronCreate asks (external, night-preserved)":         {"ask", "capability-external"},
	}
	for _, probe := range selftestProbes {
		if probe.Plane != "claude" {
			continue
		}
		if w, ok := want[probe.Name]; ok {
			if probe.WantDecision != w[0] || probe.WantRuleID != w[1] {
				t.Fatalf("%s pins %s/%s, want %s/%s", probe.Name, probe.WantDecision, probe.WantRuleID, w[0], w[1])
			}
			delete(want, probe.Name)
		}
	}
	if len(want) != 0 {
		t.Fatalf("missing claude probes: %v", want)
	}
	testenv.SetHome(t, t.TempDir())
	testenv.SetConfig(t, t.TempDir())
	testenv.SetState(t, t.TempDir())
	// Counted from the matrix, not hardcoded: a Windows host adds the
	// drive-lettered probes to the same plane, and the count is evidence that
	// every claude probe passed rather than a number to keep in step by hand.
	claudeProbes := 0
	for _, probe := range selftestProbes {
		if probe.Plane == "claude" {
			claudeProbes++
		}
	}
	pass := fmt.Sprintf("claude: probes pass (%d)", claudeProbes)
	var out, errb strings.Builder
	if code := runSelftest(t, &out, &errb); code != 0 || !strings.Contains(out.String(), pass) {
		t.Fatalf("exit = %d, want %q\n%s", code, pass, out.String())
	}
	// Idempotent: the same probes pass again in the same state directory.
	out.Reset()
	if code := runSelftest(t, &out, &errb); code != 0 || !strings.Contains(out.String(), pass) {
		t.Fatalf("second run exit = %d, want %q\n%s", code, pass, out.String())
	}
}

// Ask probes are chosen from rules night mode never relaxes (ADR-0018), so
// selftest is deterministic at any hour: an active marker changes nothing.
func TestSelftestIsDeterministicUnderActiveNightMarker(t *testing.T) {
	testenv.SetHome(t, t.TempDir())
	testenv.SetConfig(t, t.TempDir())
	testenv.SetState(t, t.TempDir())
	enableNightForHook(t)
	var out, errb strings.Builder
	if code := runSelftest(t, &out, &errb); code != 0 || !strings.Contains(out.String(), "selftest: all probes passed") {
		t.Fatalf("exit = %d under an active night marker\n%s", code, out.String())
	}
}

// Windows hosts send drive-lettered, backslash paths; the Engine normalises
// them only there. The Windows probes are appended on Windows and stay out
// of the POSIX matrix, but their shape is checked everywhere.
func TestWindowsSelftestProbesAreWellFormed(t *testing.T) {
	probes := windowsSelftestProbes()
	if len(probes) < 3 {
		t.Fatalf("windows probes = %d, want at least secret read, benign edit, destructive rm", len(probes))
	}
	want := map[string]string{
		"windows secret read denies":  "deny",
		"windows benign edit allows":  "allow",
		"windows rm -rf drive denies": "deny",
	}
	for _, p := range probes {
		if p.Plane != "claude" {
			t.Fatalf("%s: plane %q", p.Name, p.Plane)
		}
		var payload map[string]any
		if err := json.Unmarshal([]byte(p.Payload), &payload); err != nil {
			t.Fatalf("%s: payload is not JSON: %v", p.Name, err)
		}
		if !strings.Contains(p.Payload, `C:\\`) {
			t.Fatalf("%s: payload carries no drive-lettered path", p.Name)
		}
		if w, ok := want[p.Name]; ok && p.WantDecision != w {
			t.Fatalf("%s: wants %s, want %s", p.Name, p.WantDecision, w)
		}
		delete(want, p.Name)
	}
	if len(want) != 0 {
		t.Fatalf("missing windows probes: %v", want)
	}
	onMatrix := 0
	for _, p := range selftestProbes {
		if strings.HasPrefix(p.Name, "windows ") {
			onMatrix++
		}
	}
	if runtime.GOOS == "windows" && onMatrix != len(probes) {
		t.Fatalf("on windows the probes must be on the matrix: %d of %d", onMatrix, len(probes))
	}
	if runtime.GOOS != "windows" && onMatrix != 0 {
		t.Fatalf("on %s the windows probes must stay off the matrix: %d", runtime.GOOS, onMatrix)
	}
}

// On a Windows host the Windows probes run through the real hook path and
// their rule IDs are read from the audit record, exactly as selftest does.
// Skipped elsewhere: containment for drive paths is host-owned.
func TestWindowsSelftestProbesPassOnWindowsHost(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("windows probes are evaluated on a windows host")
	}
	state := t.TempDir()
	testenv.SetState(t, state)
	testenv.SetConfig(t, t.TempDir())
	t.Setenv("GUARDRAIL_CONFIG", "")
	suffix := "selftest-windows-" + t.Name()
	for _, probe := range windowsSelftestProbes() {
		payload := strings.ReplaceAll(probe.Payload, "selftest", suffix)
		var out, errb strings.Builder
		code := run(append([]string{"hook"}, probe.Args...), strings.NewReader(payload), &out, &errb)
		decision, rule := parseSelftestVerdict(code, out.String(), errb.String())
		if rule == "" && probe.WantRuleID != "" {
			rule = selftestRuleFromAudit(suffix)
		}
		if decision != probe.WantDecision || (probe.WantRuleID != "" && rule != probe.WantRuleID) {
			t.Errorf("%s: got %s/%s (exit %d, stderr %q), want %s/%s", probe.Name, decision, rule, code, errb.String(), probe.WantDecision, probe.WantRuleID)
		}
	}
}

// Codex's adapter demands a cwd that is absolute and real, and containment is
// host-owned, so its two probes are the only ones whose payload has to be
// spelled per host. Both spellings are checked on every host; a regression
// that reintroduces a POSIX-only cwd fails here rather than silently turning
// the codex plane's selftest into two unparseable payloads on Windows.
func TestWindowsCodexSelftestProbesAreHostShaped(t *testing.T) {
	for _, goos := range []string{"windows", "linux", "darwin"} {
		probes := codexSelftestProbes(goos)
		if len(probes) != 2 {
			t.Fatalf("%s: %d codex probes, want 2", goos, len(probes))
		}
		for _, probe := range probes {
			if probe.Plane != "codex" {
				t.Fatalf("%s: %s has plane %q", goos, probe.Name, probe.Plane)
			}
			var payload struct {
				CWD   string `json:"cwd"`
				Input struct {
					Command string `json:"command"`
				} `json:"tool_input"`
			}
			if err := json.Unmarshal([]byte(probe.Payload), &payload); err != nil {
				t.Fatalf("%s: %s payload is not JSON: %v", goos, probe.Name, err)
			}
			if payload.CWD == "" {
				t.Fatalf("%s: %s carries no cwd", goos, probe.Name)
			}
			if !strings.HasPrefix(probe.Name, "destructive") {
				continue
			}
			wantRoot := "/"
			if goos == "windows" {
				wantRoot = `C:\`
			}
			if !strings.HasSuffix(payload.Input.Command, "rm -rf "+wantRoot) {
				t.Fatalf("%s: destructive probe is %q, want it to end in %q — a root that is not absolute on this host deletes nothing and proves nothing",
					goos, payload.Input.Command, "rm -rf "+wantRoot)
			}
		}
	}
	// The running host's pair, and only that pair, is on the matrix.
	onMatrix := 0
	for _, probe := range selftestProbes {
		if probe.Plane == "codex" {
			onMatrix++
		}
	}
	if onMatrix != 2 {
		t.Fatalf("codex probes on the matrix = %d, want 2", onMatrix)
	}
}

// The whole matrix, on a Windows host, through the real hook path. CI's
// windows job selects tests by name, so a matrix regression on Windows is
// only visible to it through a test named like this one.
func TestWindowsSelftestMatrixPasses(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("the POSIX matrix is covered by the full suite on ubuntu and macos")
	}
	state := t.TempDir()
	testenv.SetHome(t, t.TempDir())
	testenv.SetConfig(t, t.TempDir())
	testenv.SetState(t, state)
	var out, errb strings.Builder
	if code := runSelftest(t, &out, &errb); code != 0 {
		t.Fatalf("selftest exit = %d on windows; stderr %q\n%s", code, errb.String(), out.String())
	}
	if !strings.Contains(out.String(), "selftest: all probes passed") {
		t.Fatalf("windows selftest did not report a clean pass:\n%s", out.String())
	}
}
