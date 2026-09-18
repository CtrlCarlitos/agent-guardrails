package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func runSelftest(t *testing.T, stdout, stderr *strings.Builder) int {
	t.Helper()
	return cmdSelftest([]string{}, stdout, stderr)
}

func TestSelftestPassesOnHealthyEnvironment(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("XDG_STATE_HOME", t.TempDir())
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
	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("XDG_STATE_HOME", t.TempDir())
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
	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	for run := 0; run < 2; run++ {
		var out, errb strings.Builder
		if code := runSelftest(t, &out, &errb); code != 0 {
			t.Fatalf("run %d exit = %d; stdout %q stderr %q", run, code, out.String(), errb.String())
		}
	}
}

func TestSelftestRecordsThePassedVersionInTheStateDir(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	state := t.TempDir()
	t.Setenv("XDG_STATE_HOME", state)
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
	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	state := t.TempDir()
	t.Setenv("XDG_STATE_HOME", state)
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
