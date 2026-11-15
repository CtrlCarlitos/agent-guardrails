package main

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func antigravityHooksDoc(preCommand string) map[string]any {
	return map[string]any{"guardrail": map[string]any{
		"enabled": true,
		"PreToolUse": []any{map[string]any{
			"id":    "guardrail-antigravity-pre",
			"hooks": []any{map[string]any{"type": "command", "command": preCommand}},
		}},
	}}
}

// agy hands the command to `cmd /C` through Go, which turns every quote into
// \" (#353). doctor reported Antigravity healthy while every tool call was
// denied, because it only read the file. It has to spawn what the file says.
func TestAntigravityHookSpawnProblemsNamesAnUnspawnableCommand(t *testing.T) {
	spawn := func(exe string) error {
		if strings.Contains(exe, `"`) {
			return errors.New(`'\"…\"' is not recognized as an internal or external command`)
		}
		return nil
	}
	got := antigravityHookSpawnProblems(antigravityHooksDoc(`"C:/Users/u/.local/bin/guardrail.exe" hook antigravity pre`), spawn)
	if len(got) != 1 {
		t.Fatalf("problems = %v, want exactly one", got)
	}
	for _, want := range []string{"guardrail-antigravity-pre", "cannot spawn", "plane enable antigravity"} {
		if !strings.Contains(got[0], want) {
			t.Errorf("problem %q does not mention %q", got[0], want)
		}
	}
	if problems := antigravityHookSpawnProblems(antigravityHooksDoc(`C:/Users/u/.local/bin/guardrail.exe hook antigravity pre`), spawn); len(problems) != 0 {
		t.Fatalf("a bare command that spawns reported %v", problems)
	}
}

// Only guardrail's own groups are probed; another tool's hook in the same
// file is not this doctor's to run.
func TestAntigravityHookSpawnProblemsIgnoresForeignGroups(t *testing.T) {
	doc := map[string]any{"guardrail": map[string]any{
		"PreToolUse": []any{map[string]any{
			"id":    "other-tool-pre",
			"hooks": []any{map[string]any{"type": "command", "command": `"C:/x/other.exe" run`}},
		}},
	}}
	spawn := func(string) error { return errors.New("must not be called") }
	if got := antigravityHookSpawnProblems(doc, spawn); len(got) != 0 {
		t.Fatalf("foreign group probed: %v", got)
	}
}

// The real spawn, end to end: the stub is reachable bare and unreachable
// quoted, exactly as under agy.
func TestWindowsAntigravityHookSpawnProbeUsesCmdWithGoQuoteEscaping(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("cmd.exe spawn semantics")
	}
	dir := t.TempDir()
	if strings.ContainsAny(dir, " &()^%!") {
		t.Skipf("temp dir %q needs quoting", dir)
	}
	stub := filepath.ToSlash(filepath.Join(dir, "guardrail.cmd"))
	if err := os.WriteFile(filepath.Join(dir, "guardrail.cmd"), []byte("@exit /b 0\r\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := antigravityHookSpawnProblems(antigravityHooksDoc(stub+" hook antigravity pre"), agySpawn); len(got) != 0 {
		t.Fatalf("bare stub reported %v", got)
	}
	if got := antigravityHookSpawnProblems(antigravityHooksDoc(`"`+stub+`" hook antigravity pre`), agySpawn); len(got) != 1 {
		t.Fatalf("quoted stub reported %v, want one problem", got)
	}
}

// #358: a binary path agy cannot spawn is named at setup time, before the
// plane is armed and every tool call is denied. The path is one that exists on
// no host, so no 8.3 name can rescue it.
func TestAntigravitySpawnWarningNamesAnUnspawnableBinaryPath(t *testing.T) {
	const spaced = `C:\Program Files\guardrail-358-absent\guardrail.exe`
	got := antigravitySpawnWarning(spaced, []string{"claude", "antigravity"}, "enabled")
	for _, want := range []string{"Antigravity cannot spawn", "path without a space", spaced} {
		if !strings.Contains(got, want) {
			t.Errorf("warning %q does not mention %q", got, want)
		}
	}
	for name, warn := range map[string]string{
		"antigravity not requested": antigravitySpawnWarning(spaced, []string{"claude"}, "enabled"),
		"disabling":                 antigravitySpawnWarning(spaced, []string{"antigravity"}, "disabled"),
		"spawnable path":            antigravitySpawnWarning(`C:\Users\u\.local\bin\guardrail.exe`, []string{"antigravity"}, "enabled"),
		"posix path with a space":   antigravitySpawnWarning(`/home/first last/bin/guardrail`, []string{"antigravity"}, "enabled"),
	} {
		if warn != "" {
			t.Errorf("%s: unexpected warning %q", name, warn)
		}
	}
}

// #358: `guardrail plane enable antigravity` must surface the same warning
// `setup` prints when the running binary path contains a space and has no 8.3
// short name on the volume.
func TestWindowsPlaneEnableAntigravityWarnsOnUnspawnableBinaryPath(t *testing.T) {
	driftSandbox(t)
	const spaced = `C:\Program Files\guardrail-358-absent\guardrail.exe`
	useInstalledExecutable(t, spaced)
	useInstalledPlanes(t, "antigravity", "claude")
	useTransport(t, []string{"approved"})

	var out, errb strings.Builder
	if code := runPlaneTerminal(t, []string{"plane", "enable", "antigravity"}, &out, &errb); code != 0 {
		t.Fatalf("exit = %d, want 0; stdout=%q stderr=%q", code, out.String(), errb.String())
	}
	for _, want := range []string{"Antigravity cannot spawn", "path without a space", spaced} {
		if !strings.Contains(errb.String(), want) {
			t.Errorf("stderr %q does not mention %q", errb.String(), want)
		}
	}

	// Enabling another plane must not emit the Antigravity warning.
	out.Reset()
	errb.Reset()
	useTransport(t, []string{"approved"})
	if code := runPlaneTerminal(t, []string{"plane", "enable", "claude"}, &out, &errb); code != 0 {
		t.Fatalf("claude enable exit = %d; stderr=%q", code, errb.String())
	}
	if strings.Contains(errb.String(), "Antigravity cannot spawn") {
		t.Errorf("claude enable emitted Antigravity warning: %q", errb.String())
	}
}
