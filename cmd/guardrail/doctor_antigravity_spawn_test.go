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
