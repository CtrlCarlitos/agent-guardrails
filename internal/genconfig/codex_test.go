package genconfig

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestCodexMergeRemoveAndDrift(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hooks.json")
	if err := os.WriteFile(path, []byte(`{"description":"keep","hooks":{"PreToolUse":[{"hooks":[{"type":"command","command":"user-hook"}]}]}}`), 0600); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if err := MergePlaneInto(path, "codex", CodexConfig("/opt/my tool/guardrail")); err != nil {
			t.Fatal(err)
		}
	}
	raw, _ := os.ReadFile(path)
	if strings.Count(string(raw), "guardrail-codex-PreToolUse") != 1 || !strings.Contains(string(raw), "user-hook") {
		t.Fatal(string(raw))
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if !CodexHooksRegistered(doc) {
		t.Fatal("not registered")
	}
	hooks := doc["hooks"].(map[string]any)
	var pre map[string]any
	for _, raw := range hooks["PreToolUse"].([]any) {
		group := raw.(map[string]any)
		if group["id"] == "guardrail-codex-PreToolUse" {
			pre = group
			break
		}
	}
	if pre == nil {
		t.Fatal("owned PreToolUse group missing")
	}
	handler := pre["hooks"].([]any)[0].(map[string]any)
	windowsCommand := handler["commandWindows"]
	delete(handler, "commandWindows")
	if CodexHooksRegistered(doc) {
		t.Fatal("missing Windows command accepted")
	}
	handler["commandWindows"] = windowsCommand
	delete(hooks, "PreToolUse")
	if CodexHooksRegistered(doc) {
		t.Fatal("missing pre accepted")
	}
	if err := RemovePlaneFrom(path, "codex"); err != nil {
		t.Fatal(err)
	}
	raw, _ = os.ReadFile(path)
	if strings.Contains(string(raw), "guardrail-codex") || !strings.Contains(string(raw), "user-hook") || !strings.Contains(string(raw), "keep") {
		t.Fatal(string(raw))
	}
}

func TestCodexRulesOwnership(t *testing.T) {
	hooks := filepath.Join(t.TempDir(), "hooks.json")
	if err := WriteCodexRules(hooks); err != nil {
		t.Fatal(err)
	}
	if err := WriteCodexRules(hooks); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(filepath.Dir(hooks), "rules", "guardrail.rules")
	if err := os.WriteFile(path, []byte("# user-owned\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := WriteCodexRules(hooks); err == nil {
		t.Fatal("overwrote user file")
	}
}

func TestCodexMissingBinaryBlocksAndQuotedPathCannotExecute(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "must-not-exist")
	binary := "/missing/guardrail'; touch " + marker + "; '"
	hooks := CodexConfig(binary)["hooks"].(map[string]any)
	group := hooks["PreToolUse"].([]any)[0].(map[string]any)
	command := group["hooks"].([]any)[0].(map[string]any)["command"].(string)
	cmd := exec.Command("sh", "-c", command)
	if err := cmd.Run(); err == nil || cmd.ProcessState.ExitCode() != 2 {
		t.Fatalf("missing binary did not block: %v", err)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatal("binary path was interpreted as shell code")
	}
}

func TestCodexWindowsCommandRunsAndFailsClosed(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows command handlers execute through cmd.exe")
	}
	dir := filepath.Join(t.TempDir(), "guardrail tools & helpers 'quoted'")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(dir, "guardrail.cmd")
	if err := os.WriteFile(binary, []byte("@findstr /c:\"session_id\" >nul || exit /b 9\r\n@exit /b %GUARDRAIL_TEST_EXIT%\r\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	frag := CodexConfig(binary)
	hooks := frag["hooks"].(map[string]any)
	group := hooks["PreToolUse"].([]any)[0].(map[string]any)
	handler := group["hooks"].([]any)[0].(map[string]any)
	command, ok := handler["commandWindows"].(string)
	if !ok || command == "" {
		t.Fatalf("Windows command override = %#v, want nonempty string", handler["commandWindows"])
	}

	for _, test := range []struct {
		name     string
		exit     string
		wantExit int
	}{
		{name: "evaluator allows", exit: "0", wantExit: 0},
		{name: "evaluator fails", exit: "7", wantExit: 2},
	} {
		t.Run(test.name, func(t *testing.T) {
			cmd := exec.Command(os.Getenv("ComSpec"), "/d", "/s", "/c", command)
			cmd.Env = append(os.Environ(), "GUARDRAIL_TEST_EXIT="+test.exit)
			cmd.Stdin = strings.NewReader(`{"session_id":"fixture"}`)
			_ = cmd.Run()
			if got := cmd.ProcessState.ExitCode(); got != test.wantExit {
				t.Fatalf("exit = %d, want %d; command: %s", got, test.wantExit, command)
			}
		})
	}
}
