package genconfig

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
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
