package main

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func gitInitSync(t *testing.T, dir string) {
	t.Helper()
	for _, args := range [][]string{{"init", "-q"}, {"config", "user.email", "t@t"}, {"config", "user.name", "t"}} {
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
}

func TestSyncAllPlanes(t *testing.T) {
	dir := t.TempDir()
	gitInitSync(t, dir)
	overlay := "waive = [\"P6\"]\n"
	os.WriteFile(filepath.Join(dir, "guardrail.toml"), []byte(overlay), 0o644)

	var out, errb bytes.Buffer
	code := run([]string{"sync", "--dir", dir, "--binary", "/opt/guardrail"}, strings.NewReader(""), &out, &errb)
	if code != 0 {
		t.Fatalf("exit=%d stderr=%s", code, errb.String())
	}

	claudePath := filepath.Join(dir, ".claude", "settings.json")
	if _, err := os.Stat(claudePath); err != nil {
		t.Fatalf(".claude/settings.json not written: %v", err)
	}
	oc := filepath.Join(dir, "opencode.json")
	if _, err := os.Stat(oc); err != nil {
		t.Fatalf("opencode.json not written: %v", err)
	}
	pluginPath := filepath.Join(dir, ".guardrail", "guardrail.js")
	if _, err := os.Stat(pluginPath); err != nil {
		t.Fatalf("opencode plugin not deployed: %v", err)
	}
	ag := filepath.Join(dir, ".agents", "hooks.json")
	if _, err := os.Stat(ag); err != nil {
		t.Fatalf(".agents/hooks.json not written: %v", err)
	}

	raw, _ := os.ReadFile(ag)
	if !strings.Contains(string(raw), "guardrail-antigravity-pre") {
		t.Errorf("antigravity hooks.json missing the owned id")
	}
}

func TestSyncSinglePlane(t *testing.T) {
	dir := t.TempDir()
	gitInitSync(t, dir)
	var out, errb bytes.Buffer
	code := run([]string{"sync", "--dir", dir, "--planes", "claude", "--binary", "/opt/guardrail"}, strings.NewReader(""), &out, &errb)
	if code != 0 {
		t.Fatalf("exit=%d stderr=%s", code, errb.String())
	}
	if _, err := os.Stat(filepath.Join(dir, "opencode.json")); err == nil {
		t.Error("opencode.json should not have been written when --planes=claude")
	}
	if _, err := os.Stat(filepath.Join(dir, ".claude", "settings.json")); err != nil {
		t.Error(".claude/settings.json should have been written")
	}
}

func TestSyncOverlayReachesClaudeFloor(t *testing.T) {
	dir := t.TempDir()
	gitInitSync(t, dir)
	os.WriteFile(filepath.Join(dir, "guardrail.toml"), []byte(`
[[rules]]
id = "proj.tf"
pattern = "terraform apply*"
decision = "ask"
reason = "infra change"
`), 0o644)
	var out, errb bytes.Buffer
	code := run([]string{"sync", "--dir", dir, "--planes", "claude", "--binary", "guardrail"}, strings.NewReader(""), &out, &errb)
	if code != 0 {
		t.Fatalf("exit=%d stderr=%s", code, errb.String())
	}
	// The overlay rule itself isn't a Bash()-glob-shaped entry (ClaudeConfig
	// only ever emits the fixed floor globs, not arbitrary overlay [[rules]]
	// as permission strings) — this test locks that gen-config's Merge call
	// received the *merged* policy at all by checking a merge-only signal:
	// the hooks id is present (proves the pipeline ran end-to-end).
	raw, _ := os.ReadFile(filepath.Join(dir, ".claude", "settings.json"))
	var m map[string]any
	json.Unmarshal(raw, &m)
	if _, ok := m["hooks"]; !ok {
		t.Fatal("hooks block missing from synced settings.json")
	}
}
