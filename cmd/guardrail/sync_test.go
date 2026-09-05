package main

import (
	"bytes"
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

func TestSyncOpencodeBakesAbsoluteBinary(t *testing.T) {
	dir := t.TempDir()
	gitInitSync(t, dir)
	var out, errb bytes.Buffer
	code := run([]string{"sync", "--dir", dir, "--planes", "opencode", "--binary", "/ABS/SENTINEL/guardrail"}, strings.NewReader(""), &out, &errb)
	if code != 0 {
		t.Fatalf("exit=%d stderr=%s", code, errb.String())
	}
	js, err := os.ReadFile(filepath.Join(dir, ".guardrail", "guardrail.js"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(js), "/ABS/SENTINEL/guardrail") {
		t.Fatalf("synced plugin does not pin the absolute binary path:\n%s", js)
	}
	if strings.Contains(string(js), "process.env.GUARDRAIL_BIN") {
		t.Error("plugin still resolves its enforcer from the environment")
	}
}

func TestSyncOverlayReachesClaudeFloor(t *testing.T) {
	dir := t.TempDir()
	gitInitSync(t, dir)
	os.WriteFile(filepath.Join(dir, "guardrail.toml"), []byte(`
[slots]
secret_globs = ["secrets/prod/**"]
`), 0o644)
	var out, errb bytes.Buffer
	code := run([]string{"sync", "--dir", dir, "--planes", "claude", "--binary", "guardrail"}, strings.NewReader(""), &out, &errb)
	if code != 0 {
		t.Fatalf("exit=%d stderr=%s", code, errb.String())
	}
	raw, _ := os.ReadFile(filepath.Join(dir, ".claude", "settings.json"))
	if !strings.Contains(string(raw), "Read(secrets/prod/**)") {
		t.Fatalf("overlay secret_globs did not reach the synced Claude floor:\n%s", raw)
	}
}
