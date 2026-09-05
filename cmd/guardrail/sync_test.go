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

func TestSyncOpencodeResolvesBareBinaryFromPATH(t *testing.T) {
	dir := t.TempDir()
	gitInitSync(t, dir)
	binDir := t.TempDir()
	wantBinary := writePathExecutable(t, binDir, "guardrail-sentinel")
	t.Setenv("PATH", binDir)

	var out, errb bytes.Buffer
	code := run([]string{"sync", "--dir", dir, "--planes", "opencode", "--binary", "guardrail-sentinel"}, strings.NewReader(""), &out, &errb)
	if code != 0 {
		t.Fatalf("exit=%d stderr=%s", code, errb.String())
	}
	js, err := os.ReadFile(filepath.Join(dir, ".guardrail", "guardrail.js"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(js), wantBinary) {
		t.Fatalf("synced plugin does not contain PATH-resolved binary %q:\n%s", wantBinary, js)
	}
}

func TestSyncMixedPlanesResolveBinaryOnlyForOpencode(t *testing.T) {
	dir := t.TempDir()
	gitInitSync(t, dir)
	binDir := filepath.Join(t.TempDir(), "bin with spaces;$(not-run)")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatal(err)
	}
	wantBinary := writePathExecutable(t, binDir, "guardrail-sentinel")
	t.Setenv("PATH", binDir)

	var out, errb bytes.Buffer
	code := run([]string{"sync", "--dir", dir, "--planes", "claude,opencode,antigravity", "--binary", "guardrail-sentinel"}, strings.NewReader(""), &out, &errb)
	if code != 0 {
		t.Fatalf("exit=%d stderr=%s", code, errb.String())
	}

	plugin, err := os.ReadFile(filepath.Join(dir, ".guardrail", "guardrail.js"))
	if err != nil {
		t.Fatal(err)
	}
	encodedBinary, err := json.Marshal(wantBinary)
	if err != nil {
		t.Fatal(err)
	}
	wantDeclaration := "const GUARDRAIL_BIN = " + string(encodedBinary) + ";"
	if !strings.Contains(string(plugin), wantDeclaration) {
		t.Fatalf("OpenCode plugin does not pin the exact PATH result %q:\n%s", wantBinary, plugin)
	}

	claudeRaw, err := os.ReadFile(filepath.Join(dir, ".claude", "settings.json"))
	if err != nil {
		t.Fatal(err)
	}
	var claude map[string]any
	if err := json.Unmarshal(claudeRaw, &claude); err != nil {
		t.Fatal(err)
	}
	claudePre := claude["hooks"].(map[string]any)["PreToolUse"].([]any)[0].(map[string]any)
	claudeCommand := claudePre["hooks"].([]any)[0].(map[string]any)["command"].(string)
	if claudeCommand != "guardrail-sentinel hook claude" {
		t.Fatalf("Claude command = %q, want original bare binary semantics", claudeCommand)
	}

	antigravityRaw, err := os.ReadFile(filepath.Join(dir, ".agents", "hooks.json"))
	if err != nil {
		t.Fatal(err)
	}
	var antigravity map[string]any
	if err := json.Unmarshal(antigravityRaw, &antigravity); err != nil {
		t.Fatal(err)
	}
	guardrail := antigravity["guardrail"].(map[string]any)
	antigravityPre := guardrail["PreToolUse"].([]any)[0].(map[string]any)
	antigravityCommand := antigravityPre["hooks"].([]any)[0].(map[string]any)["command"].(string)
	if antigravityCommand != "guardrail-sentinel hook antigravity pre" {
		t.Fatalf("Antigravity command = %q, want original bare binary semantics", antigravityCommand)
	}
}

func TestSyncMixedPlanesRejectUnresolvedBareBinaryBeforeDeployment(t *testing.T) {
	dir := t.TempDir()
	gitInitSync(t, dir)
	t.Setenv("PATH", t.TempDir())

	var out, errb bytes.Buffer
	code := run([]string{"sync", "--dir", dir, "--planes", "claude,opencode,antigravity", "--binary", "missing-guardrail"}, strings.NewReader(""), &out, &errb)
	if code != 2 {
		t.Fatalf("exit=%d, want 2; stderr=%s", code, errb.String())
	}
	wantErr := "guardrail: sync: cannot resolve --binary: executable \"missing-guardrail\" not found in PATH\n"
	if errb.String() != wantErr {
		t.Fatalf("stderr = %q, want %q", errb.String(), wantErr)
	}
	if out.Len() != 0 {
		t.Fatalf("stdout = %q, want empty", out.String())
	}
	for _, path := range []string{
		filepath.Join(dir, ".claude"),
		filepath.Join(dir, ".guardrail"),
		filepath.Join(dir, "opencode.json"),
		filepath.Join(dir, ".agents"),
	} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("%s was deployed on resolution failure: %v", path, err)
		}
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
