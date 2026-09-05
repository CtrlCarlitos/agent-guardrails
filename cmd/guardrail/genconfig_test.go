package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writePathExecutable(t *testing.T, dir, name string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestGenConfigNoPlane(t *testing.T) {
	var out, errb bytes.Buffer
	code := run([]string{"gen-config"}, strings.NewReader(""), &out, &errb)
	if code != 2 {
		t.Fatalf("exit = %d, want 2", code)
	}
	if !strings.Contains(errb.String(), "plane") {
		t.Fatalf("stderr = %q, want it to mention a plane", errb.String())
	}
}

func TestGenConfigUnsupportedPlane(t *testing.T) {
	var out, errb bytes.Buffer
	code := run([]string{"gen-config", "emacs"}, strings.NewReader(""), &out, &errb)
	if code != 2 || !strings.Contains(errb.String(), "emacs") {
		t.Fatalf("exit=%d stderr=%q", code, errb.String())
	}
}

func TestGenConfigBadFlag(t *testing.T) {
	var out, errb bytes.Buffer
	code := run([]string{"gen-config", "claude", "--nope"}, strings.NewReader(""), &out, &errb)
	if code != 2 {
		t.Fatalf("exit = %d, want 2", code)
	}
}

func TestGenConfigClaudePrint(t *testing.T) {
	var out, errb bytes.Buffer
	code := run([]string{"gen-config", "claude", "--print"}, strings.NewReader(""), &out, &errb)
	if code != 0 {
		t.Fatalf("exit=%d stderr=%q", code, errb.String())
	}
	var frag map[string]any
	if err := json.Unmarshal(out.Bytes(), &frag); err != nil {
		t.Fatalf("stdout is not JSON: %v\n%s", err, out.String())
	}
	if _, ok := frag["hooks"]; !ok {
		t.Error("no hooks key")
	}
	if _, ok := frag["permissions"]; !ok {
		t.Error("no permissions key")
	}
}

func TestGenConfigClaudeMerge(t *testing.T) {
	p := filepath.Join(t.TempDir(), "settings.json")
	var out, errb bytes.Buffer
	code := run([]string{"gen-config", "claude", "--merge", p, "--binary", "/opt/guardrail"}, strings.NewReader(""), &out, &errb)
	if code != 0 {
		t.Fatalf("exit=%d stderr=%q", code, errb.String())
	}
	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	pre := m["hooks"].(map[string]any)["PreToolUse"].([]any)[0].(map[string]any)
	gotCmd := pre["hooks"].([]any)[0].(map[string]any)["command"].(string)
	if gotCmd != "/opt/guardrail hook claude" {
		t.Errorf("command = %q", gotCmd)
	}
	// second run must be a no-op
	before := string(raw)
	run([]string{"gen-config", "claude", "--merge", p, "--binary", "/opt/guardrail"}, strings.NewReader(""), &out, &errb)
	after, _ := os.ReadFile(p)
	if before != string(after) {
		t.Errorf("second merge changed the file")
	}
}

func TestGenConfigPrintFalseIsNoOp(t *testing.T) {
	var out, errb bytes.Buffer
	code := run([]string{"gen-config", "claude", "--print=false"}, strings.NewReader(""), &out, &errb)
	if code != 2 {
		t.Fatalf("exit = %d, want 2", code)
	}
	if out.Len() != 0 {
		t.Fatalf("stdout should be empty, got %q", out.String())
	}
	if !strings.Contains(errb.String(), "nothing to do") {
		t.Fatalf("stderr = %q", errb.String())
	}
}

func TestGenConfigOpencodeMergeDeploysPlugin(t *testing.T) {
	dir := t.TempDir()
	settingsPath := filepath.Join(dir, "opencode.json")
	os.WriteFile(settingsPath, []byte(`{"plugin":["superpowers@git+https://github.com/obra/superpowers.git"]}`), 0o644)

	var out, errb bytes.Buffer
	code := run([]string{"gen-config", "opencode", "--merge", settingsPath, "--binary", "/opt/guardrail"}, strings.NewReader(""), &out, &errb)
	if code != 0 {
		t.Fatalf("exit=%d stderr=%s", code, errb.String())
	}

	pluginPath := filepath.Join(dir, "guardrail.js")
	if _, err := os.Stat(pluginPath); err != nil {
		t.Fatalf("plugin file not written: %v", err)
	}
	js, _ := os.ReadFile(pluginPath)
	if !strings.Contains(string(js), "tool.execute.before") {
		t.Fatalf("deployed plugin looks wrong:\n%s", js)
	}

	raw, _ := os.ReadFile(settingsPath)
	var m map[string]any
	json.Unmarshal(raw, &m)
	plugins := m["plugin"].([]any)
	foundSuperpowers, foundGuardrail := false, false
	for _, p := range plugins {
		s := p.(string)
		if strings.Contains(s, "superpowers") {
			foundSuperpowers = true
		}
		if s == pluginPath {
			foundGuardrail = true
		}
	}
	if !foundSuperpowers {
		t.Error("existing superpowers plugin entry was lost")
	}
	if !foundGuardrail {
		t.Errorf("guardrail plugin path %q not registered; plugin array = %v", pluginPath, plugins)
	}

	perm := m["permission"].(map[string]any)
	if _, ok := perm["bash"]; !ok {
		t.Error("permission.bash missing")
	}
}

func TestGenConfigOpencodeBakesAbsoluteBinary(t *testing.T) {
	dir := t.TempDir()
	settings := filepath.Join(dir, "opencode.json")
	if err := os.WriteFile(settings, []byte(`{}`), 0o644); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	code := run([]string{"gen-config", "opencode", "--merge", settings, "--binary", "/ABS/SENTINEL/guardrail"}, strings.NewReader(""), &out, &errb)
	if code != 0 {
		t.Fatalf("exit=%d stderr=%s", code, errb.String())
	}
	js, err := os.ReadFile(filepath.Join(dir, "guardrail.js"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(js), "/ABS/SENTINEL/guardrail") {
		t.Fatalf("deployed plugin does not pin the absolute binary path:\n%s", js)
	}
	if strings.Contains(string(js), "process.env.GUARDRAIL_BIN") {
		t.Error("plugin still resolves its enforcer from the environment")
	}
}

func TestGenConfigOpencodeResolvesBareBinaryFromPATH(t *testing.T) {
	dir := t.TempDir()
	settings := filepath.Join(dir, "opencode.json")
	if err := os.WriteFile(settings, []byte(`{}`), 0o644); err != nil {
		t.Fatal(err)
	}
	binDir := t.TempDir()
	wantBinary := writePathExecutable(t, binDir, "guardrail-sentinel")
	t.Setenv("PATH", binDir)

	var out, errb bytes.Buffer
	code := run([]string{"gen-config", "opencode", "--merge", settings, "--binary", "guardrail-sentinel"}, strings.NewReader(""), &out, &errb)
	if code != 0 {
		t.Fatalf("exit=%d stderr=%s", code, errb.String())
	}
	js, err := os.ReadFile(filepath.Join(dir, "guardrail.js"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(js), wantBinary) {
		t.Fatalf("deployed plugin does not contain PATH-resolved binary %q:\n%s", wantBinary, js)
	}
}

func TestGenConfigOpencodeRejectsUnresolvedBareBinaryBeforeDeployment(t *testing.T) {
	dir := t.TempDir()
	settings := filepath.Join(dir, "opencode.json")
	before := []byte(`{"plugin":["existing"]}`)
	if err := os.WriteFile(settings, before, 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", t.TempDir())

	var out, errb bytes.Buffer
	code := run([]string{"gen-config", "opencode", "--merge", settings, "--binary", "missing-guardrail"}, strings.NewReader(""), &out, &errb)
	if code != 2 {
		t.Fatalf("exit=%d, want 2; stderr=%s", code, errb.String())
	}
	wantErr := "guardrail: gen-config: cannot resolve --binary: executable \"missing-guardrail\" not found in PATH\n"
	if errb.String() != wantErr {
		t.Fatalf("stderr = %q, want %q", errb.String(), wantErr)
	}
	if out.Len() != 0 {
		t.Fatalf("stdout = %q, want empty", out.String())
	}
	after, err := os.ReadFile(settings)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(after, before) {
		t.Fatalf("settings changed on resolution failure:\n%s", after)
	}
	if _, err := os.Stat(filepath.Join(dir, "guardrail.js")); !os.IsNotExist(err) {
		t.Fatalf("plugin was deployed on resolution failure: %v", err)
	}
}

func TestGenConfigAntigravityPrint(t *testing.T) {
	var out, errb bytes.Buffer
	code := run([]string{"gen-config", "antigravity", "--print", "--binary", "/opt/guardrail"}, strings.NewReader(""), &out, &errb)
	if code != 0 {
		t.Fatalf("exit=%d stderr=%s", code, errb.String())
	}
	var frag map[string]any
	if err := json.Unmarshal(out.Bytes(), &frag); err != nil {
		t.Fatalf("stdout is not JSON: %v\n%s", err, out.String())
	}
	g, ok := frag["guardrail"].(map[string]any)
	if !ok {
		t.Fatal("no guardrail wrapper key")
	}
	if _, ok := g["PreToolUse"]; !ok {
		t.Error("no PreToolUse hooks inside the guardrail wrapper")
	}
	if _, ok := frag["permissions"]; ok {
		t.Error("antigravity fragment should not have a permissions key")
	}
}

func TestGenConfigAntigravityMerge(t *testing.T) {
	p := filepath.Join(t.TempDir(), "hooks.json")
	var out, errb bytes.Buffer
	code := run([]string{"gen-config", "antigravity", "--merge", p, "--binary", "/opt/guardrail"}, strings.NewReader(""), &out, &errb)
	if code != 0 {
		t.Fatalf("exit=%d stderr=%s", code, errb.String())
	}
	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "guardrail-antigravity-pre") {
		t.Fatalf("merged file missing the owned pre-hook id:\n%s", raw)
	}
}

func TestGenConfigDefaultStillPrints(t *testing.T) {
	var out, errb bytes.Buffer
	code := run([]string{"gen-config", "claude"}, strings.NewReader(""), &out, &errb)
	if code != 0 || out.Len() == 0 {
		t.Fatalf("exit=%d stdout=%q", code, out.String())
	}
}
