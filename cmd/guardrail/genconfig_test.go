package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

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

func TestGenConfigDefaultStillPrints(t *testing.T) {
	var out, errb bytes.Buffer
	code := run([]string{"gen-config", "claude"}, strings.NewReader(""), &out, &errb)
	if code != 0 || out.Len() == 0 {
		t.Fatalf("exit=%d stdout=%q", code, out.String())
	}
}
