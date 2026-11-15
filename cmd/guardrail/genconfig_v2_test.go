package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGenConfigOpencodeMajor2WritesDirectoryAndNativeConfig(t *testing.T) {
	dir := t.TempDir()
	settingsPath := filepath.Join(dir, "opencode.json")
	if err := os.WriteFile(settingsPath, []byte(`{"plugin":["superpowers@git+https://github.com/obra/superpowers.git"]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	// A real fixture path, not a POSIX literal: on Windows the resolver
	// absolutizes and the plugin JS-escapes the binary path, so a raw
	// "/opt/guardrail" assertion cannot match there (#554).
	binary, wantDeclaration := opencodeBinaryFixture(t)

	var out, errb bytes.Buffer
	code := run([]string{"gen-config", "opencode", "--merge", settingsPath, "--binary", binary, "--major", "2"}, strings.NewReader(""), &out, &errb)
	if code != 0 {
		t.Fatalf("exit=%d stderr=%s", code, errb.String())
	}

	artifact := filepath.Join(dir, "guardrail", "index.js")
	js, err := os.ReadFile(artifact)
	if err != nil {
		t.Fatalf("V2 directory artifact not written: %v", err)
	}
	if !strings.Contains(string(js), "execute.before") || !strings.Contains(string(js), wantDeclaration) {
		t.Fatalf("deployed V2 plugin looks wrong:\n%s", js)
	}
	if _, err := os.Stat(filepath.Join(dir, "guardrail.js")); !os.IsNotExist(err) {
		t.Fatal("--major 2 must not write the V1 single-file artifact")
	}

	raw, _ := os.ReadFile(settingsPath)
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	if _, exists := m["plugin"]; !exists || !strings.Contains(strings.Join(toStrings(m["plugin"]), ","), "superpowers") {
		t.Fatalf("operator's V1-era plugin entries must survive: %v", m["plugin"])
	}
	plugins, _ := m["plugins"].([]any)
	if len(plugins) != 1 || plugins[0] != filepath.Join(dir, "guardrail") {
		t.Fatalf("plugins = %v, want the guardrail directory", m["plugins"])
	}
	perms, _ := m["permissions"].([]any)
	if len(perms) != 1 || perms[0].(map[string]any)["action"] != "external_directory" {
		t.Fatalf("permissions = %v, want the external_directory ask", m["permissions"])
	}
}

func TestGenConfigOpencodeMajor1KeepsTodayShape(t *testing.T) {
	dir := t.TempDir()
	settingsPath := filepath.Join(dir, "opencode.json")
	if err := os.WriteFile(settingsPath, []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	code := run([]string{"gen-config", "opencode", "--merge", settingsPath, "--binary", "/opt/guardrail", "--major", "1"}, strings.NewReader(""), &out, &errb)
	if code != 0 {
		t.Fatalf("exit=%d stderr=%s", code, errb.String())
	}
	if _, err := os.Stat(filepath.Join(dir, "guardrail.js")); err != nil {
		t.Fatal("--major 1 must keep the single-file artifact")
	}
	if _, err := os.Stat(filepath.Join(dir, "guardrail")); !os.IsNotExist(err) {
		t.Fatal("--major 1 must not write the directory artifact")
	}
	raw, _ := os.ReadFile(settingsPath)
	var m map[string]any
	json.Unmarshal(raw, &m)
	if _, exists := m["plugins"]; exists {
		t.Fatal("--major 1 must not write the plugins key")
	}
	if _, exists := m["permissions"]; exists {
		t.Fatal("--major 1 must not write the permissions array")
	}
}

func TestGenConfigOpencodeRejectsUnknownMajor(t *testing.T) {
	var out, errb bytes.Buffer
	code := run([]string{"gen-config", "opencode", "--major", "3"}, strings.NewReader(""), &out, &errb)
	if code != 2 {
		t.Fatalf("exit=%d, want 2", code)
	}
	if !strings.Contains(errb.String(), "--major") {
		t.Fatalf("stderr = %q, want a --major usage error", errb.String())
	}
}

func TestGenConfigOpencodeAutoDetectsMajor(t *testing.T) {
	dir := t.TempDir()
	settingsPath := filepath.Join(dir, "opencode.json")
	if err := os.WriteFile(settingsPath, []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	useOpencodeMajor(t, "opencode v2.3.0\n", false)
	var out, errb bytes.Buffer
	code := run([]string{"gen-config", "opencode", "--merge", settingsPath, "--binary", "/opt/guardrail"}, strings.NewReader(""), &out, &errb)
	if code != 0 {
		t.Fatalf("exit=%d stderr=%s", code, errb.String())
	}
	if _, err := os.Stat(filepath.Join(dir, "guardrail", "index.js")); err != nil {
		t.Fatal("auto-detected V2 must write the directory artifact")
	}

	dir2 := t.TempDir()
	settings2 := filepath.Join(dir2, "opencode.json")
	if err := os.WriteFile(settings2, []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	useOpencodeMajor(t, "1.19.5\n", false)
	code = run([]string{"gen-config", "opencode", "--merge", settings2, "--binary", "/opt/guardrail"}, strings.NewReader(""), &out, &errb)
	if code != 0 {
		t.Fatalf("exit=%d stderr=%s", code, errb.String())
	}
	if _, err := os.Stat(filepath.Join(dir2, "guardrail.js")); err != nil {
		t.Fatal("auto-detected V1 must keep the single-file artifact")
	}

	dir3 := t.TempDir()
	settings3 := filepath.Join(dir3, "opencode.json")
	if err := os.WriteFile(settings3, []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	useOpencodeMajor(t, "", true)
	errb.Reset()
	code = run([]string{"gen-config", "opencode", "--merge", settings3, "--binary", "/opt/guardrail"}, strings.NewReader(""), &out, &errb)
	if code != 0 {
		t.Fatalf("exit=%d stderr=%s", code, errb.String())
	}
	// gen-config is a scripted command: an undetectable major silently
	// assumes V1 (today's behavior); the loud note belongs to plane
	// enable/setup and doctor, so callers parsing stderr see no new noise.
	if strings.Contains(errb.String(), "major not detected") {
		t.Fatalf("gen-config must not print the major note on stderr: %q", errb.String())
	}
	if _, err := os.Stat(filepath.Join(dir3, "guardrail.js")); err != nil {
		t.Fatal("undetectable major must assume V1")
	}
}

func TestSyncOpencodeMajor2WritesDirectoryEntry(t *testing.T) {
	dir := t.TempDir()
	var out, errb bytes.Buffer
	code := run([]string{"sync", "--dir", dir, "--planes", "opencode", "--binary", "/opt/guardrail", "--major", "2"}, strings.NewReader(""), &out, &errb)
	if code != 0 {
		t.Fatalf("exit=%d stderr=%s out=%s", code, errb.String(), out.String())
	}
	artifact := filepath.Join(dir, ".guardrail", "guardrail", "index.js")
	if _, err := os.Stat(artifact); err != nil {
		t.Fatalf("sync V2 artifact missing: %v", err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "opencode.json"))
	if err != nil {
		t.Fatalf("repo opencode.json missing: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	plugins, _ := m["plugins"].([]any)
	if len(plugins) != 1 || plugins[0] != filepath.Join(dir, ".guardrail", "guardrail") {
		t.Fatalf("plugins = %v", m["plugins"])
	}
	if _, exists := m["plugin"]; exists {
		t.Fatal("sync --major 2 must not write the V1 plugin key")
	}
}

func toStrings(v any) []string {
	list, _ := v.([]any)
	out := make([]string, 0, len(list))
	for _, e := range list {
		s, _ := e.(string)
		out = append(out, s)
	}
	return out
}

// The V2 emission must bake the exact binary path the way the V1 generator
// does (#554): named to sit beside TestGenConfigOpencodeBakesAbsoluteBinary
// so the Windows CI job's name filter runs it — the raw-literal assertion it
// replaces failed only on Windows, invisibly to that filter.
func TestGenConfigOpencodeMajor2BakesAbsoluteBinary(t *testing.T) {
	dir := t.TempDir()
	binary, wantDeclaration := opencodeBinaryFixture(t)
	settings := filepath.Join(dir, "opencode.json")
	if err := os.WriteFile(settings, []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	code := run([]string{"gen-config", "opencode", "--merge", settings, "--binary", binary, "--major", "2"}, strings.NewReader(""), &out, &errb)
	if code != 0 {
		t.Fatalf("exit=%d stderr=%s", code, errb.String())
	}
	js, err := os.ReadFile(filepath.Join(dir, "guardrail", "index.js"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(js), wantDeclaration) {
		t.Fatalf("deployed V2 plugin does not pin the exact binary path %q:\n%s", binary, js)
	}
	if strings.Contains(string(js), "process.env.GUARDRAIL_BIN") {
		t.Error("plugin still resolves its enforcer from the environment")
	}
}
