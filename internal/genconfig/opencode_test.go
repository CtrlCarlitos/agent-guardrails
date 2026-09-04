package genconfig

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestOpencodeConfigBashPermissions(t *testing.T) {
	frag := OpencodeConfig(secretPol(), "/x/guardrail.js")
	bash := frag["permission"].(map[string]any)["bash"].(map[string]string)
	if bash["*"] != "allow" {
		t.Errorf(`bash["*"] = %q, want "allow"`, bash["*"])
	}
	if bash["rm -rf *"] != "deny" {
		t.Errorf(`bash["rm -rf *"] = %q, want "deny"`, bash["rm -rf *"])
	}
	if bash["chmod -R *"] != "ask" {
		t.Errorf(`bash["chmod -R *"] = %q, want "ask"`, bash["chmod -R *"])
	}
}

func TestOpencodeConfigReadEditPermissions(t *testing.T) {
	frag := OpencodeConfig(secretPol(), "/x/guardrail.js")
	read := frag["permission"].(map[string]any)["read"].(map[string]string)
	edit := frag["permission"].(map[string]any)["edit"].(map[string]string)
	if read["**/.ssh/**"] != "deny" {
		t.Errorf(`read["**/.ssh/**"] = %q`, read["**/.ssh/**"])
	}
	if read["**/.env.example"] != "allow" {
		t.Errorf(`read["**/.env.example"] = %q, want allow`, read["**/.env.example"])
	}
	if edit[".claude/**"] != "deny" {
		t.Errorf(`edit[".claude/**"] = %q, want deny`, edit[".claude/**"])
	}
	if edit[".github/workflows/**"] != "ask" {
		t.Errorf(`edit[".github/workflows/**"] = %q, want ask`, edit[".github/workflows/**"])
	}
}

func TestOpencodeConfigPluginRegistered(t *testing.T) {
	frag := OpencodeConfig(secretPol(), "/x/guardrail.js")
	plugins := frag["plugin"].([]string)
	if len(plugins) != 1 || plugins[0] != "/x/guardrail.js" {
		t.Errorf("plugin = %v", plugins)
	}
}

func TestMergeOpencodePreservesExistingProjectConfig(t *testing.T) {
	p := filepath.Join(t.TempDir(), "opencode.json")
	os.WriteFile(p, []byte(`{
		"plugin": ["superpowers@git+https://github.com/obra/superpowers.git"],
		"permission": {
			"bash": {"*": "allow", "git commit *": "ask"},
			"external_directory": {"~/projects/**": "allow"}
		}
	}`), 0o644)

	frag := OpencodeConfig(secretPol(), "/x/guardrail.js")
	if err := MergeInto(p, frag); err != nil {
		t.Fatal(err)
	}

	raw, _ := os.ReadFile(p)
	var m map[string]any
	json.Unmarshal(raw, &m)
	perm := m["permission"].(map[string]any)

	bash := perm["bash"].(map[string]any)
	if bash["git commit *"] != "ask" {
		t.Errorf("existing project rule lost: %v", bash["git commit *"])
	}
	if bash["rm -rf *"] != "deny" {
		t.Errorf("guardrail rule not added: %v", bash["rm -rf *"])
	}
	if _, ok := perm["external_directory"]; !ok {
		t.Error("external_directory block lost")
	}

	plugins := m["plugin"].([]any)
	if len(plugins) != 2 {
		t.Fatalf("want superpowers + guardrail = 2 plugin entries, got %v", plugins)
	}
}
