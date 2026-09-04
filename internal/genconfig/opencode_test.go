package genconfig

import "testing"

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
