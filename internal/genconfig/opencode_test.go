package genconfig

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestOpencodePluginSourceRetainsDeploymentPlaceholder(t *testing.T) {
	if !bytes.Contains(OpencodePluginJS, []byte("__GUARDRAIL_BIN__")) {
		t.Fatal("embedded OpenCode plugin source is missing the deployment placeholder")
	}
}

func TestOpencodePluginRequiresExplicitAllow(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node is required to exercise the embedded OpenCode plugin")
	}

	dir := t.TempDir()
	binary := filepath.Join(dir, "guardrail")
	fakeGuardrail := `#!/bin/sh
IFS= read -r _ || :
case "$GUARDRAIL_TEST_RESPONSE" in
	allow) printf '%s' '{"decision":"allow","reason":"accepted"}' ;;
	ask) printf '%s' '{"decision":"ask","reason":"confirm it"}' ;;
	deny) printf '%s' '{"decision":"deny","reason":"blocked it"}' ;;
	unknown) printf '%s' '{"decision":"unexpected","reason":"bad verdict"}' ;;
	empty) ;;
	malformed) printf '%s' 'not-json' ;;
esac
`
	if err := os.WriteFile(binary, []byte(fakeGuardrail), 0o755); err != nil {
		t.Fatal(err)
	}
	pluginPath := filepath.Join(dir, "guardrail.mjs")
	if err := os.WriteFile(pluginPath, OpencodePluginFor(binary), 0o644); err != nil {
		t.Fatal(err)
	}

	runner := `
import { pathToFileURL } from "node:url";
const loaded = await import(pathToFileURL(process.argv[1]).href);
const plugin = await loaded.default({ directory: process.cwd() });
try {
	await plugin["tool.execute.before"](
		{ tool: "bash", sessionID: "test-session" },
		{ args: { command: "true" } },
	);
	process.stdout.write("allowed");
} catch (error) {
	process.stderr.write(error instanceof Error ? error.message : String(error));
	process.exit(42);
}
`
	tests := []struct {
		response string
		wantErr  string
	}{
		{response: "allow"},
		{response: "ask", wantErr: "needs confirmation - confirm it"},
		{response: "deny", wantErr: "guardrail: blocked it"},
		{response: "unknown", wantErr: "guardrail: bad verdict"},
		{response: "empty", wantErr: "guardrail: no decision returned"},
		{response: "malformed", wantErr: "guardrail: unparseable response"},
	}
	for _, tt := range tests {
		t.Run(tt.response, func(t *testing.T) {
			cmd := exec.Command(node, "--input-type=module", "--eval", runner, pluginPath)
			cmd.Env = append(os.Environ(), "GUARDRAIL_TEST_RESPONSE="+tt.response)
			output, err := cmd.CombinedOutput()
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("explicit allow was blocked: %v\n%s", err, output)
				}
				if string(output) != "allowed" {
					t.Fatalf("stdout = %q, want allowed", output)
				}
				return
			}
			if err == nil {
				t.Fatalf("%s response was allowed", tt.response)
			}
			if !strings.Contains(string(output), tt.wantErr) {
				t.Fatalf("error = %q, want it to contain %q", output, tt.wantErr)
			}
		})
	}
}

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

func TestOpencodeConfigProtectsGuardrailOwnMachinery(t *testing.T) {
	frag := OpencodeConfig(secretPol(), "/x/guardrail.js")
	edit := frag["permission"].(map[string]any)["edit"].(map[string]string)
	want := []string{
		"guardrail.toml",
		"**/guardrail.toml",
		".guardrail/**",
		"opencode.json",
		"**/opencode.json",
		".agents/hooks.json",
		"**/.gemini/config/hooks.json",
		"**/.local/bin/guardrail",
		"**/bin/guardrail",
	}
	for _, path := range want {
		if edit[path] != "deny" {
			t.Errorf("OpenCode edit permission for %q = %q, want deny", path, edit[path])
		}
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
