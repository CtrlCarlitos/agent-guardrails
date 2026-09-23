package genconfig

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
	"github.com/CtrlCarlitos/agent-guardrails/internal/testenv"
)

// The ownership manifest (#278 findings, ADR-0028 phase-1 precondition).
//
// Permission entries are bare strings sharing an array with the operator's
// own, so nothing in the file says which are guardrail's. The consequences are
// the three tests below, and they are the manifest's entire reason to exist.

func manifestEnv(t *testing.T) {
	t.Helper()
	testenv.SetState(t, t.TempDir())
	testenv.SetConfig(t, t.TempDir())
}

func writeJSON(t *testing.T, path string, doc map[string]any) {
	t.Helper()
	raw, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(raw, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
}

func stringsAt(t *testing.T, doc map[string]any, keys ...string) []string {
	t.Helper()
	var cur any = doc
	for _, k := range keys {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil
		}
		cur = m[k]
	}
	list, ok := cur.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(list))
	for _, v := range list {
		if s, ok := v.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

// RED 1 — the original complaint.
//
// `plane disable claude` handles `hooks` only, so all 243 generated permission
// entries survive the operator explicitly disabling the integration. Guardrail
// wrote them into a file that belongs to the operator, and then had no way to
// take them back out.
func TestDisableClaudeRemovesTheFloorAndKeepsOperatorEntries(t *testing.T) {
	manifestEnv(t)
	base, err := policy.LoadBase()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "settings.json")
	writeJSON(t, path, map[string]any{
		"permissions": map[string]any{
			"allow": []any{"Bash(graft:*)", "Bash(npx graft:*)"},
			"deny":  []any{"Bash(my-own-rule *)"},
		},
		"statusLine": map[string]any{"type": "command", "command": "mine"},
	})
	if err := MergePlaneInto(path, "claude", ClaudeConfig(base, "guardrail")); err != nil {
		t.Fatal(err)
	}
	if got := len(stringsAt(t, readJSON(t, path), "permissions", "deny")); got < 100 {
		t.Fatalf("the floor did not land: %d deny entries", got)
	}

	if err := RemovePlaneFrom(path, "claude"); err != nil {
		t.Fatal(err)
	}
	after := readJSON(t, path)

	deny := stringsAt(t, after, "permissions", "deny")
	for _, g := range deny {
		if g != "Bash(my-own-rule *)" {
			t.Errorf("guardrail entry %q survived disable; the operator disabled the integration and it is still writing policy into their file", g)
		}
	}
	if !slices.Contains(deny, "Bash(my-own-rule *)") {
		t.Error("the operator's own deny entry was removed")
	}
	allow := stringsAt(t, after, "permissions", "allow")
	for _, want := range []string{"Bash(graft:*)", "Bash(npx graft:*)"} {
		if !slices.Contains(allow, want) {
			t.Errorf("the operator's allow entry %q was removed", want)
		}
	}
	if _, ok := after["statusLine"]; !ok {
		t.Error("unrelated operator settings were removed")
	}
}

// RED 2 — removal by demolition.
//
// `plane disable opencode` deletes the entire `permission` block, operator
// entries included, because nothing distinguishes whose entries are whose.
func TestDisableOpencodeRemovesOnlyGuardrailPermissionEntries(t *testing.T) {
	manifestEnv(t)
	base, err := policy.LoadBase()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "opencode.json")
	writeJSON(t, path, map[string]any{
		"$schema": "https://opencode.ai/config.json",
		"permission": map[string]any{
			"bash": map[string]any{"my-own-tool *": "ask"},
		},
		"mcp": map[string]any{"serena": map[string]any{"type": "local"}},
	})
	if err := MergePlaneInto(path, "opencode", OpencodeConfig(base, filepath.Join(dir, "guardrail.js"))); err != nil {
		t.Fatal(err)
	}
	if err := RemovePlaneFrom(path, "opencode"); err != nil {
		t.Fatal(err)
	}
	after := readJSON(t, path)

	perm, ok := after["permission"].(map[string]any)
	if !ok {
		t.Fatal("the whole permission block was deleted; the operator's own entries went with guardrail's")
	}
	bash, _ := perm["bash"].(map[string]any)
	if got, ok := bash["my-own-tool *"]; !ok || got != "ask" {
		t.Errorf("the operator's own permission entry did not survive: %v", bash)
	}
	if _, ok := bash["rm -rf /"]; ok {
		t.Error("a guardrail permission entry survived disable")
	}
	if _, ok := after["mcp"]; !ok {
		t.Error("unrelated operator configuration was removed")
	}
}

// RED 3 — live user-data destruction, today, independent of the reset.
//
// `RemovePlaneFrom` deletes the whole `plugin` array. The merge path already
// knows how to pick out guardrail's entry precisely
// (absorbGuardrailPluginEntries, basename-matched and separator-normalized);
// the removal path simply never used that knowledge. On a real machine the
// array also holds the operator's own plugins, and disabling guardrail
// unregisters them.
func TestDisableOpencodeKeepsOperatorPlugins(t *testing.T) {
	manifestEnv(t)
	base, err := policy.LoadBase()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "opencode.json")
	writeJSON(t, path, map[string]any{
		"plugin": []any{"~/.config/opencode/node_modules/superpowers"},
	})
	if err := MergePlaneInto(path, "opencode", OpencodeConfig(base, filepath.Join(dir, "guardrail.js"))); err != nil {
		t.Fatal(err)
	}
	if got := stringsAt(t, readJSON(t, path), "plugin"); len(got) != 2 {
		t.Fatalf("setup: plugin array is %v, want the operator's plus guardrail's", got)
	}

	if err := RemovePlaneFrom(path, "opencode"); err != nil {
		t.Fatal(err)
	}
	plugins := stringsAt(t, readJSON(t, path), "plugin")
	if !slices.Contains(plugins, "~/.config/opencode/node_modules/superpowers") {
		t.Errorf("disabling guardrail unregistered the operator's plugins: %v", plugins)
	}
	for _, p := range plugins {
		if filepath.Base(p) == "guardrail.js" {
			t.Errorf("guardrail's own plugin entry survived disable: %v", plugins)
		}
	}
}
