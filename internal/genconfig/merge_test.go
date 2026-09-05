package genconfig

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func readJSON(t *testing.T, p string) map[string]any {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("not json: %v\n%s", err, b)
	}
	return m
}

func TestMergeIntoEmpty(t *testing.T) {
	p := filepath.Join(t.TempDir(), "settings.json")
	frag := Fragment{"permissions": map[string]any{"deny": []string{"Bash(rm -rf *)"}}}
	if err := MergeInto(p, frag); err != nil {
		t.Fatal(err)
	}
	m := readJSON(t, p)
	deny := m["permissions"].(map[string]any)["deny"].([]any)
	if len(deny) != 1 || deny[0] != "Bash(rm -rf *)" {
		t.Fatalf("deny = %v", deny)
	}
}

func TestMergeIntoPreservesUnrelated(t *testing.T) {
	p := filepath.Join(t.TempDir(), "settings.json")
	os.WriteFile(p, []byte(`{"theme":"dark","permissions":{"deny":["Bash(foo)"],"allow":["Bash(ls)"]}}`), 0o644)
	frag := Fragment{"permissions": map[string]any{"deny": []string{"Bash(rm -rf *)"}}}
	if err := MergeInto(p, frag); err != nil {
		t.Fatal(err)
	}
	m := readJSON(t, p)
	if m["theme"] != "dark" {
		t.Error("theme lost")
	}
	perms := m["permissions"].(map[string]any)
	if _, ok := perms["allow"]; !ok {
		t.Error("permissions.allow lost")
	}
	deny := perms["deny"].([]any)
	if len(deny) != 2 {
		t.Fatalf("deny = %v, want the original + the new one", deny)
	}
}

func TestMergeIntoIdempotent(t *testing.T) {
	p := filepath.Join(t.TempDir(), "settings.json")
	frag := Fragment{"permissions": map[string]any{"deny": []string{"Bash(rm -rf *)", "Bash(dd *)"}}}
	if err := MergeInto(p, frag); err != nil {
		t.Fatal(err)
	}
	first, _ := os.ReadFile(p)
	if err := MergeInto(p, frag); err != nil {
		t.Fatal(err)
	}
	second, _ := os.ReadFile(p)
	if string(first) != string(second) {
		t.Fatalf("not idempotent:\n--- first ---\n%s\n--- second ---\n%s", first, second)
	}
}

func TestMergeIntoRejectsNonObject(t *testing.T) {
	p := filepath.Join(t.TempDir(), "settings.json")
	os.WriteFile(p, []byte(`["not","an","object"]`), 0o644)
	if err := MergeInto(p, Fragment{"x": 1}); err == nil {
		t.Fatal("want error, got nil (would have clobbered)")
	}
}

func TestMergeIntoRejectsNullObject(t *testing.T) {
	p := filepath.Join(t.TempDir(), "settings.json")
	os.WriteFile(p, []byte(`null`), 0o644)
	if err := MergeInto(p, Fragment{"x": 1}); err == nil {
		t.Fatal("want error, got nil (would have clobbered)")
	}
	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != "null" {
		t.Fatalf("file was modified: %q", raw)
	}
}

func TestMergeIntoRejectsDirectory(t *testing.T) {
	dir := t.TempDir()
	if err := MergeInto(dir, Fragment{"x": 1}); err == nil {
		t.Fatal("want error for a directory path, got nil")
	}
}

func hookFrag(binary string) Fragment {
	return Fragment{"hooks": map[string]any{
		"PreToolUse": []any{
			map[string]any{
				"id": "guardrail-claude-pre", "matcher": "Bash",
				"hooks": []any{map[string]any{"type": "command", "command": binary + " hook claude"}},
			},
		},
	}}
}

func preGroups(t *testing.T, p string) []any {
	m := readJSON(t, p)
	return m["hooks"].(map[string]any)["PreToolUse"].([]any)
}

func TestMergeHooksReplacesOwnedOnRerun(t *testing.T) {
	p := filepath.Join(t.TempDir(), "settings.json")
	if err := MergeInto(p, hookFrag("/a/guardrail")); err != nil {
		t.Fatal(err)
	}
	if err := MergeInto(p, hookFrag("/a/guardrail")); err != nil {
		t.Fatal(err)
	}
	g := preGroups(t, p)
	if len(g) != 1 {
		t.Fatalf("want exactly 1 PreToolUse group after 2 identical merges, got %d: %v", len(g), g)
	}
}

func TestMergeHooksRebindsBinary(t *testing.T) {
	p := filepath.Join(t.TempDir(), "settings.json")
	MergeInto(p, hookFrag("/old/guardrail"))
	if err := MergeInto(p, hookFrag("/new/guardrail")); err != nil {
		t.Fatal(err)
	}
	g := preGroups(t, p)
	if len(g) != 1 {
		t.Fatalf("want 1 owned group, got %d", len(g))
	}
	cmd := g[0].(map[string]any)["hooks"].([]any)[0].(map[string]any)["command"].(string)
	if cmd != "/new/guardrail hook claude" {
		t.Fatalf("command = %q, want the new binary path", cmd)
	}
}

func TestMergeHooksPreservesUserGroups(t *testing.T) {
	p := filepath.Join(t.TempDir(), "settings.json")
	os.WriteFile(p, []byte(`{"hooks":{"PreToolUse":[{"matcher":"Task","hooks":[{"type":"command","command":"my-own-hook"}]}]}}`), 0o644)
	if err := MergeInto(p, hookFrag("/x/guardrail")); err != nil {
		t.Fatal(err)
	}
	g := preGroups(t, p)
	if len(g) != 2 {
		t.Fatalf("want user group + owned group = 2, got %d: %v", len(g), g)
	}
	var sawUser, sawOwned bool
	for _, grp := range g {
		m := grp.(map[string]any)
		if m["matcher"] == "Task" {
			sawUser = true
		}
		if m["id"] == "guardrail-claude-pre" {
			sawOwned = true
		}
	}
	if !sawUser || !sawOwned {
		t.Fatalf("user=%v owned=%v", sawUser, sawOwned)
	}
	// a second merge must not add a third group
	MergeInto(p, hookFrag("/x/guardrail"))
	if g := preGroups(t, p); len(g) != 2 {
		t.Fatalf("second merge changed group count to %d", len(g))
	}
}

func TestPermissionsStillUnionAppend(t *testing.T) {
	p := filepath.Join(t.TempDir(), "settings.json")
	os.WriteFile(p, []byte(`{"permissions":{"deny":["Bash(foo)"]}}`), 0o644)
	MergeInto(p, Fragment{"permissions": map[string]any{"deny": []string{"Bash(rm -rf *)"}}})
	deny := readJSON(t, p)["permissions"].(map[string]any)["deny"].([]any)
	if len(deny) != 2 {
		t.Fatalf("deny = %v, want the user entry kept + the new one", deny)
	}
}

func TestMergeIntoOpencodePermissionCollision(t *testing.T) {
	p := filepath.Join(t.TempDir(), "opencode.json")
	existing := `{
		"theme": "dark",
		"permission": {
			"bash": {
				"*": "deny",
				"chmod -R *": "deny",
				"rm -rf *": "allow",
				"safe *": "allow",
				"zzz-custom": {"mode": "audit"}
			},
			"read": {"**/.ssh/**": "ask"},
			"edit": {
				".env.example": "ask",
				".github/workflows/**": "deny"
			},
			"external_directory": {"~/projects/**": "allow"}
		}
	}`
	if err := os.WriteFile(p, []byte(existing), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := MergeInto(p, OpencodeConfig(secretPol(), "/x/guardrail.js")); err != nil {
		t.Fatal(err)
	}

	root := readJSON(t, p)
	if root["theme"] != "dark" {
		t.Fatal("unrelated top-level setting was not preserved")
	}
	permission := root["permission"].(map[string]any)
	bash := permission["bash"].(map[string]any)
	for key, want := range map[string]string{
		"*":          "deny",
		"chmod -R *": "deny",
		"rm -rf *":   "deny",
	} {
		if got := bash[key]; got != want {
			t.Errorf("permission.bash[%q] = %v, want %q", key, got, want)
		}
	}
	if got, want := bash["zzz-custom"], map[string]any{"mode": "audit"}; !reflect.DeepEqual(got, want) {
		t.Errorf("unknown permission value = %#v, want %#v", got, want)
	}
	if got := permission["read"].(map[string]any)["**/.ssh/**"]; got != "deny" {
		t.Errorf("generated deny did not tighten retained ask: %v", got)
	}
	edit := permission["edit"].(map[string]any)
	if got := edit[".env.example"]; got != "ask" {
		t.Errorf("retained ask did not tighten generated allow: %v", got)
	}
	if got := edit[".github/workflows/**"]; got != "deny" {
		t.Errorf("retained deny did not tighten generated ask: %v", got)
	}
	if got, want := permission["external_directory"], map[string]any{"~/projects/**": "allow"}; !reflect.DeepEqual(got, want) {
		t.Errorf("unrelated permission category = %#v, want %#v", got, want)
	}

	rules := readOpencodePermissionRules(t, p, "bash")
	if rules[0].pattern != "zzz-custom" {
		t.Errorf("first bash rule = %q, want unknown-valued zzz-custom rule", rules[0].pattern)
	}
}

func TestMergeIntoOpencodePermissionIdempotent(t *testing.T) {
	p := filepath.Join(t.TempDir(), "opencode.json")
	existing := []byte(`{"permission":{"edit":{"/**":"allow","zzz-custom":{"mode":"audit"},"**/workflows/**":"deny"}}}`)
	if err := os.WriteFile(p, existing, 0o644); err != nil {
		t.Fatal(err)
	}
	frag := OpencodeConfig(secretPol(), "/x/guardrail.js")
	if err := MergeInto(p, frag); err != nil {
		t.Fatal(err)
	}
	first, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := MergeInto(p, frag); err != nil {
		t.Fatal(err)
	}
	second, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) {
		t.Fatalf("OpenCode merge is not byte-idempotent:\n--- first ---\n%s\n--- second ---\n%s", first, second)
	}
}
