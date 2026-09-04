package genconfig

import (
	"encoding/json"
	"os"
	"path/filepath"
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
