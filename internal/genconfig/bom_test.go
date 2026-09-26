package genconfig

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

var utf8BOM = []byte{0xEF, 0xBB, 0xBF}

// Windows editors (Notepad before 1903, PowerShell 5 Out-File -Encoding
// utf8) prepend a UTF-8 BOM. encoding/json rejects it, so an operator who
// once opened settings.json in Notepad would lock plane enable out with
// "is not a JSON object; refusing to overwrite". The merge must read
// through a BOM and write without one.
func TestMergeIntoReadsBOMPrefixedSettingsAndWritesWithoutBOM(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settings.json")
	body := append(append([]byte{}, utf8BOM...), []byte(`{"permissions":{"allow":["Bash(ls:*)"]},"theme":"dark"}`)...)
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := MergePlaneInto(path, "claude", legacyClaudeFragment(secretPol(), "guardrail")); err != nil {
		t.Fatalf("merge refused a BOM-prefixed file: %v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.HasPrefix(raw, utf8BOM) {
		t.Fatal("merge wrote the BOM back; JSON is BOM-free by specification")
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("merged file is not JSON: %v", err)
	}
	if doc["theme"] != "dark" {
		t.Fatalf("user data lost across the BOM read: %v", doc)
	}
	if _, ok := doc["hooks"].(map[string]any); !ok {
		t.Fatalf("hooks not merged: %v", doc)
	}
}

func TestReadJSONObjectStripsBOMAndRejectsNonObjects(t *testing.T) {
	dir := t.TempDir()
	write := func(name string, body []byte) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, body, 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	doc, err := ReadJSONObject(write("bom.json", append(append([]byte{}, utf8BOM...), []byte(`{"a":1}`)...)))
	if err != nil || doc["a"] != float64(1) {
		t.Fatalf("bom: %v %v", doc, err)
	}
	doc, err = ReadJSONObject(write("plain.json", []byte(`{"a":2}`)))
	if err != nil || doc["a"] != float64(2) {
		t.Fatalf("plain: %v %v", doc, err)
	}
	if _, err := ReadJSONObject(write("array.json", []byte(`[1]`))); err == nil {
		t.Fatal("array accepted as an object")
	}
	if _, err := ReadJSONObject(write("null.json", []byte(`null`))); err == nil {
		t.Fatal("null accepted as an object")
	}
	if _, err := ReadJSONObject(filepath.Join(dir, "missing.json")); !os.IsNotExist(err) {
		t.Fatalf("missing file must surface os.IsNotExist, got %v", err)
	}
}
