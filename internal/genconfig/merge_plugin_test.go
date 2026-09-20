package genconfig

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestMergeOpencodeReplacesPriorGuardrailPluginEntries pins #145: the plugin
// file legitimately deploys to more than one location (state root, config
// dir, repository .guardrail/), and opencode loads the first-listed entry —
// a merge must replace prior guardrail deployments instead of appending, so
// exactly one guardrail entry remains and a stale first-listed copy can no
// longer silently win over the fresh deploy.
func TestMergeOpencodeReplacesPriorGuardrailPluginEntries(t *testing.T) {
	p := filepath.Join(t.TempDir(), "opencode.json")
	os.WriteFile(p, []byte(`{
		"plugin": ["C:\\state\\guardrail.js", "superpowers@git+https://github.com/obra/superpowers.git"]
	}`), 0o644)

	frag := OpencodeConfig(secretPol(), "/x/guardrail.js")
	if err := MergeInto(p, frag); err != nil {
		t.Fatal(err)
	}

	raw, _ := os.ReadFile(p)
	var m map[string]any
	json.Unmarshal(raw, &m)
	plugins, _ := m["plugin"].([]any)
	guardrailEntries := 0
	for _, entry := range plugins {
		s, _ := entry.(string)
		if strings.HasSuffix(filepath.ToSlash(s), "guardrail.js") {
			guardrailEntries++
		}
	}
	if guardrailEntries != 1 {
		t.Fatalf("want exactly one guardrail plugin entry, got %d in %v", guardrailEntries, plugins)
	}
	found := false
	for _, entry := range plugins {
		if s, _ := entry.(string); s == "/x/guardrail.js" {
			found = true
		}
	}
	if !found {
		t.Fatalf("current guardrail plugin missing: %v", plugins)
	}
	if len(plugins) != 2 {
		t.Fatalf("foreign plugin entries must be preserved: %v", plugins)
	}
}

// TestMergeOpencodeKeepsSingleGuardrailPluginEntryIdempotent pins the steady
// state: merging the same plugin path twice leaves one guardrail entry.
func TestMergeOpencodeKeepsSingleGuardrailPluginEntryIdempotent(t *testing.T) {
	p := filepath.Join(t.TempDir(), "opencode.json")
	os.WriteFile(p, []byte(`{"plugin": ["/x/guardrail.js"]}`), 0o644)
	if err := MergeInto(p, OpencodeConfig(secretPol(), "/x/guardrail.js")); err != nil {
		t.Fatal(err)
	}
	if err := MergeInto(p, OpencodeConfig(secretPol(), "/x/guardrail.js")); err != nil {
		t.Fatal(err)
	}

	raw, _ := os.ReadFile(p)
	var m map[string]any
	json.Unmarshal(raw, &m)
	plugins, _ := m["plugin"].([]any)
	if len(plugins) != 1 || plugins[0] != "/x/guardrail.js" {
		t.Fatalf("steady state must hold exactly the current entry: %v", plugins)
	}
}
