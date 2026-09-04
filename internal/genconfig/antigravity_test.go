package genconfig

import (
	"path/filepath"
	"testing"
)

func TestAntigravityConfigShape(t *testing.T) {
	frag := AntigravityConfig("/usr/local/bin/guardrail")
	g, ok := frag["guardrail"].(map[string]any)
	if !ok {
		t.Fatalf("want a named \"guardrail\" wrapper, got %T (%v)", frag["guardrail"], frag["guardrail"])
	}
	if g["enabled"] != true {
		t.Errorf("guardrail.enabled = %v, want true", g["enabled"])
	}

	pre := g["PreToolUse"].([]any)[0].(map[string]any)
	if pre["id"] != "guardrail-antigravity-pre" {
		t.Errorf("pre id = %v", pre["id"])
	}
	if pre["matcher"] != "run_command|view_file|write_to_file|replace_file_content|multi_replace_file_content" {
		t.Errorf("pre matcher = %v", pre["matcher"])
	}
	preHook := pre["hooks"].([]any)[0].(map[string]any)
	if preHook["command"] != "/usr/local/bin/guardrail hook antigravity pre" {
		t.Errorf("pre command = %q", preHook["command"])
	}
	if preHook["timeout"] != 15 {
		t.Errorf("pre timeout = %v, want 15", preHook["timeout"])
	}

	post := g["PostToolUse"].([]any)[0].(map[string]any)
	if post["id"] != "guardrail-antigravity-post" {
		t.Errorf("post id = %v", post["id"])
	}
	if post["matcher"] != "write_to_file|replace_file_content|multi_replace_file_content" {
		t.Errorf("post matcher = %v", post["matcher"])
	}
	postHook := post["hooks"].([]any)[0].(map[string]any)
	if postHook["command"] != "/usr/local/bin/guardrail hook antigravity post" {
		t.Errorf("post command = %q", postHook["command"])
	}
	if postHook["timeout"] != 120 {
		t.Errorf("post timeout = %v, want 120", postHook["timeout"])
	}

	if _, ok := frag["permissions"]; ok {
		t.Error("AntigravityConfig should not emit a permissions key — no declarative layer exists for this plane")
	}
}

func TestMergeAntigravityRebindsBinaryNoFork(t *testing.T) {
	p := filepath.Join(t.TempDir(), "hooks.json")
	MergeInto(p, AntigravityConfig("/old/guardrail"))
	MergeInto(p, AntigravityConfig("/new/guardrail"))
	m := readJSON(t, p)
	g := m["guardrail"].(map[string]any)
	if g["enabled"] != true {
		t.Fatalf("guardrail.enabled = %v, want true to survive a rebind", g["enabled"])
	}
	pre := g["PreToolUse"].([]any)
	if len(pre) != 1 {
		t.Fatalf("want exactly 1 owned PreToolUse group after a rebind, got %d: %v", len(pre), pre)
	}
	cmd := pre[0].(map[string]any)["hooks"].([]any)[0].(map[string]any)["command"].(string)
	if cmd != "/new/guardrail hook antigravity pre" {
		t.Fatalf("command = %q, want the new binary path", cmd)
	}
}
