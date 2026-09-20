package planecontract

import (
	"slices"
	"testing"

	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
)

// TestDegradedAllowClassification pins the B+ contract: only direct
// human-communication tools whose SafeControl classification is
// argument-independent may be allowed locally by an adapter while the
// engine is unreachable. skill loads instructions whose effect outlives the
// outage; manage_task is argument-dependent; schedule is External;
// read/discovery and delegation never qualify.
func TestDegradedAllowClassification(t *testing.T) {
	type check struct {
		plane string
		tool  string
		want  bool
	}
	checks := []check{
		{"opencode", "question", true},
		{"opencode", "QUESTION", true},
		{"opencode", "todowrite", true},
		{"opencode", "skill", false},
		{"opencode", "read", false},
		{"opencode", "bash", false},
		{"opencode", "task", false},
		{"claude", "AskUserQuestion", true},
		{"claude", "Bash", false},
		{"claude", "Read", false},
		{"antigravity", "ask_question", true},
		{"antigravity", "manage_task", false},
		{"antigravity", "schedule", false},
		{"antigravity", "list_permissions", false},
		{"codex", "shell", false},
		{"unknown-plane", "question", false},
	}
	for _, c := range checks {
		if got := DegradedAllow(c.plane, c.tool); got != c.want {
			t.Fatalf("DegradedAllow(%s, %s) = %v, want %v", c.plane, c.tool, got, c.want)
		}
	}

	// Every degraded-allowable tool must be SafeControl in its contract.
	lookups := map[string]func(string) (ToolSpec, bool){
		"opencode":    OpencodeTool,
		"claude":      ClaudeTool,
		"antigravity": AntigravityTool,
	}
	for plane, tools := range map[string][]string{
		"opencode":    {"question", "todowrite"},
		"claude":      {"AskUserQuestion"},
		"antigravity": {"ask_question"},
	} {
		for _, tool := range tools {
			spec, ok := lookups[plane](tool)
			if !ok {
				t.Fatalf("%s/%s not in contract", plane, tool)
			}
			if spec.Capability != policy.CapabilitySafeControl {
				t.Fatalf("%s/%s is degraded-allowable but not SafeControl", plane, tool)
			}
		}
	}
}

// TestOpencodeDegradedAllowToolsIsSortedAndComplete pins the codegen
// surface: gen-config bakes exactly this list into the plugin artifact.
func TestOpencodeDegradedAllowToolsIsSortedAndComplete(t *testing.T) {
	got := OpencodeDegradedAllowTools()
	want := []string{"question", "todowrite"}
	if !slices.Equal(got, want) {
		t.Fatalf("OpencodeDegradedAllowTools() = %v, want %v", got, want)
	}
}

// TestFloorFallbackClassification pins the ADR-0022 capability table's
// middle rows: ReadDiscovery and Mutation tools proceed under the floor in
// degraded mode; commands, egress, delegation, unknown, MCP, and the
// communication valve's own set are separate concerns.
func TestFloorFallbackClassification(t *testing.T) {
	eligible := []string{"apply_patch", "edit", "glob", "grep", "lsp", "read", "write"}
	for _, tool := range eligible {
		if !FloorFallback("opencode", tool) {
			t.Fatalf("FloorFallback(opencode, %s) = false, want true", tool)
		}
	}
	for _, tool := range []string{"bash", "webfetch", "websearch", "task", "custom", "mcp_foo", "question", "todowrite", "skill"} {
		if FloorFallback("opencode", tool) {
			t.Fatalf("FloorFallback(opencode, %s) = true, want false", tool)
		}
	}
	if FloorFallback("claude", "Read") || FloorFallback("antigravity", "view_file") || FloorFallback("codex", "shell") {
		t.Fatal("floor fallback is opencode-only until other planes own an adapter shim (ADR-0022 per-plane applicability)")
	}
}

// TestOpencodeFloorFallbackToolsIsSortedAndComplete pins the codegen surface.
func TestOpencodeFloorFallbackToolsIsSortedAndComplete(t *testing.T) {
	want := []string{"apply_patch", "edit", "glob", "grep", "lsp", "read", "write"}
	if got := OpencodeFloorFallbackTools(); !slices.Equal(got, want) {
		t.Fatalf("OpencodeFloorFallbackTools() = %v, want %v", got, want)
	}
}
