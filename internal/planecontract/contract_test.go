package planecontract

import (
	"testing"

	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
)

func TestClaudeInventoryClassifiesCapabilityBoundary(t *testing.T) {
	want := map[string]policy.Capability{
		"Bash":         policy.CapabilityCommand,
		"PowerShell":   policy.CapabilityCommand,
		"Read":         policy.CapabilityReadDiscovery,
		"Glob":         policy.CapabilityReadDiscovery,
		"Grep":         policy.CapabilityReadDiscovery,
		"LSP":          policy.CapabilityReadDiscovery,
		"Edit":         policy.CapabilityMutation,
		"Write":        policy.CapabilityMutation,
		"MultiEdit":    policy.CapabilityMutation,
		"NotebookEdit": policy.CapabilityMutation,
		"WebFetch":     policy.CapabilityWebFetch,
		"WebSearch":    policy.CapabilityWebSearch,
		"Agent":        policy.CapabilityDelegation,
	}
	for tool, capability := range want {
		spec, ok := ClaudeTool(tool)
		if !ok || spec.Capability != capability {
			t.Fatalf("%s = %#v, %v; want %v", tool, spec, ok, capability)
		}
	}

	if spec, ok := ClaudeTool("mcp__server__unsafe"); !ok || spec.Capability != policy.CapabilityDeny {
		t.Fatalf("MCP tool = %#v, %v; want deny", spec, ok)
	}
}

func TestClaudePreHookMatcherCoversEveryInventoryTool(t *testing.T) {
	if matcher := ClaudePreHookMatcher(); matcher != "*" {
		t.Fatalf("matcher = %q, want catch-all", matcher)
	}
	for _, spec := range RegisteredTools("claude") {
		if !ClaudePreMatcherMatches(spec.NativeTool) {
			t.Fatal(spec.NativeTool)
		}
	}
}

func TestOpenCodeAndAntigravityInventoriesClassifyCapabilityBoundary(t *testing.T) {
	for _, tt := range []struct {
		plane string
		tool  string
		want  policy.Capability
	}{
		{"opencode", "apply_patch", policy.CapabilityMutation},
		{"opencode", "grep", policy.CapabilityReadDiscovery},
		{"opencode", "glob", policy.CapabilityReadDiscovery},
		{"opencode", "webfetch", policy.CapabilityWebFetch},
		{"antigravity", "list_dir", policy.CapabilityReadDiscovery},
		{"antigravity", "grep_search", policy.CapabilityReadDiscovery},
		{"antigravity", "read_url_content", policy.CapabilityWebFetch},
		{"antigravity", "search_web", policy.CapabilityWebSearch},
	} {
		var spec ToolSpec
		var ok bool
		switch tt.plane {
		case "opencode":
			spec, ok = OpencodeTool(tt.tool)
		case "antigravity":
			spec, ok = AntigravityTool(tt.tool)
		}
		if !ok || spec.Capability != tt.want {
			t.Fatalf("%s %s = %#v, %v; want %v", tt.plane, tt.tool, spec, ok, tt.want)
		}
	}
	for _, tool := range []string{"custom", "mcp__server__unsafe"} {
		spec, ok := OpencodeTool(tool)
		if !ok || spec.Capability != policy.CapabilityDeny {
			t.Fatalf("OpenCode %s = %#v, %v; want deny", tool, spec, ok)
		}
	}
}

func TestAntigravityPreHookMatcherCoversEveryInventoryTool(t *testing.T) {
	if matcher := AntigravityPreHookMatcher(); matcher != "*" {
		t.Fatalf("matcher = %q, want catch-all", matcher)
	}
	for _, spec := range RegisteredTools("antigravity") {
		if !AntigravityPreMatcherMatches(spec.NativeTool) {
			t.Fatal(spec.NativeTool)
		}
	}
}
