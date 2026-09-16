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
