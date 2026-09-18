package planecontract

import (
	"testing"

	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
)

func TestMatchMCPToolResolvesEveryPlaneNaming(t *testing.T) {
	cases := []struct {
		name string
		want string
		cap  policy.Capability
		path string
	}{
		{"serena_replace_content", "replace_content", policy.CapabilityMutation, "relative_path"},
		{"mcp__serena__replace_content", "replace_content", policy.CapabilityMutation, "relative_path"},
		{"mcp__serena__find_symbol", "find_symbol", policy.CapabilityReadDiscovery, "relative_path"},
		{"serena_get_symbols_overview", "get_symbols_overview", policy.CapabilityReadDiscovery, "relative_path"},
		{"mcp__serena__write_memory", "write_memory", policy.CapabilityMutation, "memory_name"},
		{"serena_list_memories", "list_memories", policy.CapabilitySafeControl, ""},
		{"mcp__serena__activate_project", "activate_project", policy.CapabilityExternal, ""},
		{"graft_graft_find_code", "graft_find_code", policy.CapabilityReadDiscovery, "relative_path"},
		{"mcp__graft__graft_find_code", "graft_find_code", policy.CapabilityReadDiscovery, "relative_path"},
		{"mcp__graft__graft_repo_map", "graft_repo_map", policy.CapabilityReadDiscovery, "relative_path"},
	}
	for _, tc := range cases {
		spec, ok := MatchMCPTool(tc.name)
		if !ok {
			t.Errorf("%s: no match", tc.name)
			continue
		}
		if spec.Tool != tc.want || spec.Capability != tc.cap {
			t.Errorf("%s = %+v, want tool %q capability %q", tc.name, spec, tc.want, tc.cap)
		}
		if tc.path == "" && len(spec.PathArgs) != 0 {
			t.Errorf("%s: unexpected path args %v", tc.name, spec.PathArgs)
		}
		if tc.path != "" && (len(spec.PathArgs) == 0 || spec.PathArgs[0] != tc.path) {
			t.Errorf("%s: path args = %v, want first %q", tc.name, spec.PathArgs, tc.path)
		}
	}
}

func TestMatchMCPToolRejectsUnknownAndPrefixedUnknowns(t *testing.T) {
	for _, name := range []string{"", "totally_unknown", "mcp__weather__get_forecast", "bash", "read"} {
		if _, ok := MatchMCPTool(name); ok {
			t.Errorf("%q matched an MCP family", name)
		}
	}
}

func TestMatchMCPToolMemoryToolsCarryMemoryPrefix(t *testing.T) {
	spec, ok := MatchMCPTool("mcp__serena__write_memory")
	if !ok || spec.PathPrefix != ".serena/memories/" {
		t.Fatalf("write_memory spec = %+v ok=%v", spec, ok)
	}
}
