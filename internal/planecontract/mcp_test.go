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
		// serena 1.7.0 (#458): opens serena's local web dashboard; no arguments.
		{"mcp__serena__open_dashboard", "open_dashboard", policy.CapabilitySafeControl, ""},
		{"serena_open_dashboard", "open_dashboard", policy.CapabilitySafeControl, ""},
		{"graft_graft_find_code", "graft_find_code", policy.CapabilityReadDiscovery, "relative_path"},
		{"mcp__graft__graft_find_code", "graft_find_code", policy.CapabilityReadDiscovery, "relative_path"},
		{"mcp__graft__graft_repo_map", "graft_repo_map", policy.CapabilityReadDiscovery, "relative_path"},
		// graft 0.20 added it; doctor reported it uncontracted (2026-09-27).
		{"mcp__graft__graft_check_freshness", "graft_check_freshness", policy.CapabilityReadDiscovery, "relative_path"},
		{"graft_graft_check_freshness", "graft_check_freshness", policy.CapabilityReadDiscovery, "relative_path"},
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

// #543: the codex apps GitHub connector's repository search resolves under
// both connector spellings; the bare tool name stays deliberately unkeyed —
// too generic to claim across planes — and unevidenced siblings do not
// resolve at all.
func TestMatchMCPToolCodexAppsGitHubDiscovery(t *testing.T) {
	for _, name := range []string{
		"mcp__codex_apps__github__search_repositories",
		"mcp__codex_apps__github_search_repositories",
	} {
		spec, ok := MatchMCPTool(name)
		if !ok || spec.Family != "codex_apps" || spec.Tool != "github__search_repositories" {
			t.Errorf("%s = %+v,%v", name, spec, ok)
		}
	}
	for _, name := range []string{
		"search_repositories",
		"github__create_issue",
		"mcp__codex_apps__github__create_issue",
	} {
		if _, ok := MatchMCPTool(name); ok {
			t.Errorf("%s must not resolve; discovery is keyed, mutations are not", name)
		}
	}
}
