package planecontract

import (
	"strings"

	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
)

// MCPToolSpec types a known MCP server tool: its capability classification
// plus the argument names whose values are file-system paths, so adapters can
// project them into the Engine's path policy. See ADR-0017.
type MCPToolSpec struct {
	Family     string
	Tool       string
	Capability policy.Capability
	PathArgs   []string
	// PathPrefix is joined before each PathArgs value when the argument names
	// an opaque id rather than a path (serena memories).
	PathPrefix string
}

// mcpRegistry is keyed by the tool's own name, unqualified by server: MCP
// tool names are unique across the families we type. Entries carry the
// family for matching convenience only.
var mcpRegistry = map[string]MCPToolSpec{
	// serena — code intelligence (paths are project-relative).
	"replace_content":          {"serena", "replace_content", policy.CapabilityMutation, []string{"relative_path"}, ""},
	"replace_in_files":         {"serena", "replace_in_files", policy.CapabilityMutation, []string{"relative_path"}, ""},
	"replace_symbol_body":      {"serena", "replace_symbol_body", policy.CapabilityMutation, []string{"relative_path"}, ""},
	"insert_after_symbol":      {"serena", "insert_after_symbol", policy.CapabilityMutation, []string{"relative_path"}, ""},
	"insert_before_symbol":     {"serena", "insert_before_symbol", policy.CapabilityMutation, []string{"relative_path"}, ""},
	"rename_symbol":            {"serena", "rename_symbol", policy.CapabilityMutation, []string{"relative_path"}, ""},
	"safe_delete_symbol":       {"serena", "safe_delete_symbol", policy.CapabilityMutation, []string{"relative_path"}, ""},
	"find_symbol":              {"serena", "find_symbol", policy.CapabilityReadDiscovery, []string{"relative_path"}, ""},
	"find_declaration":         {"serena", "find_declaration", policy.CapabilityReadDiscovery, []string{"relative_path"}, ""},
	"find_implementations":     {"serena", "find_implementations", policy.CapabilityReadDiscovery, []string{"relative_path"}, ""},
	"find_referencing_symbols": {"serena", "find_referencing_symbols", policy.CapabilityReadDiscovery, []string{"relative_path"}, ""},
	"get_symbols_overview":     {"serena", "get_symbols_overview", policy.CapabilityReadDiscovery, []string{"relative_path"}, ""},
	"get_diagnostics_for_file": {"serena", "get_diagnostics_for_file", policy.CapabilityReadDiscovery, []string{"relative_path", "filePath"}, ""},
	// serena — memories (opaque names resolve under the memory store).
	"write_memory":  {"serena", "write_memory", policy.CapabilityMutation, []string{"memory_name"}, ".serena/memories/"},
	"edit_memory":   {"serena", "edit_memory", policy.CapabilityMutation, []string{"memory_name"}, ".serena/memories/"},
	"rename_memory": {"serena", "rename_memory", policy.CapabilityMutation, []string{"memory_name", "new_name"}, ".serena/memories/"},
	"delete_memory": {"serena", "delete_memory", policy.CapabilityMutation, []string{"memory_name"}, ".serena/memories/"},
	"read_memory":   {"serena", "read_memory", policy.CapabilityReadDiscovery, []string{"memory_name"}, ".serena/memories/"},
	// serena — session-scope introspection and control.
	"list_memories":        {"serena", "list_memories", policy.CapabilitySafeControl, nil, ""},
	"get_current_config":   {"serena", "get_current_config", policy.CapabilitySafeControl, nil, ""},
	"initial_instructions": {"serena", "initial_instructions", policy.CapabilitySafeControl, nil, ""},
	"onboarding":           {"serena", "onboarding", policy.CapabilitySafeControl, nil, ""},
	"activate_project":     {"serena", "activate_project", policy.CapabilityExternal, nil, ""},
	// graft — code-graph index queries.
	"graft_find_code":   {"graft", "graft_find_code", policy.CapabilityReadDiscovery, []string{"relative_path", "path", "file_path"}, ""},
	"graft_find_all":    {"graft", "graft_find_all", policy.CapabilityReadDiscovery, []string{"relative_path", "path", "file_path"}, ""},
	"graft_trace_calls": {"graft", "graft_trace_calls", policy.CapabilityReadDiscovery, []string{"relative_path", "path", "file_path"}, ""},
	"graft_file_api":    {"graft", "graft_file_api", policy.CapabilityReadDiscovery, []string{"relative_path", "path", "file_path"}, ""},
	"graft_repo_map":    {"graft", "graft_repo_map", policy.CapabilityReadDiscovery, []string{"relative_path", "path", "file_path"}, ""},
}

// MatchMCPTool resolves a native MCP tool name in any plane's naming —
// bare ("serena_find_symbol"), single-underscore family-joined, or prefixed
// ("mcp__serena__find_symbol", "mcp__graft__graft_find_code") — to its typed
// spec. Unknown tools return false and stay under their plane's unclassified
// posture.
func MatchMCPTool(nativeTool string) (MCPToolSpec, bool) {
	name := strings.ToLower(strings.TrimSpace(nativeTool))
	if name == "" {
		return MCPToolSpec{}, false
	}
	if spec, ok := mcpRegistry[name]; ok {
		return spec, true
	}
	var rest string
	if strings.HasPrefix(name, "mcp__") {
		parts := strings.SplitN(name, "__", 3)
		if len(parts) == 3 {
			rest = parts[2]
		}
	} else if i := strings.Index(name, "_"); i > 0 {
		rest = name[i+1:]
	}
	if rest == "" {
		return MCPToolSpec{}, false
	}
	if spec, ok := mcpRegistry[rest]; ok {
		return spec, true
	}
	// Family-prefixed tool names ("graft_graft_find_code" after prefix strip):
	// drop a repeated family prefix and retry.
	if i := strings.Index(rest, "_"); i > 0 {
		if spec, ok := mcpRegistry[rest[i+1:]]; ok {
			return spec, true
		}
	}
	return MCPToolSpec{}, false
}
