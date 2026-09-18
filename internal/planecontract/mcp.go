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
	// DefaultPath is projected when no PathArgs value is present, scoping
	// pathless queries ("." = the call's working directory) so the path
	// policy governs them instead of failing closed. Mutations never set it.
	DefaultPath string
}

// mcpRegistry is keyed by the tool's own name, unqualified by server: MCP
// tool names are unique across the families we type. Entries carry the
// family for matching convenience only.
var mcpRegistry = map[string]MCPToolSpec{
	// serena mutators
	"replace_content":      {Family: "serena", Tool: "replace_content", Capability: policy.CapabilityMutation, PathArgs: []string{"relative_path"}},
	"replace_in_files":     {Family: "serena", Tool: "replace_in_files", Capability: policy.CapabilityMutation, PathArgs: []string{"relative_path"}},
	"replace_symbol_body":  {Family: "serena", Tool: "replace_symbol_body", Capability: policy.CapabilityMutation, PathArgs: []string{"relative_path"}},
	"insert_after_symbol":  {Family: "serena", Tool: "insert_after_symbol", Capability: policy.CapabilityMutation, PathArgs: []string{"relative_path"}},
	"insert_before_symbol": {Family: "serena", Tool: "insert_before_symbol", Capability: policy.CapabilityMutation, PathArgs: []string{"relative_path"}},
	"rename_symbol":        {Family: "serena", Tool: "rename_symbol", Capability: policy.CapabilityMutation, PathArgs: []string{"relative_path"}},
	"safe_delete_symbol":   {Family: "serena", Tool: "safe_delete_symbol", Capability: policy.CapabilityMutation, PathArgs: []string{"relative_path"}},
	// serena readers
	"find_symbol":              {Family: "serena", Tool: "find_symbol", Capability: policy.CapabilityReadDiscovery, PathArgs: []string{"relative_path"}, DefaultPath: "."},
	"find_declaration":         {Family: "serena", Tool: "find_declaration", Capability: policy.CapabilityReadDiscovery, PathArgs: []string{"relative_path"}, DefaultPath: "."},
	"find_implementations":     {Family: "serena", Tool: "find_implementations", Capability: policy.CapabilityReadDiscovery, PathArgs: []string{"relative_path"}, DefaultPath: "."},
	"find_referencing_symbols": {Family: "serena", Tool: "find_referencing_symbols", Capability: policy.CapabilityReadDiscovery, PathArgs: []string{"relative_path"}, DefaultPath: "."},
	"get_symbols_overview":     {Family: "serena", Tool: "get_symbols_overview", Capability: policy.CapabilityReadDiscovery, PathArgs: []string{"relative_path"}, DefaultPath: "."},
	"get_diagnostics_for_file": {Family: "serena", Tool: "get_diagnostics_for_file", Capability: policy.CapabilityReadDiscovery, PathArgs: []string{"relative_path", "filePath"}, DefaultPath: "."},
	// serena memories
	"write_memory":  {Family: "serena", Tool: "write_memory", Capability: policy.CapabilityMutation, PathArgs: []string{"memory_name"}, PathPrefix: ".serena/memories/"},
	"edit_memory":   {Family: "serena", Tool: "edit_memory", Capability: policy.CapabilityMutation, PathArgs: []string{"memory_name"}, PathPrefix: ".serena/memories/"},
	"rename_memory": {Family: "serena", Tool: "rename_memory", Capability: policy.CapabilityMutation, PathArgs: []string{"memory_name", "new_name"}, PathPrefix: ".serena/memories/"},
	"delete_memory": {Family: "serena", Tool: "delete_memory", Capability: policy.CapabilityMutation, PathArgs: []string{"memory_name"}, PathPrefix: ".serena/memories/"},
	"read_memory":   {Family: "serena", Tool: "read_memory", Capability: policy.CapabilityReadDiscovery, PathArgs: []string{"memory_name"}, PathPrefix: ".serena/memories/"},
	// serena session-scope
	"list_memories":        {Family: "serena", Tool: "list_memories", Capability: policy.CapabilitySafeControl, PathArgs: nil},
	"get_current_config":   {Family: "serena", Tool: "get_current_config", Capability: policy.CapabilitySafeControl, PathArgs: nil},
	"initial_instructions": {Family: "serena", Tool: "initial_instructions", Capability: policy.CapabilitySafeControl, PathArgs: nil},
	"onboarding":           {Family: "serena", Tool: "onboarding", Capability: policy.CapabilitySafeControl, PathArgs: nil},
	"activate_project":     {Family: "serena", Tool: "activate_project", Capability: policy.CapabilityExternal, PathArgs: nil},
	// graft
	"graft_find_code":   {Family: "graft", Tool: "graft_find_code", Capability: policy.CapabilityReadDiscovery, PathArgs: []string{"relative_path", "path", "file_path"}, DefaultPath: "."},
	"graft_find_all":    {Family: "graft", Tool: "graft_find_all", Capability: policy.CapabilityReadDiscovery, PathArgs: []string{"relative_path", "path", "file_path"}, DefaultPath: "."},
	"graft_trace_calls": {Family: "graft", Tool: "graft_trace_calls", Capability: policy.CapabilityReadDiscovery, PathArgs: []string{"relative_path", "path", "file_path"}, DefaultPath: "."},
	"graft_file_api":    {Family: "graft", Tool: "graft_file_api", Capability: policy.CapabilityReadDiscovery, PathArgs: []string{"relative_path", "path", "file_path"}, DefaultPath: "."},
	"graft_repo_map":    {Family: "graft", Tool: "graft_repo_map", Capability: policy.CapabilityReadDiscovery, PathArgs: []string{"relative_path", "path", "file_path"}, DefaultPath: "."},
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
