package planecontract

import (
	"sort"
	"strings"
)

// degradedAllowTools is the B+ contract: the native tools an adapter may
// allow locally, without the engine, when the engine is unreachable after a
// single spawn attempt. Eligibility is strict — argument-independent, direct
// human communication only:
//
//   - skill does NOT qualify: it loads instructions whose effect outlives
//     the outage.
//   - manage_task does NOT qualify: its SafeControl classification is
//     argument-dependent (send_input is denied in the adapter).
//   - schedule does NOT qualify: External tier.
//   - read/discovery, mutation, delegation, and command tools never qualify.
//
// Engine-owned and baked into adapter artifacts by gen-config; adapters
// never curate their own lists (ADR-0022 candidate).
var degradedAllowTools = map[string]map[string]bool{
	"opencode":    {"question": true, "todowrite": true},
	"claude":      {"AskUserQuestion": true},
	"antigravity": {"ask_question": true},
}

// DegradedAllow reports whether the plane's native tool is degraded-
// allowable: an adapter facing an engine transport failure may allow this
// one call locally (with a stderr notice and a deferred audit record)
// instead of failing the agent's communication channel closed.
func DegradedAllow(plane, nativeTool string) bool {
	tools, ok := degradedAllowTools[plane]
	if !ok {
		return false
	}
	if plane == "opencode" {
		nativeTool = strings.ToLower(nativeTool)
	}
	return tools[nativeTool]
}

// OpencodeDegradedAllowTools returns the opencode degraded-allowable native
// tools for adapter codegen, sorted.
func OpencodeDegradedAllowTools() []string {
	tools := make([]string, 0, len(degradedAllowTools["opencode"]))
	for name := range degradedAllowTools["opencode"] {
		tools = append(tools, name)
	}
	sort.Strings(tools)
	return tools
}

// floorFallbackTools is the ADR-0022 capability table's middle rows: the
// ReadDiscovery and Mutation tools that proceed under the host-side
// Declarative floor when the engine is unreachable after the full retry
// ladder. Commands, egress, delegation, unknown, and MCP surfaces are NOT
// floor-fallback-eligible — the floor has no equivalent for them — and
// communication tools are handled by degradedAllowTools above.
var floorFallbackTools = map[string]map[string]bool{
	"opencode": {"apply_patch": true, "edit": true, "glob": true, "grep": true, "lsp": true, "read": true, "write": true},
}

// FloorFallback reports whether the plane's native tool proceeds under the
// Declarative floor during degraded mode (ADR-0022).
func FloorFallback(plane, nativeTool string) bool {
	tools, ok := floorFallbackTools[plane]
	if !ok {
		return false
	}
	if plane == "opencode" {
		nativeTool = strings.ToLower(nativeTool)
	}
	return tools[nativeTool]
}

// OpencodeFloorFallbackTools returns the opencode floor-fallback native
// tools for adapter codegen, sorted.
func OpencodeFloorFallbackTools() []string {
	tools := make([]string, 0, len(floorFallbackTools["opencode"]))
	for name := range floorFallbackTools["opencode"] {
		tools = append(tools, name)
	}
	sort.Strings(tools)
	return tools
}
