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
