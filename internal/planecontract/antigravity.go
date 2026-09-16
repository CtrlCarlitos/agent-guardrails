package planecontract

import (
	"strings"

	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
)

var antigravityTools = []ToolSpec{
	{"run_command", "Bash", policy.CapabilityCommand},
	{"view_file", "Read", policy.CapabilityReadDiscovery},
	{"list_dir", "List", policy.CapabilityReadDiscovery},
	{"grep_search", "Grep", policy.CapabilityReadDiscovery},
	{"write_to_file", "Write", policy.CapabilityMutation},
	{"replace_file_content", "Edit", policy.CapabilityMutation},
	{"multi_replace_file_content", "Edit", policy.CapabilityMutation},
	{"read_url_content", "read_url_content", policy.CapabilityWebFetch},
	{"search_web", "search_web", policy.CapabilityWebSearch},
	{"ask_user", "ask_user", policy.CapabilitySafeControl},
	{"update_todo", "update_todo", policy.CapabilitySafeControl},
}

func AntigravityTool(nativeTool string) (ToolSpec, bool) {
	if nativeTool == "custom" || strings.HasPrefix(strings.ToLower(nativeTool), "mcp") {
		return ToolSpec{NativeTool: nativeTool, Tool: nativeTool, Capability: policy.CapabilityDeny}, true
	}
	for _, spec := range antigravityTools {
		if spec.NativeTool == nativeTool {
			return spec, true
		}
	}
	return ToolSpec{}, false
}

func AntigravityPreHookMatcher() string { return "*" }

func AntigravityPreMatcherMatches(string) bool { return true }
