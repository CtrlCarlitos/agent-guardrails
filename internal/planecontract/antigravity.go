package planecontract

import (
	"strings"

	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
)

var antigravityTools = []ToolSpec{
	{"run_command", "Bash", policy.CapabilityCommand},
	{"view_file", "Read", policy.CapabilityReadDiscovery},
	{"list_dir", "List", policy.CapabilityReadDiscovery},
	{"find_by_name", "Glob", policy.CapabilityReadDiscovery},
	{"grep_search", "Grep", policy.CapabilityReadDiscovery},
	{"write_to_file", "Write", policy.CapabilityMutation},
	{"replace_file_content", "Edit", policy.CapabilityMutation},
	{"multi_replace_file_content", "Edit", policy.CapabilityMutation},
	{"read_url_content", "read_url_content", policy.CapabilityWebFetch},
	{"search_web", "search_web", policy.CapabilityWebSearch},
	{"manage_task", "manage_task", policy.CapabilitySafeControl},
	{"schedule", "schedule", policy.CapabilityExternal},
	{"list_permissions", "list_permissions", policy.CapabilitySafeControl},
	{"ask_permission", "ask_permission", policy.CapabilitySafeControl},
	{"invoke_subagent", "invoke_subagent", policy.CapabilityDelegation},
	{"define_subagent", "define_subagent", policy.CapabilityDeny},
	{"send_message", "send_message", policy.CapabilityDelegation},
	{"manage_subagents", "manage_subagents", policy.CapabilityDelegation},
	{"ask_question", "ask_question", policy.CapabilitySafeControl},
	{"generate_image", "generate_image", policy.CapabilityDeny},
	{"call_mcp_tool", "call_mcp_tool", policy.CapabilityDeny},
	{"send_command_input", "send_command_input", policy.CapabilityDeny},
	{"tool_caller", "tool_caller", policy.CapabilityDeny},
	{"notebook_edit", "Edit", policy.CapabilityMutation},
	{"sed_file", "Edit", policy.CapabilityMutation},
	{"delete_knowledge", "Write", policy.CapabilityMutation},
	{"notebook_execution", "Bash", policy.CapabilityCommand},
	{"list_resources", "list_resources", policy.CapabilityExternal},
	{"read_resource", "read_resource", policy.CapabilityExternal},
	{"command_status", "command_status", policy.CapabilitySafeControl},
	{"manage_inbox", "manage_inbox", policy.CapabilitySafeControl},
	{"ask_custom_permission", "ask_custom_permission", policy.CapabilitySafeControl},
	{"finish", "finish", policy.CapabilitySafeControl},
	{"wait", "wait", policy.CapabilitySafeControl},
	{"wait_five_seconds", "wait", policy.CapabilitySafeControl},
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
