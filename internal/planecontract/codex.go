package planecontract

import (
	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
	"strings"
)

// Canonical hook names, not model-facing namespaces. Codex projects shell and
// unified exec to Bash; apply_patch carries its patch in tool_input.command.
var codexTools = []ToolSpec{
	{"Bash", "Bash", policy.CapabilityCommand},
	{"apply_patch", "Edit", policy.CapabilityMutation},
	{"view_image", "Read", policy.CapabilityReadDiscovery},
	{"update_plan", "update_plan", policy.CapabilitySafeControl},
	{"request_user_input", "request_user_input", policy.CapabilitySafeControl},
	{"request_user_input_async", "request_user_input_async", policy.CapabilitySafeControl},
	{"create_goal", "create_goal", policy.CapabilitySafeControl},
	{"get_goal", "get_goal", policy.CapabilitySafeControl},
	{"update_goal", "update_goal", policy.CapabilitySafeControl},
	{"spawn_agent", "spawn_agent", policy.CapabilityDelegation},
	{"send_input", "send_input", policy.CapabilityDelegation},
	{"send_message", "send_message", policy.CapabilityDelegation},
	{"followup_task", "followup_task", policy.CapabilityDelegation},
	{"interrupt_agent", "interrupt_agent", policy.CapabilitySafeControl},
	{"resume_agent", "resume_agent", policy.CapabilityDelegation},
	{"wait_agent", "wait_agent", policy.CapabilitySafeControl},
	{"close_agent", "close_agent", policy.CapabilitySafeControl},
	{"list_agents", "list_agents", policy.CapabilitySafeControl},
	{"list_mcp_resources", "list_mcp_resources", policy.CapabilityDeny},
	{"list_mcp_resource_templates", "list_mcp_resource_templates", policy.CapabilityDeny},
	{"read_mcp_resource", "read_mcp_resource", policy.CapabilityDeny},
}

func CodexTool(name string) (ToolSpec, bool) {
	if strings.HasPrefix(name, "mcp__") {
		return ToolSpec{name, name, policy.CapabilityDeny}, true
	}
	for _, spec := range codexTools {
		if spec.NativeTool == name {
			return spec, true
		}
	}
	return ToolSpec{}, false
}
