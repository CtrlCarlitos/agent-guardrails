package planecontract

import (
	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
	"strings"
)

// Canonical hook names, not model-facing namespaces. Codex projects shell and
// unified exec to Bash; apply_patch carries its patch in tool_input.command.
var codexTools = []ToolSpec{
	// web.run is refined by argument shape in the adapter; unprojectable
	// requests retain Deny rather than checking only part of a composite call.
	{"web.run", "web.run", policy.CapabilityDeny},
	{"image_gen.imagegen", "image_gen.imagegen", policy.CapabilityExternal},
	{"clock.curr_time", "clock.curr_time", policy.CapabilitySafeControl},
	{"clock.sleep", "clock.sleep", policy.CapabilitySafeControl},
	{"functions.wait", "functions.wait", policy.CapabilitySafeControl},
	{"functions.exec", "functions.exec", policy.CapabilityDeny},
	{"write_stdin", "write_stdin", policy.CapabilityDeny},
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
	// Codex collaboration.* is the live native spelling observed on the
	// current runtime schema. Bare names above stay for the documented
	// hook surface. collaboration.resume_agent is omitted: #184 listed it
	// as a sibling, but it is not in the current schema and we have no
	// captured hook payload for that spelling.
	{"collaboration.spawn_agent", "collaboration.spawn_agent", policy.CapabilityDelegation},
	{"collaboration.send_message", "collaboration.send_message", policy.CapabilityDelegation},
	{"collaboration.followup_task", "collaboration.followup_task", policy.CapabilityDelegation},
	{"collaboration.interrupt_agent", "collaboration.interrupt_agent", policy.CapabilitySafeControl},
	{"collaboration.list_agents", "collaboration.list_agents", policy.CapabilitySafeControl},
	{"collaboration.wait_agent", "collaboration.wait_agent", policy.CapabilitySafeControl},
	{"list_mcp_resources", "list_mcp_resources", policy.CapabilityDeny},
	{"list_mcp_resource_templates", "list_mcp_resource_templates", policy.CapabilityDeny},
	{"read_mcp_resource", "read_mcp_resource", policy.CapabilityDeny},
}

func CodexTool(name string) (ToolSpec, bool) {
	if strings.HasPrefix(name, "mcp__") {
		return ToolSpec{name, name, policy.CapabilityDeny}, true
	}
	// Explicit documented namespace spellings only. Do not strip arbitrary
	// prefixes: that could turn an unknown extension into an allowed control.
	switch name {
	case "web__run", "webrun":
		name = "web.run"
	case "image_gen__imagegen", "image_genimagegen":
		name = "image_gen.imagegen"
	case "clock__curr_time", "clockcurr_time":
		name = "clock.curr_time"
	case "clock__sleep", "clocksleep":
		name = "clock.sleep"
	case "wait", "functions__wait":
		name = "functions.wait"
	case "exec", "functions__exec":
		name = "functions.exec"
	}
	for _, spec := range codexTools {
		if spec.NativeTool == name {
			return spec, true
		}
	}
	return ToolSpec{}, false
}
