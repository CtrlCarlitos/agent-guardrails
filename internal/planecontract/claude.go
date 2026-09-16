// Package planecontract defines the native tool boundaries each plane exposes.
package planecontract

import (
	"strings"

	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
)

type ToolSpec struct {
	NativeTool string
	Tool       string
	Capability policy.Capability
}

var claudeTools = []ToolSpec{
	{"Agent", "Agent", policy.CapabilityDelegation},
	{"AskUserQuestion", "AskUserQuestion", policy.CapabilitySafeControl},
	{"Bash", "Bash", policy.CapabilityCommand},
	{"Edit", "Edit", policy.CapabilityMutation},
	{"Glob", "Glob", policy.CapabilityReadDiscovery},
	{"Grep", "Grep", policy.CapabilityReadDiscovery},
	{"LSP", "LSP", policy.CapabilityReadDiscovery},
	{"Monitor", "Bash", policy.CapabilityCommand},
	{"MultiEdit", "MultiEdit", policy.CapabilityMutation},
	{"NotebookEdit", "NotebookEdit", policy.CapabilityMutation},
	{"PowerShell", "Bash", policy.CapabilityCommand},
	{"Read", "Read", policy.CapabilityReadDiscovery},
	{"WebFetch", "WebFetch", policy.CapabilityWebFetch},
	{"WebSearch", "WebSearch", policy.CapabilityWebSearch},
	{"Workflow", "Workflow", policy.CapabilityDelegation},
	{"Write", "Write", policy.CapabilityMutation},
	{"Artifact", "Artifact", policy.CapabilityDeny},
	{"CronCreate", "CronCreate", policy.CapabilityDeny},
	{"CronDelete", "CronDelete", policy.CapabilityDeny},
	{"CronList", "CronList", policy.CapabilitySafeControl},
	{"EndConversation", "EndConversation", policy.CapabilitySafeControl},
	{"EnterPlanMode", "EnterPlanMode", policy.CapabilitySafeControl},
	{"EnterWorktree", "EnterWorktree", policy.CapabilityDeny},
	{"ExitPlanMode", "ExitPlanMode", policy.CapabilitySafeControl},
	{"ExitWorktree", "ExitWorktree", policy.CapabilitySafeControl},
	{"ListAgents", "ListAgents", policy.CapabilitySafeControl},
	{"ListMcpResourcesTool", "ListMcpResourcesTool", policy.CapabilityDeny},
	{"PushNotification", "PushNotification", policy.CapabilityDeny},
	{"ReadMcpResourceTool", "ReadMcpResourceTool", policy.CapabilityDeny},
	{"RemoteTrigger", "RemoteTrigger", policy.CapabilityDeny},
	{"ReportFindings", "ReportFindings", policy.CapabilitySafeControl},
	{"ScheduleWakeup", "ScheduleWakeup", policy.CapabilitySafeControl},
	{"SendFeedback", "SendFeedback", policy.CapabilityDeny},
	{"SendMessage", "SendMessage", policy.CapabilityDeny},
	{"SendUserFile", "SendUserFile", policy.CapabilityDeny},
	{"ShareOnboardingGuide", "ShareOnboardingGuide", policy.CapabilityDeny},
	{"Skill", "Skill", policy.CapabilitySafeControl},
	{"SubagentHandback", "SubagentHandback", policy.CapabilitySafeControl},
	{"TaskCreate", "TaskCreate", policy.CapabilitySafeControl},
	{"TaskGet", "TaskGet", policy.CapabilitySafeControl},
	{"TaskList", "TaskList", policy.CapabilitySafeControl},
	{"TaskOutput", "TaskOutput", policy.CapabilitySafeControl},
	{"TaskStop", "TaskStop", policy.CapabilitySafeControl},
	{"TaskUpdate", "TaskUpdate", policy.CapabilitySafeControl},
	{"TodoWrite", "TodoWrite", policy.CapabilitySafeControl},
	{"ToolSearch", "ToolSearch", policy.CapabilitySafeControl},
	{"WaitForMcpServers", "WaitForMcpServers", policy.CapabilitySafeControl},
}

func RegisteredTools(plane string) []ToolSpec {
	switch plane {
	case "claude":
		return append([]ToolSpec(nil), claudeTools...)
	case "opencode":
		return append([]ToolSpec(nil), opencodeTools...)
	case "antigravity":
		return append([]ToolSpec(nil), antigravityTools...)
	default:
		return nil
	}
}

func ClaudeTool(nativeTool string) (ToolSpec, bool) {
	if strings.HasPrefix(nativeTool, "mcp__") {
		return ToolSpec{NativeTool: nativeTool, Tool: nativeTool, Capability: policy.CapabilityDeny}, true
	}
	for _, spec := range claudeTools {
		if spec.NativeTool == nativeTool {
			return spec, true
		}
	}
	return ToolSpec{}, false
}

func ClaudePreHookMatcher() string { return "*" }

func ClaudePreMatcherMatches(string) bool { return true }
