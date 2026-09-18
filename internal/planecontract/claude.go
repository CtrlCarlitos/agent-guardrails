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
	{"Task", "Agent", policy.CapabilityDelegation}, // pre-rename Claude Code subagent tool
	{"AskUserQuestion", "AskUserQuestion", policy.CapabilitySafeControl},
	{"Bash", "Bash", policy.CapabilityCommand},
	{"Edit", "Edit", policy.CapabilityMutation},
	{"Glob", "Glob", policy.CapabilityReadDiscovery},
	{"Grep", "Grep", policy.CapabilityReadDiscovery},
	{"LSP", "LSP", policy.CapabilityReadDiscovery},
	{"Monitor", "Bash", policy.CapabilityCommand},
	{"MultiEdit", "MultiEdit", policy.CapabilityMutation},
	{"NotebookEdit", "NotebookEdit", policy.CapabilityMutation},
	{"NotebookRead", "NotebookRead", policy.CapabilityReadDiscovery}, // legacy; notebook_path projects like Read
	{"PowerShell", "Bash", policy.CapabilityCommand},
	{"Read", "Read", policy.CapabilityReadDiscovery},
	{"WebFetch", "WebFetch", policy.CapabilityWebFetch},
	{"WebSearch", "WebSearch", policy.CapabilityWebSearch},
	{"Workflow", "Workflow", policy.CapabilityDelegation},
	{"Write", "Write", policy.CapabilityMutation},
	// Reach claude.ai state outside the session: reads of a published artifact,
	// comment replies and shared-database writes that other people see.
	{"Artifact", "Artifact", policy.CapabilityExternal},
	{"ArtifactCheck", "ArtifactCheck", policy.CapabilityExternal},
	{"ArtifactComments", "ArtifactComments", policy.CapabilityExternal},
	{"ArtifactData", "ArtifactData", policy.CapabilityExternal},
	{"DesignSync", "DesignSync", policy.CapabilityExternal},
	// Background-shell companions: the command itself was evaluated at launch.
	{"BashOutput", "BashOutput", policy.CapabilitySafeControl},
	{"KillShell", "KillShell", policy.CapabilitySafeControl},
	{"Sleep", "Sleep", policy.CapabilitySafeControl},
	{"StructuredOutput", "StructuredOutput", policy.CapabilitySafeControl},
	{"CronCreate", "CronCreate", policy.CapabilityExternal},
	{"CronDelete", "CronDelete", policy.CapabilitySafeControl},
	{"CronList", "CronList", policy.CapabilitySafeControl},
	{"EndConversation", "EndConversation", policy.CapabilitySafeControl},
	{"EnterPlanMode", "EnterPlanMode", policy.CapabilitySafeControl},
	{"EnterWorktree", "EnterWorktree", policy.CapabilitySafeControl},
	{"ExitPlanMode", "ExitPlanMode", policy.CapabilitySafeControl},
	{"ExitWorktree", "ExitWorktree", policy.CapabilitySafeControl},
	{"ListAgents", "ListAgents", policy.CapabilitySafeControl},
	{"ListMcpResourcesTool", "ListMcpResourcesTool", policy.CapabilityExternal},
	{"PushNotification", "PushNotification", policy.CapabilitySafeControl},
	{"ReadMcpResourceTool", "ReadMcpResourceTool", policy.CapabilityExternal},
	{"ReadMcpResourceDirTool", "ReadMcpResourceDirTool", policy.CapabilityExternal},
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
	case "codex":
		return append([]ToolSpec(nil), codexTools...)
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
	// MCP tools are server-defined: their names carry no verifiable data-flow
	// claim, so every call is an operator decision rather than a blanket deny.
	if strings.HasPrefix(nativeTool, "mcp__") {
		return ToolSpec{NativeTool: nativeTool, Tool: nativeTool, Capability: policy.CapabilityExternal}, true
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
