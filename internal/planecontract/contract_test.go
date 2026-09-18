package planecontract

import (
	"testing"

	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
)

func TestClaudeInventoryClassifiesCapabilityBoundary(t *testing.T) {
	want := map[string]policy.Capability{
		"Bash":         policy.CapabilityCommand,
		"PowerShell":   policy.CapabilityCommand,
		"Read":         policy.CapabilityReadDiscovery,
		"Glob":         policy.CapabilityReadDiscovery,
		"Grep":         policy.CapabilityReadDiscovery,
		"LSP":          policy.CapabilityReadDiscovery,
		"Edit":         policy.CapabilityMutation,
		"Write":        policy.CapabilityMutation,
		"MultiEdit":    policy.CapabilityMutation,
		"NotebookEdit": policy.CapabilityMutation,
		"WebFetch":     policy.CapabilityWebFetch,
		"WebSearch":    policy.CapabilityWebSearch,
		"Agent":        policy.CapabilityDelegation,
		"Task":         policy.CapabilityDelegation,
		// Reaches outside the session (publication, scheduler, MCP server):
		// the operator decides per call.
		"Artifact":               policy.CapabilityExternal,
		"ArtifactCheck":          policy.CapabilityExternal,
		"ArtifactComments":       policy.CapabilityExternal,
		"ArtifactData":           policy.CapabilityExternal,
		"DesignSync":             policy.CapabilityExternal,
		"CronCreate":             policy.CapabilityExternal,
		"ListMcpResourcesTool":   policy.CapabilityExternal,
		"ReadMcpResourceTool":    policy.CapabilityExternal,
		"ReadMcpResourceDirTool": policy.CapabilityExternal,
		// Session-local control with no data flow of its own.
		"CronDelete":       policy.CapabilitySafeControl,
		"CronList":         policy.CapabilitySafeControl,
		"EnterWorktree":    policy.CapabilitySafeControl,
		"ExitWorktree":     policy.CapabilitySafeControl,
		"PushNotification": policy.CapabilitySafeControl,
		"BashOutput":       policy.CapabilitySafeControl, // output of a shell already evaluated at launch
		"KillShell":        policy.CapabilitySafeControl,
		"Sleep":            policy.CapabilitySafeControl,
		"StructuredOutput": policy.CapabilitySafeControl,
		// Legacy notebook read: a path read, projected like Read.
		"NotebookRead": policy.CapabilityReadDiscovery,
		// Moves data or control to another principal; stays denied.
		"SendMessage":          policy.CapabilityDeny,
		"SendUserFile":         policy.CapabilityDeny,
		"RemoteTrigger":        policy.CapabilityDeny,
		"SendFeedback":         policy.CapabilityDeny,
		"ShareOnboardingGuide": policy.CapabilityDeny,
	}
	for tool, capability := range want {
		spec, ok := ClaudeTool(tool)
		if !ok || spec.Capability != capability {
			t.Fatalf("%s = %#v, %v; want %v", tool, spec, ok, capability)
		}
	}

	if spec, ok := ClaudeTool("mcp__server__unsafe"); !ok || spec.Capability != policy.CapabilityExternal {
		t.Fatalf("MCP tool = %#v, %v; want external", spec, ok)
	}
}

func TestClaudePreHookMatcherCoversEveryInventoryTool(t *testing.T) {
	if matcher := ClaudePreHookMatcher(); matcher != "*" {
		t.Fatalf("matcher = %q, want catch-all", matcher)
	}
	for _, spec := range RegisteredTools("claude") {
		if !ClaudePreMatcherMatches(spec.NativeTool) {
			t.Fatal(spec.NativeTool)
		}
	}
}

func TestOpenCodeAndAntigravityInventoriesClassifyCapabilityBoundary(t *testing.T) {
	// These are the documented hook-visible surfaces, not copies of the inventories.
	for _, tt := range []struct {
		plane string
		tools map[string]policy.Capability
	}{
		{"opencode", map[string]policy.Capability{
			"bash": policy.CapabilityCommand, "read": policy.CapabilityReadDiscovery,
			"grep": policy.CapabilityReadDiscovery, "glob": policy.CapabilityReadDiscovery,
			"lsp": policy.CapabilityReadDiscovery, "edit": policy.CapabilityMutation,
			"write": policy.CapabilityMutation, "apply_patch": policy.CapabilityMutation,
			"skill": policy.CapabilitySafeControl, "todowrite": policy.CapabilitySafeControl,
			"webfetch": policy.CapabilityWebFetch, "websearch": policy.CapabilityWebSearch,
			"question": policy.CapabilitySafeControl, "task": policy.CapabilityDelegation,
		}},
		{"antigravity", map[string]policy.Capability{
			"run_command": policy.CapabilityCommand, "view_file": policy.CapabilityReadDiscovery,
			"list_dir": policy.CapabilityReadDiscovery, "find_by_name": policy.CapabilityReadDiscovery,
			"grep_search": policy.CapabilityReadDiscovery, "write_to_file": policy.CapabilityMutation,
			"replace_file_content": policy.CapabilityMutation, "multi_replace_file_content": policy.CapabilityMutation,
			"read_url_content": policy.CapabilityWebFetch, "search_web": policy.CapabilityWebSearch,
			"manage_task": policy.CapabilitySafeControl, "schedule": policy.CapabilityExternal,
			"list_permissions": policy.CapabilitySafeControl, "ask_permission": policy.CapabilitySafeControl,
			"invoke_subagent": policy.CapabilityDelegation, "define_subagent": policy.CapabilityDeny,
			"send_message": policy.CapabilityDelegation, "manage_subagents": policy.CapabilityDelegation,
			"ask_question": policy.CapabilitySafeControl, "generate_image": policy.CapabilityDeny,
			"call_mcp_tool": policy.CapabilityDeny, "send_command_input": policy.CapabilityDeny,
			"tool_caller": policy.CapabilityDeny, "notebook_edit": policy.CapabilityMutation,
			"sed_file": policy.CapabilityMutation, "delete_knowledge": policy.CapabilityMutation,
			"notebook_execution": policy.CapabilityCommand, "list_resources": policy.CapabilityExternal,
			"read_resource": policy.CapabilityExternal, "command_status": policy.CapabilitySafeControl,
			"manage_inbox": policy.CapabilitySafeControl, "ask_custom_permission": policy.CapabilitySafeControl,
			"finish": policy.CapabilitySafeControl, "wait": policy.CapabilitySafeControl,
			"wait_five_seconds": policy.CapabilitySafeControl,
		}},
	} {
		got := RegisteredTools(tt.plane)
		if len(got) != len(tt.tools) {
			t.Fatalf("%s inventory has %d entries, want %d", tt.plane, len(got), len(tt.tools))
		}
		for _, spec := range got {
			if want, ok := tt.tools[spec.NativeTool]; !ok || spec.Capability != want {
				t.Fatalf("%s %s = %q, want %q", tt.plane, spec.NativeTool, spec.Capability, want)
			}
		}
	}
	for _, tool := range []string{"custom", "mcp__server__unsafe"} {
		spec, ok := OpencodeTool(tool)
		if !ok || spec.Capability != policy.CapabilityDeny {
			t.Fatalf("OpenCode %s = %#v, %v; want deny", tool, spec, ok)
		}
	}
}

func TestAntigravityPreHookMatcherCoversEveryInventoryTool(t *testing.T) {
	if matcher := AntigravityPreHookMatcher(); matcher != "*" {
		t.Fatalf("matcher = %q, want catch-all", matcher)
	}
	for _, spec := range RegisteredTools("antigravity") {
		if !AntigravityPreMatcherMatches(spec.NativeTool) {
			t.Fatal(spec.NativeTool)
		}
	}
}
