package planecontract

import (
	"strings"

	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
)

var opencodeTools = []ToolSpec{
	{"bash", "Bash", policy.CapabilityCommand},
	{"read", "Read", policy.CapabilityReadDiscovery},
	{"glob", "Glob", policy.CapabilityReadDiscovery},
	{"grep", "Grep", policy.CapabilityReadDiscovery},
	{"lsp", "LSP", policy.CapabilityReadDiscovery},
	{"edit", "Edit", policy.CapabilityMutation},
	{"write", "Write", policy.CapabilityMutation},
	{"apply_patch", "apply_patch", policy.CapabilityMutation},
	{"webfetch", "webfetch", policy.CapabilityWebFetch},
	{"websearch", "websearch", policy.CapabilityWebSearch},
	{"question", "question", policy.CapabilitySafeControl},
	{"skill", "skill", policy.CapabilitySafeControl},
	{"todowrite", "todowrite", policy.CapabilitySafeControl},
	{"task", "task", policy.CapabilityDelegation},
}

func OpencodeTool(nativeTool string) (ToolSpec, bool) {
	name := strings.ToLower(nativeTool)
	if name == "custom" || strings.HasPrefix(name, "mcp") {
		return ToolSpec{NativeTool: nativeTool, Tool: nativeTool, Capability: policy.CapabilityDeny}, true
	}
	for _, spec := range opencodeTools {
		if spec.NativeTool == name {
			return spec, true
		}
	}
	return ToolSpec{}, false
}
