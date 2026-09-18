package adapter

import (
	"encoding/json"

	"github.com/CtrlCarlitos/agent-guardrails/internal/planecontract"
)

// projectMCPPaths extracts the file paths an MCP tool names, per its
// registry spec: each PathArgs value, prefixed when the argument names an
// opaque id (serena memories). Paths stay as provided; the Engine resolves
// them against the call's working directory.
func projectMCPPaths(mcp planecontract.MCPToolSpec, arguments json.RawMessage) []string {
	if len(mcp.PathArgs) == 0 {
		return nil
	}
	var args map[string]any
	if err := json.Unmarshal(arguments, &args); err != nil {
		return nil
	}
	var paths []string
	for _, name := range mcp.PathArgs {
		if value, ok := args[name].(string); ok && value != "" {
			paths = append(paths, mcp.PathPrefix+value)
		}
	}
	if len(paths) == 0 && mcp.DefaultPath != "" {
		// Pathless queries scope to the call's working directory; the path
		// policy governs the scope instead of failing closed.
		paths = []string{mcp.DefaultPath}
	}
	return paths
}
