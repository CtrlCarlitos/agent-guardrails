package main

import (
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/CtrlCarlitos/agent-guardrails/internal/coverage"
	"github.com/CtrlCarlitos/agent-guardrails/internal/planecontract"
	"github.com/CtrlCarlitos/agent-guardrails/internal/safetext"
)

// mcpToolLister starts a server and lists its tools; tests replace it.
var mcpToolLister coverage.MCPToolLister = coverage.ListMCPToolsStdio

// mcpServerTimeout bounds one server's start and listing. serena starts
// language servers, so this is generous; a server that misses it is unknown.
const mcpServerTimeout = 45 * time.Second

// printMCPCoverage is `doctor --coverage <plane> --mcp` for Claude Code, Codex
// and OpenCode (#463). Exit 1 when a listed tool is absent from the registry
// or a server's tools could not be listed: either way coverage is unproven.
func printMCPCoverage(plane, configPath string, stdout, stderr io.Writer) int {
	paths := []string{configPath}
	if configPath == "" {
		resolved, err := coverage.MCPConfigPaths(plane)
		if err != nil {
			fmt.Fprintf(stderr, "guardrail: doctor --coverage %s --mcp: %s\n", plane, safetext.SingleLine(err.Error()))
			return 2
		}
		paths = resolved
	}
	// Claude Code keys project-scoped servers by the directory it runs in.
	project, _ := os.Getwd()
	var servers []coverage.MCPServerConfig
	for _, path := range paths {
		read, err := coverage.ReadMCPServers(plane, path, project)
		if err != nil {
			fmt.Fprintf(stderr, "guardrail: doctor --coverage %s --mcp: %s\n", plane, safetext.SingleLine(err.Error()))
			return 2
		}
		servers = append(servers, read...)
	}
	inv := coverage.ScanMCP(plane, paths, servers, mcpToolLister, mcpServerTimeout, planecontract.MatchMCPTool)
	fmt.Fprintf(stdout, "%s MCP coverage (%s)\n", plane, safetext.SingleLine(strings.Join(inv.ConfigPaths, ", ")))
	for _, line := range inv.Describe() {
		fmt.Fprintln(stdout, "  "+safetext.SingleLine(line))
	}
	if len(inv.Uncontracted) > 0 {
		fmt.Fprintln(stdout, "  add each uncontracted tool to internal/planecontract/mcp.go with its capability and path args; until then it runs under unknown_tool_posture")
	}
	if len(inv.Uncontracted) > 0 || len(inv.Unknown) > 0 {
		return 1
	}
	return 0
}
