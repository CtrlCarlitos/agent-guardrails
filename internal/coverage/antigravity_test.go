package coverage

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/CtrlCarlitos/agent-guardrails/internal/planecontract"
)

func TestScanAntigravityFindsToolsAndFlagsUncontracted(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "mcp_config.json")
	configJSON := `{
		"mcpServers": {
			"serena": {
				"command": "serena",
				"args": ["start-mcp-server"]
			},
			"custom_server": {
				"command": "custom-binary"
			}
		}
	}`
	if err := os.WriteFile(configPath, []byte(configJSON), 0o644); err != nil {
		t.Fatal(err)
	}

	schemasDir := filepath.Join(dir, "mcp")
	serenaDir := filepath.Join(schemasDir, "serena")
	customDir := filepath.Join(schemasDir, "custom_server")
	if err := os.MkdirAll(serenaDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(customDir, 0o755); err != nil {
		t.Fatal(err)
	}

	// Registered tools in serena
	for _, name := range []string{"replace_content.json", "find_symbol.json"} {
		if err := os.WriteFile(filepath.Join(serenaDir, name), []byte(`{}`), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// Unregistered tools in custom_server
	for _, name := range []string{"unknown_widget.json", "unregistered_action.json"} {
		if err := os.WriteFile(filepath.Join(customDir, name), []byte(`{}`), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	inv, err := ScanAntigravity(configPath, schemasDir, planecontract.MatchMCPTool)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if strings.Join(inv.Servers, ",") != "custom_server,serena" {
		t.Fatalf("servers = %v, want [custom_server, serena]", inv.Servers)
	}

	wantUncontracted := []string{"unknown_widget", "unregistered_action"}
	if strings.Join(inv.Uncontracted, ",") != strings.Join(wantUncontracted, ",") {
		t.Fatalf("uncontracted = %v, want %v", inv.Uncontracted, wantUncontracted)
	}

	wantContracted := []string{"find_symbol", "replace_content"}
	if strings.Join(inv.Contracted, ",") != strings.Join(wantContracted, ",") {
		t.Fatalf("contracted = %v, want %v", inv.Contracted, wantContracted)
	}

	desc := inv.Describe()
	descJoined := strings.Join(desc, "\n")
	if !strings.Contains(descJoined, "configured MCP servers: custom_server, serena") {
		t.Errorf("desc missing servers: %s", descJoined)
	}
	if !strings.Contains(descJoined, "uncontracted (absent from registry): unknown_widget, unregistered_action") {
		t.Errorf("desc missing uncontracted tools: %s", descJoined)
	}
}

func TestScanAntigravityFullCoverage(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "mcp_config.json")
	configJSON := `{
		"mcpServers": {
			"serena": {
				"command": "serena"
			}
		}
	}`
	if err := os.WriteFile(configPath, []byte(configJSON), 0o644); err != nil {
		t.Fatal(err)
	}

	schemasDir := filepath.Join(dir, "mcp", "serena")
	if err := os.MkdirAll(schemasDir, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"list_memories.json", "get_current_config.json"} {
		if err := os.WriteFile(filepath.Join(schemasDir, name), []byte(`{}`), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	inv, err := ScanAntigravity(configPath, filepath.Join(dir, "mcp"), planecontract.MatchMCPTool)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(inv.Uncontracted) != 0 {
		t.Fatalf("uncontracted = %v, want empty", inv.Uncontracted)
	}

	desc := strings.Join(inv.Describe(), "\n")
	if !strings.Contains(desc, "uncontracted (absent from registry): none") {
		t.Errorf("desc want none uncontracted, got: %s", desc)
	}
}

func TestScanAntigravityDiscoversToolsFromInstructionsAndConfig(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "mcp_config.json")
	configJSON := `{
		"mcpServers": {
			"graft": {
				"command": "graft"
			},
			"declared_server": {
				"command": "srv",
				"tools": ["replace_symbol_body", {"name": "safe_delete_symbol"}]
			}
		}
	}`
	if err := os.WriteFile(configPath, []byte(configJSON), 0o644); err != nil {
		t.Fatal(err)
	}

	graftDir := filepath.Join(dir, "mcp", "graft")
	if err := os.MkdirAll(graftDir, 0o755); err != nil {
		t.Fatal(err)
	}
	instructionsMD := `- graft_find_code — "how does X work"
- graft_find_all — when you need EVERY occurrence
- graft_trace_calls — blast radius
`
	if err := os.WriteFile(filepath.Join(graftDir, "instructions.md"), []byte(instructionsMD), 0o644); err != nil {
		t.Fatal(err)
	}

	inv, err := ScanAntigravity(configPath, filepath.Join(dir, "mcp"), planecontract.MatchMCPTool)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	wantContracted := []string{"graft_find_all", "graft_find_code", "graft_trace_calls", "replace_symbol_body", "safe_delete_symbol"}
	if strings.Join(inv.Contracted, ",") != strings.Join(wantContracted, ",") {
		t.Fatalf("contracted = %v, want %v", inv.Contracted, wantContracted)
	}
	if len(inv.Uncontracted) != 0 {
		t.Fatalf("uncontracted = %v, want none", inv.Uncontracted)
	}
}

func TestScanAntigravityMissingConfig(t *testing.T) {
	_, err := ScanAntigravity("/nonexistent/mcp_config.json", "/nonexistent/mcp", planecontract.MatchMCPTool)
	if err == nil {
		t.Fatal("expected error for nonexistent config path")
	}
}

func TestScanAntigravityInvalidJSON(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "mcp_config.json")
	if err := os.WriteFile(configPath, []byte("not-json"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := ScanAntigravity(configPath, dir, planecontract.MatchMCPTool)
	if err == nil {
		t.Fatal("expected error for invalid json")
	}
}
