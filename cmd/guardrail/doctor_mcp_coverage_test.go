package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/CtrlCarlitos/agent-guardrails/internal/coverage"
)

// #463: `doctor --coverage <plane> --mcp` inventories the MCP tools Claude
// Code, Codex and OpenCode would see, which only Antigravity's coverage did.

func fakeMCPLister(t *testing.T, tools map[string][]string) {
	t.Helper()
	old := mcpToolLister
	t.Cleanup(func() { mcpToolLister = old })
	mcpToolLister = func(_ context.Context, s coverage.MCPServerConfig) ([]string, error) {
		if list, ok := tools[s.Name]; ok {
			return list, nil
		}
		return nil, errors.New("timed out")
	}
}

func writeConfig(t *testing.T, name, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestDoctorMCPCoverageReportsUncontractedToolsOnEachPlane(t *testing.T) {
	fakeMCPLister(t, map[string][]string{"serena": {"find_symbol", "brand_new_tool"}})
	for _, tc := range []struct {
		plane, file, body, want string
	}{
		{"claude", "claude.json", `{"mcpServers":{"serena":{"command":"uvx","env":{"TOKEN":"s3cret"}}}}`, "mcp__serena__brand_new_tool"},
		{"codex", "config.toml", "[mcp_servers.serena]\ncommand = \"uvx\"\nenv = { TOKEN = \"s3cret\" }\n", "mcp__serena__brand_new_tool"},
		{"opencode", "opencode.json", `{"mcp":{"serena":{"type":"local","command":["uvx"],"environment":{"TOKEN":"s3cret"}}}}`, "serena_brand_new_tool"},
	} {
		var out, errb bytes.Buffer
		code := run([]string{"doctor", "--coverage", tc.plane, "--mcp", "--config", writeConfig(t, tc.file, tc.body)}, strings.NewReader(""), &out, &errb)
		if code != 1 {
			t.Errorf("%s: exit %d, want 1 (an uncontracted tool); stderr %q", tc.plane, code, errb.String())
		}
		if !strings.Contains(out.String(), "uncontracted (absent from registry): "+tc.want) {
			t.Errorf("%s: output lacks %s:\n%s", tc.plane, tc.want, out.String())
		}
		if strings.Contains(out.String(), "s3cret") {
			t.Errorf("%s: a server secret reached the output", tc.plane)
		}
	}
}

func TestDoctorMCPCoverageReportsUnlistedServersAsUnknown(t *testing.T) {
	fakeMCPLister(t, map[string][]string{"serena": {"find_symbol"}})
	var out, errb bytes.Buffer
	cfg := writeConfig(t, "opencode.json", `{"mcp":{"serena":{"type":"local","command":["uvx"]},"slow":{"type":"local","command":["x"]}}}`)
	code := run([]string{"doctor", "--coverage", "opencode", "--mcp", "--config", cfg}, strings.NewReader(""), &out, &errb)
	if code != 1 || !strings.Contains(out.String(), "unknown (tools not listed, not covered): slow") {
		t.Errorf("exit %d; an unlisted server must be reported unknown and counted:\n%s", code, out.String())
	}
	fakeMCPLister(t, map[string][]string{"serena": {"find_symbol"}})
	out.Reset()
	cfg = writeConfig(t, "opencode.json", `{"mcp":{"serena":{"type":"local","command":["uvx"]}}}`)
	if code := run([]string{"doctor", "--coverage", "opencode", "--mcp", "--config", cfg}, strings.NewReader(""), &out, &errb); code != 0 {
		t.Errorf("all tools contracted: exit %d, want 0:\n%s", code, out.String())
	}
}

func TestDoctorMCPFlagCombinations(t *testing.T) {
	for _, args := range [][]string{
		{"doctor", "--mcp"},
		{"doctor", "--coverage", "antigravity", "--mcp"},
		{"doctor", "--coverage", "opencode"},
		{"doctor", "--coverage", "claude", "--mcp", "--bundle", "cli.js"},
	} {
		var out, errb bytes.Buffer
		if code := run(args, strings.NewReader(""), &out, &errb); code != 2 {
			t.Errorf("%v: exit %d, want 2 (usage error); stderr %q", args, code, errb.String())
		}
	}
	// --mcp lifts Codex's --schema requirement.
	fakeMCPLister(t, map[string][]string{})
	var out, errb bytes.Buffer
	if code := run([]string{"doctor", "--coverage", "codex", "--mcp", "--config", writeConfig(t, "config.toml", "")}, strings.NewReader(""), &out, &errb); code != 0 {
		t.Errorf("codex --mcp without --schema: exit %d; stderr %q", code, errb.String())
	}
}
