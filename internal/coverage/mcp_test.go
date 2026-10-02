package coverage

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/CtrlCarlitos/agent-guardrails/internal/planecontract"
)

// The test binary doubles as a fake stdio MCP server when GUARDRAIL_FAKE_MCP
// is set, so ListMCPToolsStdio is exercised over a real process and pipes.
func TestMain(m *testing.M) {
	if os.Getenv("GUARDRAIL_FAKE_MCP") == "1" {
		fakeMCPServer()
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func fakeMCPServer() {
	tools := strings.Split(os.Getenv("GUARDRAIL_FAKE_MCP_TOOLS"), ",")
	paged := os.Getenv("GUARDRAIL_FAKE_MCP_PAGES") == "2"
	hang := os.Getenv("GUARDRAIL_FAKE_MCP_HANG") == "1"
	in := bufio.NewScanner(os.Stdin)
	in.Buffer(make([]byte, 1<<20), 1<<20)
	out := bufio.NewWriter(os.Stdout)
	reply := func(id json.RawMessage, result any) {
		raw, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": id, "result": result})
		out.Write(append(raw, '\n'))
		out.Flush()
	}
	for in.Scan() {
		if hang {
			continue
		}
		var msg struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
			Params struct {
				Cursor string `json:"cursor"`
			} `json:"params"`
		}
		if json.Unmarshal(in.Bytes(), &msg) != nil {
			continue
		}
		// Noise a real server may write before answering.
		fmt.Fprintln(out, "starting language servers...")
		fmt.Fprintln(out, `{"jsonrpc":"2.0","method":"notifications/message","params":{"level":"info"}}`)
		switch msg.Method {
		case "initialize":
			reply(msg.ID, map[string]any{"protocolVersion": "2025-06-18", "capabilities": map[string]any{"tools": map[string]any{}}})
		case "tools/list":
			list := func(names []string) []map[string]any {
				var l []map[string]any
				for _, n := range names {
					if n != "" {
						l = append(l, map[string]any{"name": n, "inputSchema": map[string]any{"type": "object"}})
					}
				}
				return l
			}
			switch {
			case paged && msg.Params.Cursor == "":
				reply(msg.ID, map[string]any{"tools": list(tools[:1]), "nextCursor": "page2"})
			case paged:
				reply(msg.ID, map[string]any{"tools": list(tools[1:])})
			default:
				reply(msg.ID, map[string]any{"tools": list(tools)})
			}
		}
	}
}

func fakeServer(t *testing.T, name, tools string, extra map[string]string) MCPServerConfig {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	env := map[string]string{"GUARDRAIL_FAKE_MCP": "1", "GUARDRAIL_FAKE_MCP_TOOLS": tools}
	for k, v := range extra {
		env[k] = v
	}
	return MCPServerConfig{Name: name, Command: exe, Env: env}
}

func TestListMCPToolsOverStdio(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	got, err := ListMCPToolsStdio(ctx, fakeServer(t, "serena", "find_symbol,open_dashboard", nil))
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"find_symbol", "open_dashboard"}; !reflect.DeepEqual(got, want) {
		t.Errorf("tools = %v, want %v", got, want)
	}
	paged, err := ListMCPToolsStdio(ctx, fakeServer(t, "graft", "graft_find_code,graft_repo_map,graft_new", map[string]string{"GUARDRAIL_FAKE_MCP_PAGES": "2"}))
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"graft_find_code", "graft_repo_map", "graft_new"}; !reflect.DeepEqual(paged, want) {
		t.Errorf("paged tools = %v, want %v", paged, want)
	}
}

func TestListMCPToolsFailsAsUnknown(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	start := time.Now()
	if _, err := ListMCPToolsStdio(ctx, fakeServer(t, "slow", "x", map[string]string{"GUARDRAIL_FAKE_MCP_HANG": "1"})); err == nil {
		t.Error("a server that never answers was listed")
	}
	if elapsed := time.Since(start); elapsed > 10*time.Second {
		t.Errorf("the timeout was not honoured: %v", elapsed)
	}
	if _, err := ListMCPToolsStdio(context.Background(), MCPServerConfig{Name: "gone", Command: filepath.Join(t.TempDir(), "no-such-server")}); err == nil {
		t.Error("a server that cannot start was listed")
	}
}

func TestReadMCPServersForEachPlane(t *testing.T) {
	dir := t.TempDir()
	project := filepath.Join(dir, "repo")
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	projectKey, _ := json.Marshal(filepath.ToSlash(project))
	claude := write("claude.json", `{"mcpServers":{"serena":{"type":"stdio","command":"uvx","args":["serena"],"env":{"TOKEN":"s3cret"}},"docs":{"type":"http","url":"https://example.test/mcp"}},
		"projects":{`+string(projectKey)+`:{"mcpServers":{"graft":{"command":"graft","args":["mcp"]}}},"/elsewhere":{"mcpServers":{"other":{"command":"x"}}}}}`)
	codex := write("config.toml", "[mcp_servers.serena]\ncommand = \"uvx\"\nargs = [\"serena\"]\n\n[mcp_servers.off]\ncommand = \"x\"\nenabled = false\n\n[mcp_servers.remote]\nurl = \"https://example.test/mcp\"\n")
	opencode := write("opencode.json", `{"mcp":{"serena":{"type":"local","command":["uvx","serena","start"],"environment":{"K":"v"}},"web":{"type":"remote","url":"https://example.test"},"off":{"type":"local","command":["x"],"enabled":false}}}`)

	for _, tc := range []struct {
		plane, path string
		want        []MCPServerConfig
	}{
		{"claude", claude, []MCPServerConfig{
			{Name: "docs", Remote: true},
			{Name: "graft", Command: "graft", Args: []string{"mcp"}},
			{Name: "serena", Command: "uvx", Args: []string{"serena"}, Env: map[string]string{"TOKEN": "s3cret"}},
		}},
		{"codex", codex, []MCPServerConfig{
			{Name: "off", Command: "x", Disabled: true},
			{Name: "remote", Remote: true},
			{Name: "serena", Command: "uvx", Args: []string{"serena"}},
		}},
		{"opencode", opencode, []MCPServerConfig{
			{Name: "off", Command: "x", Args: []string{}, Disabled: true},
			{Name: "serena", Command: "uvx", Args: []string{"serena", "start"}, Env: map[string]string{"K": "v"}},
			{Name: "web", Remote: true},
		}},
	} {
		got, err := ReadMCPServers(tc.plane, tc.path, project)
		if err != nil {
			t.Fatalf("%s: %v", tc.plane, err)
		}
		if !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%s:\n got %+v\nwant %+v", tc.plane, got, tc.want)
		}
	}
	if got, err := ReadMCPServers("codex", filepath.Join(dir, "absent.toml"), ""); err != nil || got != nil {
		t.Errorf("a missing config is empty: %v %v", got, err)
	}
}

// Acceptance (#463): a tool absent from the registry is reported on every
// plane, under that plane's naming; a server that cannot be listed is
// unknown, never covered; and no server secret reaches the output.
func TestScanMCPReportsUncontractedToolsPerPlane(t *testing.T) {
	servers := []MCPServerConfig{
		{Name: "serena", Command: "serena", Env: map[string]string{"API_TOKEN": "s3cret-value"}, Args: []string{"--token", "s3cret-arg"}},
		{Name: "broken", Command: "broken"},
		{Name: "remote", Remote: true},
		{Name: "off", Command: "x", Disabled: true},
	}
	lister := func(_ context.Context, s MCPServerConfig) ([]string, error) {
		if s.Name == "broken" {
			return nil, errors.New("timed out")
		}
		return []string{"find_symbol", "brand_new_tool"}, nil
	}
	for plane, wantNew := range map[string]string{
		"claude":   "mcp__serena__brand_new_tool",
		"codex":    "mcp__serena__brand_new_tool",
		"opencode": "serena_brand_new_tool",
	} {
		inv := ScanMCP(plane, []string{"cfg"}, servers, lister, time.Second, planecontract.MatchMCPTool)
		if !reflect.DeepEqual(inv.Uncontracted, []string{wantNew}) {
			t.Errorf("%s: uncontracted %v, want [%s]", plane, inv.Uncontracted, wantNew)
		}
		if len(inv.Contracted) != 1 || !strings.Contains(inv.Contracted[0], "find_symbol") {
			t.Errorf("%s: contracted %v, want find_symbol", plane, inv.Contracted)
		}
		if _, ok := inv.Unknown["broken"]; !ok {
			t.Errorf("%s: an unlisted server is not reported unknown", plane)
		}
		if _, ok := inv.Unknown["remote"]; !ok {
			t.Errorf("%s: a remote server is not reported unknown", plane)
		}
		text := strings.Join(inv.Describe(), "\n")
		if strings.Contains(text, "off") || strings.Contains(text, "s3cret") {
			t.Errorf("%s: output names a disabled server or a secret:\n%s", plane, text)
		}
		if !strings.Contains(text, wantNew) || !strings.Contains(text, "unknown (tools not listed, not covered): broken") {
			t.Errorf("%s: output lacks the finding:\n%s", plane, text)
		}
	}
}
