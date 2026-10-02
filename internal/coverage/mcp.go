package coverage

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/BurntSushi/toml"

	"github.com/CtrlCarlitos/agent-guardrails/internal/planecontract"
)

// MCP coverage for the planes whose hosts do not cache tool schemas on disk
// (#463). Antigravity's doctor reads its cached schemas; Claude Code, Codex
// and OpenCode only learn a server's tools by asking it. So this starts each
// configured stdio server the way the host would, runs MCP `initialize` and
// `tools/list`, stops it, and diffs the names against the registry in
// internal/planecontract/mcp.go under the plane's own tool naming.
//
// A server that cannot be started or listed in time, or a remote (URL) one,
// is reported as unknown, never as covered. Server arguments and environment
// can hold tokens: nothing from them is printed, only server and tool names.

// MCPServerConfig is one configured MCP server.
type MCPServerConfig struct {
	Name     string
	Command  string
	Args     []string
	Env      map[string]string
	Remote   bool // a URL transport; not launched
	Disabled bool
}

// MCPInventory is what the scan of one plane's MCP servers established.
type MCPInventory struct {
	Plane        string
	ConfigPaths  []string
	Servers      []string            // configured, enabled server names, sorted
	ServerTools  map[string][]string // server -> plane-named tools, sorted
	Unknown      map[string]string   // server -> why its tools are unknown
	Runtime      []string            // every listed tool, plane-named, sorted
	Contracted   []string
	Uncontracted []string
}

// MCPToolName is the name a plane gives an MCP server's tool, as its hooks
// see it: `mcp__<server>__<tool>` for Claude Code and Codex, and
// `<server>_<tool>` for OpenCode.
func MCPToolName(plane, server, tool string) string {
	if plane == "opencode" {
		return server + "_" + tool
	}
	return "mcp__" + server + "__" + tool
}

// MCPConfigPaths are the files a plane reads its MCP servers from.
func MCPConfigPaths(plane string) ([]string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	switch plane {
	case "claude":
		return []string{filepath.Join(home, ".claude.json")}, nil
	case "codex":
		dir := os.Getenv("CODEX_HOME")
		if dir == "" {
			dir = filepath.Join(home, ".codex")
		}
		return []string{filepath.Join(dir, "config.toml")}, nil
	case "opencode":
		base := os.Getenv("XDG_CONFIG_HOME")
		if base == "" {
			base = filepath.Join(home, ".config")
		}
		return []string{filepath.Join(base, "opencode", "opencode.json")}, nil
	}
	return nil, fmt.Errorf("no MCP configuration known for plane %q", plane)
}

// ReadMCPServers reads a plane's MCP server configuration from path. A
// missing file is an empty configuration. For Claude Code, project is the
// directory whose project-scoped servers also apply ("" for none).
func ReadMCPServers(plane, path, project string) ([]MCPServerConfig, error) {
	raw, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("cannot read %q: %w", path, err)
	}
	if len(strings.TrimSpace(string(raw))) == 0 {
		return nil, nil
	}
	switch plane {
	case "claude":
		return readClaudeMCP(raw, project)
	case "codex":
		return readCodexMCP(raw)
	case "opencode":
		return readOpencodeMCP(raw)
	}
	return nil, fmt.Errorf("no MCP configuration known for plane %q", plane)
}

type claudeMCPServer struct {
	Type    string            `json:"type"`
	Command string            `json:"command"`
	Args    []string          `json:"args"`
	Env     map[string]string `json:"env"`
	URL     string            `json:"url"`
}

func readClaudeMCP(raw []byte, project string) ([]MCPServerConfig, error) {
	var doc struct {
		MCPServers map[string]claudeMCPServer `json:"mcpServers"`
		Projects   map[string]struct {
			MCPServers map[string]claudeMCPServer `json:"mcpServers"`
		} `json:"projects"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("parsing Claude Code configuration: %w", err)
	}
	servers := map[string]claudeMCPServer{}
	for name, s := range doc.MCPServers {
		servers[name] = s
	}
	if project != "" {
		for dir, p := range doc.Projects {
			if sameDirectory(dir, project) {
				for name, s := range p.MCPServers {
					servers[name] = s // a project server shadows a user one
				}
			}
		}
	}
	var out []MCPServerConfig
	for name, s := range servers {
		out = append(out, MCPServerConfig{Name: name, Command: s.Command, Args: s.Args, Env: s.Env,
			Remote: s.URL != "" || s.Type == "http" || s.Type == "sse"})
	}
	return sortedServers(out), nil
}

func readCodexMCP(raw []byte) ([]MCPServerConfig, error) {
	var doc struct {
		MCPServers map[string]struct {
			Command string            `toml:"command"`
			Args    []string          `toml:"args"`
			Env     map[string]string `toml:"env"`
			URL     string            `toml:"url"`
			Enabled *bool             `toml:"enabled"`
		} `toml:"mcp_servers"`
	}
	if _, err := toml.Decode(string(raw), &doc); err != nil {
		return nil, fmt.Errorf("parsing Codex configuration: %w", err)
	}
	var out []MCPServerConfig
	for name, s := range doc.MCPServers {
		out = append(out, MCPServerConfig{Name: name, Command: s.Command, Args: s.Args, Env: s.Env,
			Remote: s.URL != "", Disabled: s.Enabled != nil && !*s.Enabled})
	}
	return sortedServers(out), nil
}

func readOpencodeMCP(raw []byte) ([]MCPServerConfig, error) {
	var doc struct {
		MCP map[string]struct {
			Type        string            `json:"type"`
			Command     []string          `json:"command"`
			Environment map[string]string `json:"environment"`
			URL         string            `json:"url"`
			Enabled     *bool             `json:"enabled"`
		} `json:"mcp"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("parsing OpenCode configuration: %w", err)
	}
	var out []MCPServerConfig
	for name, s := range doc.MCP {
		server := MCPServerConfig{Name: name, Env: s.Environment, Remote: s.Type == "remote" || s.URL != "",
			Disabled: s.Enabled != nil && !*s.Enabled}
		if len(s.Command) > 0 {
			server.Command, server.Args = s.Command[0], s.Command[1:]
		}
		out = append(out, server)
	}
	return sortedServers(out), nil
}

func sortedServers(servers []MCPServerConfig) []MCPServerConfig {
	sort.Slice(servers, func(i, j int) bool { return servers[i].Name < servers[j].Name })
	return servers
}

func sameDirectory(a, b string) bool {
	clean := func(p string) string { return strings.ToLower(filepath.Clean(filepath.FromSlash(p))) }
	return clean(a) == clean(b)
}

// MCPToolLister lists one server's tool names.
type MCPToolLister func(ctx context.Context, server MCPServerConfig) ([]string, error)

// ScanMCP inventories a plane's servers with lister, each bounded by timeout.
func ScanMCP(plane string, configPaths []string, servers []MCPServerConfig, lister MCPToolLister, timeout time.Duration,
	matchRegistry func(string) (planecontract.MCPToolSpec, bool)) MCPInventory {
	inv := MCPInventory{Plane: plane, ConfigPaths: append([]string{}, configPaths...), ServerTools: map[string][]string{}, Unknown: map[string]string{}}
	toolSet := map[string]bool{}
	for _, server := range servers {
		if server.Disabled {
			continue
		}
		inv.Servers = append(inv.Servers, server.Name)
		if server.Remote {
			inv.Unknown[server.Name] = "remote server; not listed"
			continue
		}
		if server.Command == "" {
			inv.Unknown[server.Name] = "no command configured"
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		tools, err := lister(ctx, server)
		cancel()
		if err != nil {
			inv.Unknown[server.Name] = "could not list tools: " + err.Error()
			continue
		}
		var named []string
		for _, tool := range tools {
			if !isValidToolName(tool) {
				continue
			}
			name := MCPToolName(plane, server.Name, tool)
			named = append(named, name)
			toolSet[name] = true
		}
		sort.Strings(named)
		inv.ServerTools[server.Name] = named
	}
	sort.Strings(inv.Servers)
	for tool := range toolSet {
		inv.Runtime = append(inv.Runtime, tool)
		if _, ok := matchRegistry(tool); ok {
			inv.Contracted = append(inv.Contracted, tool)
		} else {
			inv.Uncontracted = append(inv.Uncontracted, tool)
		}
	}
	sort.Strings(inv.Runtime)
	sort.Strings(inv.Contracted)
	sort.Strings(inv.Uncontracted)
	return inv
}

// Describe renders the inventory as doctor lines. Only server and tool names
// appear: a server's arguments and environment are never printed.
func (inv MCPInventory) Describe() []string {
	var lines []string
	if len(inv.Servers) == 0 {
		lines = append(lines, "configured MCP servers: none")
	} else {
		lines = append(lines, "configured MCP servers: "+strings.Join(inv.Servers, ", "))
	}
	lines = append(lines, fmt.Sprintf("listed MCP tools: %d (%d in registry, %d uncontracted)",
		len(inv.Runtime), len(inv.Contracted), len(inv.Uncontracted)))
	if len(inv.Uncontracted) == 0 {
		lines = append(lines, "uncontracted (absent from registry): none")
	} else {
		lines = append(lines, "uncontracted (absent from registry): "+strings.Join(inv.Uncontracted, ", "))
	}
	var unknown []string
	for server := range inv.Unknown {
		unknown = append(unknown, server)
	}
	sort.Strings(unknown)
	for _, server := range unknown {
		lines = append(lines, "unknown (tools not listed, not covered): "+server+" ("+inv.Unknown[server]+")")
	}
	return lines
}

// ListMCPToolsStdio starts a stdio MCP server, runs initialize and tools/list
// (following pagination), and stops it. The context bounds the whole exchange.
func ListMCPToolsStdio(ctx context.Context, server MCPServerConfig) ([]string, error) {
	cmd := exec.CommandContext(ctx, server.Command, server.Args...)
	cmd.Env = os.Environ()
	for k, v := range server.Env {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	cmd.Stderr = io.Discard
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, errors.New("server did not start")
	}
	defer func() {
		_ = stdin.Close()
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		_ = cmd.Wait()
	}()

	type result struct {
		tools []string
		err   error
	}
	done := make(chan result, 1)
	go func() {
		tools, err := mcpExchange(stdin, bufio.NewReaderSize(stdout, 1<<20))
		done <- result{tools, err}
	}()
	select {
	case r := <-done:
		return r.tools, r.err
	case <-ctx.Done():
		return nil, errors.New("timed out")
	}
}

func mcpExchange(w io.Writer, r *bufio.Reader) ([]string, error) {
	send := func(msg map[string]any) error {
		raw, err := json.Marshal(msg)
		if err != nil {
			return err
		}
		_, err = w.Write(append(raw, '\n'))
		return err
	}
	if err := send(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": map[string]any{
		"protocolVersion": "2025-06-18", "capabilities": map[string]any{},
		"clientInfo": map[string]any{"name": "guardrail-doctor", "version": "1"},
	}}); err != nil {
		return nil, err
	}
	if _, err := awaitResponse(r, 1); err != nil {
		return nil, fmt.Errorf("initialize: %w", err)
	}
	if err := send(map[string]any{"jsonrpc": "2.0", "method": "notifications/initialized"}); err != nil {
		return nil, err
	}
	var tools []string
	cursor := ""
	for id := 2; id < 102; id++ {
		params := map[string]any{}
		if cursor != "" {
			params["cursor"] = cursor
		}
		if err := send(map[string]any{"jsonrpc": "2.0", "id": id, "method": "tools/list", "params": params}); err != nil {
			return nil, err
		}
		raw, err := awaitResponse(r, id)
		if err != nil {
			return nil, fmt.Errorf("tools/list: %w", err)
		}
		var page struct {
			Tools []struct {
				Name string `json:"name"`
			} `json:"tools"`
			NextCursor string `json:"nextCursor"`
		}
		if err := json.Unmarshal(raw, &page); err != nil {
			return nil, fmt.Errorf("tools/list: %w", err)
		}
		for _, t := range page.Tools {
			tools = append(tools, t.Name)
		}
		if page.NextCursor == "" {
			return tools, nil
		}
		cursor = page.NextCursor
	}
	return nil, errors.New("tools/list: too many pages")
}

// awaitResponse reads lines until the response with id arrives, skipping
// notifications, requests and non-JSON log lines a server may write.
func awaitResponse(r *bufio.Reader, id int) (json.RawMessage, error) {
	for {
		line, err := r.ReadBytes('\n')
		if len(line) > 0 {
			var msg struct {
				ID     *json.RawMessage `json:"id"`
				Result json.RawMessage  `json:"result"`
				Error  *struct {
					Message string `json:"message"`
				} `json:"error"`
				Method string `json:"method"`
			}
			if json.Unmarshal(line, &msg) == nil && msg.ID != nil && msg.Method == "" && string(*msg.ID) == fmt.Sprint(id) {
				if msg.Error != nil {
					return nil, errors.New("server error")
				}
				return msg.Result, nil
			}
		}
		if err != nil {
			return nil, errors.New("server closed the connection")
		}
	}
}
