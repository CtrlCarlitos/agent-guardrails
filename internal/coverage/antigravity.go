package coverage

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/CtrlCarlitos/agent-guardrails/internal/planecontract"
)

// AntigravityInventory is what the scan of Antigravity MCP configuration
// and schemas established.
type AntigravityInventory struct {
	ConfigPaths  []string            // ordered mcp_config.json sources
	SchemasDir   string              // path to schema directory
	Servers      []string            // configured server names, sorted
	ServerTools  map[string][]string // server -> tool names discovered, sorted
	Runtime      []string            // all discovered MCP tools, sorted
	Contracted   []string            // tools recognized by the registry, sorted
	Uncontracted []string            // tools absent from the registry, sorted
}

// AntigravityConfigPath resolves the default path to Antigravity's mcp_config.json.
func AntigravityConfigPath() (string, error) {
	paths, err := AntigravityConfigPaths()
	if err != nil {
		return "", err
	}
	return paths[0], nil
}

// AntigravityConfigPaths resolves Antigravity's effective MCP configuration:
// the global (or legacy CLI) file followed by every plugin bundle. The primary
// path remains in the result when absent so doctor can name what it checked;
// default scanning treats that absence as an empty configuration.
func AntigravityConfigPaths() ([]string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	primary := filepath.Join(home, ".gemini", "config", "mcp_config.json")
	legacy := filepath.Join(home, ".gemini", "antigravity-cli", "mcp_config.json")
	paths := []string{primary}
	if _, err := os.Stat(primary); err != nil {
		if !os.IsNotExist(err) {
			return nil, err
		}
		if _, err := os.Stat(legacy); err == nil {
			paths[0] = legacy
		} else if !os.IsNotExist(err) {
			return nil, err
		}
	}
	plugins, err := filepath.Glob(filepath.Join(home, ".gemini", "config", "plugins", "*", "mcp_config.json"))
	if err != nil {
		return nil, err
	}
	sort.Strings(plugins)
	return append(paths, plugins...), nil
}

// AntigravitySchemasDir resolves the default directory where Antigravity stores MCP tool schemas.
func AntigravitySchemasDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	p := filepath.Join(home, ".gemini", "antigravity-cli", "mcp")
	if _, err := os.Stat(p); err == nil {
		return p, nil
	}
	alt := filepath.Join(home, ".gemini", "config", "mcp")
	if _, err := os.Stat(alt); err == nil {
		return alt, nil
	}
	return p, nil
}

func isValidToolName(name string) bool {
	if len(name) == 0 {
		return false
	}
	for i, r := range name {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || r == '_' {
			continue
		}
		if i > 0 && (r >= '0' && r <= '9' || r == '-') {
			continue
		}
		return false
	}
	return true
}

// ScanAntigravity reads Antigravity's mcp_config.json and scans MCP tool schemas
// for each configured server, checking them against matchRegistry.
func ScanAntigravity(configPath, schemasDir string, matchRegistry func(string) (planecontract.MCPToolSpec, bool)) (AntigravityInventory, error) {
	return scanAntigravityConfigs([]string{configPath}, schemasDir, matchRegistry, false)
}

// ScanAntigravityConfigs scans the union of Antigravity's default optional
// config sources. Missing files and empty files mean that source contributes
// no servers; malformed non-empty JSON remains an error.
func ScanAntigravityConfigs(configPaths []string, schemasDir string, matchRegistry func(string) (planecontract.MCPToolSpec, bool)) (AntigravityInventory, error) {
	return scanAntigravityConfigs(configPaths, schemasDir, matchRegistry, true)
}

func scanAntigravityConfigs(configPaths []string, schemasDir string, matchRegistry func(string) (planecontract.MCPToolSpec, bool), optional bool) (AntigravityInventory, error) {
	serverConfigs := map[string][]any{}
	for _, configPath := range configPaths {
		raw, err := os.ReadFile(configPath)
		if os.IsNotExist(err) && optional {
			continue
		}
		if err != nil {
			return AntigravityInventory{}, fmt.Errorf("cannot read config %q: %w", configPath, err)
		}
		if len(strings.TrimSpace(string(raw))) == 0 {
			continue
		}
		var doc struct {
			MCPServers map[string]any `json:"mcpServers"`
		}
		if err := json.Unmarshal(raw, &doc); err != nil {
			return AntigravityInventory{}, fmt.Errorf("parsing %q: %w", configPath, err)
		}
		for server, config := range doc.MCPServers {
			serverConfigs[server] = append(serverConfigs[server], config)
		}
	}

	inv := AntigravityInventory{
		ConfigPaths: append([]string{}, configPaths...),
		SchemasDir:  schemasDir,
		ServerTools: map[string][]string{},
	}

	for server := range serverConfigs {
		inv.Servers = append(inv.Servers, server)
	}
	sort.Strings(inv.Servers)

	toolSet := map[string]bool{}

	for _, server := range inv.Servers {
		var serverTools []string
		toolMap := map[string]bool{}
		addTool := func(name string) {
			name = strings.TrimSpace(name)
			if isValidToolName(name) && !toolMap[name] {
				toolMap[name] = true
				serverTools = append(serverTools, name)
				toolSet[name] = true
			}
		}

		// Check if config entry explicitly declares tools
		for _, config := range serverConfigs[server] {
			if serverVal, ok := config.(map[string]any); ok {
				if toolsList, ok := serverVal["tools"].([]any); ok {
					for _, item := range toolsList {
						switch t := item.(type) {
						case string:
							addTool(t)
						case map[string]any:
							if name, ok := t["name"].(string); ok {
								addTool(name)
							}
						}
					}
				}
			}
		}

		serverDir := filepath.Join(schemasDir, server)
		entries, err := os.ReadDir(serverDir)
		if err == nil {
			for _, e := range entries {
				if e.IsDir() {
					continue
				}
				name := e.Name()
				if strings.HasSuffix(name, ".json") {
					toolName := strings.TrimSuffix(name, ".json")
					addTool(toolName)
				}
			}
		}

		// Check if server directory contains an instructions.md declaring tool bullets (e.g. graft)
		if mdBytes, err := os.ReadFile(filepath.Join(serverDir, "instructions.md")); err == nil {
			for _, line := range strings.Split(string(mdBytes), "\n") {
				line = strings.TrimSpace(line)
				if strings.HasPrefix(line, "- ") || strings.HasPrefix(line, "* ") {
					toolDef := strings.TrimSpace(line[2:])
					for _, sep := range []string{" ", "—", "-", ":", "\t"} {
						if idx := strings.Index(toolDef, sep); idx != -1 {
							toolDef = toolDef[:idx]
						}
					}
					toolDef = strings.Trim(toolDef, "`*_")
					addTool(toolDef)
				}
			}
		}

		sort.Strings(serverTools)
		inv.ServerTools[server] = serverTools
	}

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

	return inv, nil
}

// Describe renders the inventory as doctor lines.
func (inv AntigravityInventory) Describe() []string {
	var lines []string
	if len(inv.Servers) > 0 {
		lines = append(lines, fmt.Sprintf("configured MCP servers: %s", strings.Join(inv.Servers, ", ")))
	} else {
		lines = append(lines, "configured MCP servers: none")
	}
	lines = append(lines, fmt.Sprintf("declared MCP tools: %d (%d in registry, %d uncontracted)",
		len(inv.Runtime), len(inv.Contracted), len(inv.Uncontracted)))
	if len(inv.Uncontracted) == 0 {
		lines = append(lines, "uncontracted (absent from registry): none")
	} else {
		lines = append(lines, "uncontracted (absent from registry): "+strings.Join(inv.Uncontracted, ", "))
	}
	return lines
}
