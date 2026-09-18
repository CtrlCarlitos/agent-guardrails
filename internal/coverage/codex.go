package coverage

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/CtrlCarlitos/agent-guardrails/internal/planecontract"
	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
)

// CodexSchemaInventory describes only the supplied Responses tool schema. It
// cannot establish that other feature configurations or nested tools are covered.
type CodexSchemaInventory struct {
	SHA256     string
	Tools      []CodexSchemaTool
	Unobserved []string
}

// CodexSchemaTool keeps model-facing names separate from hook-facing identities.
// Hosted and unsupported entries never establish local hook coverage.
type CodexSchemaTool struct {
	Name       string
	Kind       string
	Hook       string
	Capability policy.Capability
	Status     string
}

// ScanCodexSchema reads a Responses tools array or a request containing that
// array. Descriptions and parameter properties are never mined for tool names.
// Contract lookup uses the shared native contract and MCP registry, not a copy
// of the set of contracted tools.
func ScanCodexSchema(r io.Reader) (CodexSchemaInventory, error) {
	data, err := io.ReadAll(io.LimitReader(r, (8<<20)+1))
	if err != nil {
		return CodexSchemaInventory{}, err
	}
	if len(data) > 8<<20 {
		return CodexSchemaInventory{}, fmt.Errorf("schema exceeds 8 MiB")
	}
	inv := CodexSchemaInventory{SHA256: fmt.Sprintf("%x", sha256.Sum256(data))}
	raw := bytes.TrimSpace(data)
	if len(raw) > 0 && raw[0] == '{' {
		var request struct {
			Tools json.RawMessage `json:"tools"`
		}
		if err := json.Unmarshal(raw, &request); err != nil {
			return inv, err
		}
		raw = bytes.TrimSpace(request.Tools)
	}
	if len(raw) == 0 || raw[0] != '[' {
		return inv, fmt.Errorf("expected a Responses tools array or an object with tools")
	}
	seen := map[string]bool{}
	var walk func(json.RawMessage, string, int) error
	walk = func(raw json.RawMessage, namespace string, depth int) error {
		if depth > 1 {
			return fmt.Errorf("nested namespaces are not supported")
		}
		var schemas []struct {
			Type       string          `json:"type"`
			Name       string          `json:"name"`
			Tools      json.RawMessage `json:"tools"`
			Parameters json.RawMessage `json:"parameters"`
			Format     json.RawMessage `json:"format"`
		}
		if err := json.Unmarshal(raw, &schemas); err != nil {
			return err
		}
		if len(schemas) == 0 {
			return fmt.Errorf("empty tool inventory")
		}
		for _, schema := range schemas {
			if schema.Type == "namespace" {
				if !codexSchemaIdentifier(schema.Name) || len(schema.Tools) == 0 {
					return fmt.Errorf("namespace requires a name and tools")
				}
				if err := walk(schema.Tools, schema.Name, depth+1); err != nil {
					return err
				}
				continue
			}
			if !codexSchemaIdentifier(schema.Type) {
				return fmt.Errorf("tool requires a valid type")
			}
			name := schema.Name
			if schema.Type == "function" || schema.Type == "custom" {
				if !codexSchemaIdentifier(name) {
					return fmt.Errorf("function/custom tool requires a valid name")
				}
				shape := schema.Parameters
				if schema.Type == "custom" {
					shape = schema.Format
				}
				shape = bytes.TrimSpace(shape)
				if len(shape) == 0 || shape[0] != '{' {
					return fmt.Errorf("tool %q requires its schema object", name)
				}
			} else if name == "" {
				name = schema.Type
			}
			if !codexSchemaIdentifier(name) {
				return fmt.Errorf("invalid tool name")
			}
			qualified := name
			if namespace != "" {
				qualified = namespace + "." + name
			}
			if seen[qualified] {
				return fmt.Errorf("duplicate tool %q", qualified)
			}
			seen[qualified] = true
			row := CodexSchemaTool{Name: qualified, Kind: schema.Type, Status: "unsupported-schema"}
			switch schema.Type {
			case "function", "custom":
				row.Hook = codexSchemaHook(namespace, name)
				spec, known := planecontract.CodexTool(row.Hook)
				if !known || spec.Capability == policy.CapabilityDeny {
					if mcp, ok := planecontract.MatchMCPTool(row.Hook); ok {
						row.Capability, row.Status = mcp.Capability, "mcp-registry"
					}
				}
				if row.Status != "mcp-registry" {
					switch {
					case !known:
						row.Capability, row.Status = policy.CapabilityUnknown, "uncontracted"
					case strings.HasPrefix(row.Hook, "mcp__"):
						row.Capability, row.Status = spec.Capability, "mcp-prefix-deny"
					default:
						row.Capability, row.Status = spec.Capability, "contracted"
					}
				}
			case "web_search", "web_search_preview", "file_search", "image_generation", "code_interpreter", "computer", "computer_use_preview", "mcp":
				row.Status = "hosted-no-local-hook"
			}
			inv.Tools = append(inv.Tools, row)
		}
		return nil
	}
	if err := walk(raw, "", 0); err != nil {
		return inv, err
	}
	observed := map[string]bool{}
	for _, row := range inv.Tools {
		if row.Status == "contracted" {
			spec, _ := planecontract.CodexTool(row.Hook)
			observed[spec.NativeTool] = true
		}
	}
	for _, spec := range planecontract.RegisteredTools("codex") {
		if !observed[spec.NativeTool] {
			inv.Unobserved = append(inv.Unobserved, spec.NativeTool)
		}
	}
	sort.Slice(inv.Tools, func(i, j int) bool { return inv.Tools[i].Name < inv.Tools[j].Name })
	sort.Strings(inv.Unobserved)
	return inv, nil
}

// These projections follow Codex's HookToolName, function_hook_tool_name,
// flat_tool_name and MCP join_tool_name at upstream 7498521. They describe the
// runtime wire identities; they do not add aliases to the enforcement contract.
func codexSchemaHook(namespace, name string) string {
	if strings.HasPrefix(namespace, "mcp__") {
		return strings.TrimRight(namespace, "_") + "__" + strings.TrimLeft(name, "_")
	}
	if namespace == "" || namespace == "functions" {
		switch name {
		case "exec_command", "shell", "shell_command":
			return "Bash"
		default:
			return name
		}
	}
	if namespace == "multi_agent_v1" && name == "spawn_agent" {
		return "spawn_agent"
	}
	return namespace + name
}

func codexSchemaIdentifier(s string) bool {
	if s == "" || len(s) > 256 {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-' || c == '.') {
			return false
		}
	}
	return true
}
