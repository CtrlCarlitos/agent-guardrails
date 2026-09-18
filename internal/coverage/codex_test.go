package coverage

import (
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
)

func TestCodexSchemaInventory(t *testing.T) {
	raw := `{"tools":[
 {"type":"function","name":"exec_command","parameters":{},"description":"future_tool"},
 {"type":"namespace","name":"mcp__serena","tools":[{"type":"function","name":"replace_symbol_body","parameters":{}}]},
 {"type":"namespace","name":"mcp__other","tools":[{"type":"function","name":"new_tool","parameters":{}}]},
 {"type":"namespace","name":"web","tools":[{"type":"function","name":"run","parameters":{}}]},
 {"type":"function","name":"new_native","parameters":{}},
 {"type":"web_search"}, {"type":"future_provider_tool"}
 ]}`
	inv, err := ScanCodexSchema(strings.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	want := []CodexSchemaTool{
		{"exec_command", "function", "Bash", policy.CapabilityCommand, "contracted"},
		{"future_provider_tool", "future_provider_tool", "", "", "unsupported-schema"},
		{"mcp__other.new_tool", "function", "mcp__other__new_tool", policy.CapabilityDeny, "mcp-prefix-deny"},
		{"mcp__serena.replace_symbol_body", "function", "mcp__serena__replace_symbol_body", policy.CapabilityMutation, "mcp-registry"},
		{"new_native", "function", "new_native", policy.CapabilityUnknown, "uncontracted"},
		{"web.run", "function", "webrun", policy.CapabilityDeny, "contracted"},
		{"web_search", "web_search", "", "", "hosted-no-local-hook"},
	}
	if !reflect.DeepEqual(inv.Tools, want) {
		t.Fatalf("tools = %#v; want %#v", inv.Tools, want)
	}
	if len(inv.SHA256) != 64 {
		t.Fatalf("digest = %q", inv.SHA256)
	}
	for _, name := range inv.Unobserved {
		if name == "Bash" || name == "web.run" {
			t.Fatalf("observed tool reported unobserved: %s", name)
		}
	}
}

func TestCodexCapturedSchema(t *testing.T) {
	for _, name := range []string{"codex-direct.json", "codex-code-mode.json"} {
		t.Run(name, func(t *testing.T) {
			f, err := os.Open("testdata/" + name)
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			inv, err := ScanCodexSchema(f)
			if err != nil {
				t.Fatal(err)
			}
			rows := map[string]CodexSchemaTool{}
			for _, row := range inv.Tools {
				rows[row.Name] = row
			}
			if name == "codex-code-mode.json" {
				if rows["exec"].Capability != policy.CapabilityDeny || rows["wait"].Capability != policy.CapabilitySafeControl {
					t.Fatalf("code-mode = %#v", rows)
				}
			} else {
				if rows["exec_command"].Hook != "Bash" || rows["web_search"].Status != "hosted-no-local-hook" || rows["multi_agent_v1.spawn_agent"].Capability != policy.CapabilityDelegation {
					t.Fatalf("direct = %#v", rows)
				}
				if rows["multi_agent_v1.wait_agent"].Status != "uncontracted" {
					t.Fatalf("must not silently strip arbitrary namespaces: %#v", rows)
				}
			}
		})
	}
}

func TestCodexSchemaRejectsIncompleteInput(t *testing.T) {
	cases := []string{
		`null`, `{}`, `[]`, `{"tools":null}`, `[{"type":"function","name":"x"}]`,
		`[{"type":"function","name":"x","parameters":{}}] {}`,
		`[{"type":"custom","name":"x","format":[]}]`,
		`[{"type":"namespace","name":"x","tools":[]}]`,
		`[{"type":"namespace","name":"x","tools":[{"type":"namespace","name":"y","tools":[{"type":"web_search"}]}]}]`,
		`[{"type":"function","name":"bad\nname","parameters":{}}]`,
		`[{"type":"web_search"},{"type":"web_search"}]`,
		`[{"type":"namespace","name":"x","tools":[{"type":"function","name":"y","parameters":{}}]},{"type":"function","name":"x.y","parameters":{}}]`,
		strings.Repeat(" ", (8<<20)+1),
	}
	for i, input := range cases {
		if _, err := ScanCodexSchema(strings.NewReader(input)); err == nil {
			t.Errorf("case %d accepted invalid inventory", i)
		}
	}
}
