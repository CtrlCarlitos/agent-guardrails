package adapter

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/CtrlCarlitos/agent-guardrails/internal/engine"
	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
)

func TestCodexMCPRegistryProjectsBeforePrefixDeny(t *testing.T) {
	pol, err := policy.LoadBase()
	if err != nil {
		t.Fatal(err)
	}
	cwd := t.TempDir()
	for _, tt := range []struct {
		name       string
		tool       string
		args       string
		capability policy.Capability
		paths      []string
		decision   policy.Decision
		rule       string
	}{
		{"mutation", "mcp__serena__replace_symbol_body", `{"relative_path":"src/main.go","body":"x"}`, policy.CapabilityMutation, []string{"src/main.go"}, policy.Allow, ""},
		{"secret mutation", "mcp__serena__replace_symbol_body", `{"relative_path":".env","body":"x"}`, policy.CapabilityMutation, []string{".env"}, policy.Deny, "P4.secret-path"},
		{"alternate server", "mcp__takumi_serena__insert_after_symbol", `{"relative_path":".env"}`, policy.CapabilityMutation, []string{".env"}, policy.Deny, "P4.secret-path"},
		{"bare family", "serena_replace_content", `{"relative_path":".env"}`, policy.CapabilityMutation, []string{".env"}, policy.Deny, "P4.secret-path"},
		{"secret read", "mcp__serena__find_symbol", `{"relative_path":".env"}`, policy.CapabilityReadDiscovery, []string{".env"}, policy.Deny, "P4.secret-path"},
		{"missing path", "mcp__serena__replace_in_files", `{}`, policy.CapabilityMutation, nil, policy.Deny, "capability-input-missing"},
		{"wrong path type", "mcp__serena__replace_in_files", `{"relative_path":[".env"]}`, policy.CapabilityMutation, nil, policy.Deny, "capability-input-missing"},
		{"empty path", "mcp__serena__replace_in_files", `{"relative_path":""}`, policy.CapabilityMutation, nil, policy.Deny, "capability-input-missing"},
		{"memory", "mcp__serena__write_memory", `{"memory_name":"notes"}`, policy.CapabilityMutation, []string{".serena/memories/notes"}, policy.Allow, ""},
		{"memory rename destination", "mcp__serena__rename_memory", `{"memory_name":"notes","new_name":"../../.env"}`, policy.CapabilityMutation, []string{".serena/memories/notes", ".serena/memories/../../.env"}, policy.Deny, "P4.secret-path"},
		{"graft", "mcp__takumi_graft__graft_file_api", `{"file_path":"src/main.go"}`, policy.CapabilityReadDiscovery, []string{"src/main.go"}, policy.Allow, ""},
		{"diagnostics aliases", "mcp__serena__get_diagnostics_for_file", `{"relative_path":"src/main.go","filePath":".env"}`, policy.CapabilityReadDiscovery, []string{"src/main.go", ".env"}, policy.Deny, "P4.secret-path"},
		{"safe control", "mcp__serena__list_memories", `{}`, policy.CapabilitySafeControl, nil, policy.Allow, ""},
		{"external", "mcp__serena__activate_project", `{"project":"other"}`, policy.CapabilityExternal, nil, policy.Ask, "capability-external"},
		{"unknown mcp", "mcp__serena__future_tool", `{}`, policy.CapabilityDeny, nil, policy.Deny, "capability-deny"},
		{"unknown bare", "serena_future_tool", `{}`, policy.CapabilityUnknown, nil, policy.Deny, "unknown-native-tool"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			raw, err := json.Marshal(map[string]any{"session_id": "fixture", "cwd": cwd, "hook_event_name": "PreToolUse", "tool_name": tt.tool, "tool_input": json.RawMessage(tt.args)})
			if err != nil {
				t.Fatal(err)
			}
			tc, err := ParseCodex(bytes.NewReader(raw))
			if err != nil {
				t.Fatal(err)
			}
			if tc.NativeTool != tt.tool || tc.Capability != tt.capability || !reflect.DeepEqual(tc.Paths, tt.paths) || !bytes.Equal(tc.Arguments, json.RawMessage(tt.args)) {
				t.Fatalf("unexpected projection: %+v", tc)
			}
			if (tt.capability == policy.CapabilityMutation || tt.capability == policy.CapabilityReadDiscovery) && tc.InputShape != "path" {
				t.Fatalf("shape %q", tc.InputShape)
			}
			v := engine.Evaluate(tc, pol)
			if v.Decision != tt.decision || v.RuleID != tt.rule {
				t.Fatalf("got %+v, want %s/%s", v, tt.decision, tt.rule)
			}
			var out, guidance bytes.Buffer
			code := EmitCodex(v, "pre", tc, &out, &guidance)
			if tt.decision == policy.Allow && code != 0 || tt.decision != policy.Allow && code != 2 {
				t.Fatalf("unexpected exit %d", code)
			}
			if tt.rule == "P4.secret-path" && !strings.Contains(guidance.String(), "secret-tier") {
				t.Fatal(guidance.String())
			}
		})
	}
}
