package adapter

import (
	"bytes"
	"encoding/json"
	"os/exec"
	"runtime"
	"strings"
	"testing"

	"github.com/CtrlCarlitos/agent-guardrails/internal/engine"
	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
)

func codexEnvelope(tool string, input any) string {
	raw, _ := json.Marshal(map[string]any{"session_id": "fixture", "cwd": "/repo", "hook_event_name": "PreToolUse", "tool_name": tool, "tool_input": input})
	return string(raw)
}

func TestCodexNativeProjection(t *testing.T) {
	cases := []struct {
		tool       string
		input      any
		capability policy.Capability
		command    string
		paths      string
	}{
		{"Bash", map[string]any{"command": "ls"}, policy.CapabilityCommand, "ls", ""},
		{"apply_patch", map[string]any{"command": "*** Begin Patch\n*** Update File: src/a.txt\n*** Move to: .env\n@@\n-old\n+new\n*** End Patch"}, policy.CapabilityMutation, "", "/repo/src/a.txt,/repo/.env"},
		{"view_image", map[string]any{"path": "image.png"}, policy.CapabilityReadDiscovery, "", "image.png"},
		{"spawn_agent", map[string]any{"message": "work"}, policy.CapabilityDelegation, "", ""},
		{"collaboration.spawn_agent", map[string]any{"message": "work"}, policy.CapabilityDelegation, "", ""},
		{"collaboration.send_message", map[string]any{"message": "hello"}, policy.CapabilityDelegation, "", ""},
		{"collaboration.resume_agent", map[string]any{"agent_id": "a1"}, policy.CapabilityDelegation, "", ""},
		{"mcp__server__read", map[string]any{}, policy.CapabilityDeny, "", ""},
		{"future_tool", map[string]any{}, policy.CapabilityUnknown, "", ""},
	}
	for _, tt := range cases {
		t.Run(tt.tool, func(t *testing.T) {
			tc, err := ParseCodex(strings.NewReader(codexEnvelope(tt.tool, tt.input)))
			if err != nil {
				t.Fatal(err)
			}
			if tc.Plane != "codex" || tc.Capability != tt.capability || tc.Command != tt.command || strings.Join(tc.Paths, ",") != tt.paths {
				t.Fatalf("%+v", tc)
			}
		})
	}
}

func TestCodexMalformedFailsClosed(t *testing.T) {
	for _, raw := range []string{"null", "{}", `[]`, codexEnvelope("Bash", nil), codexEnvelope("Bash", map[string]any{"command": 12}), codexEnvelope("apply_patch", map[string]any{"command": "garbage"}), strings.Replace(codexEnvelope("Bash", map[string]any{"command": "ls"}), "PreToolUse", "UnknownEvent", 1)} {
		if _, err := ParseCodex(strings.NewReader(raw)); err == nil {
			t.Fatalf("accepted %s", raw)
		}
	}
}

func TestCodexUnknownCannotBeWaivedByAuditPosture(t *testing.T) {
	tc, err := ParseCodex(strings.NewReader(codexEnvelope("future_tool", map[string]any{})))
	if err != nil {
		t.Fatal(err)
	}
	if v := engine.Evaluate(tc, &policy.Policy{}); v.Decision != policy.Deny {
		t.Fatalf("unknown allowed: %+v", v)
	}
}

func TestCodexCollaborationSpawnAgentIsDelegationNotUnknown(t *testing.T) {
	for _, tool := range []string{"collaboration.spawn_agent", "collaboration.send_message", "collaboration.resume_agent"} {
		tc, err := ParseCodex(strings.NewReader(codexEnvelope(tool, map[string]any{"message": "work"})))
		if err != nil {
			t.Fatal(err)
		}
		if tc.Capability != policy.CapabilityDelegation {
			t.Fatalf("%s capability = %q, want delegation", tool, tc.Capability)
		}
		v := engine.Evaluate(tc, &policy.Policy{})
		if v.Decision != policy.Deny || v.RuleID != "capability-delegation-unverified" {
			t.Fatalf("%s verdict = %+v, want deny/capability-delegation-unverified", tool, v)
		}
		if v.RuleID == "unknown-native-tool" {
			t.Fatalf("%s still unknown-native-tool", tool)
		}
	}
}

func TestCodexEmitNeverReturnsUnsupportedAsk(t *testing.T) {
	for _, decision := range []policy.Decision{policy.Allow, policy.Ask, policy.Deny, policy.Complete} {
		var out, errb bytes.Buffer
		code := EmitCodex(policy.Verdict{Decision: decision, Reason: "reason", RequestID: "req-1", ApprovalURL: "http://localhost/approve"}, "pre", engine.ToolCall{}, &out, &errb)
		if out.Len() != 0 {
			t.Fatalf("unexpected native JSON: %s", out.String())
		}
		if decision == policy.Allow {
			if code != 0 {
				t.Fatal(code)
			}
		} else if code != 2 || errb.Len() == 0 {
			t.Fatalf("%s: %d %s", decision, code, errb.String())
		}
		if decision == policy.Ask && !strings.Contains(errb.String(), "cannot request approval") {
			t.Fatal(errb.String())
		}
		if decision == policy.Complete && !strings.Contains(errb.String(), "req-1") {
			t.Fatal(errb.String())
		}
	}
}

func TestCodexAllowedShellGuardsActualDirectory(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows command hooks fail closed until Codex identifies the runtime shell")
	}
	cwd := t.TempDir()
	tc := engine.ToolCall{Capability: policy.CapabilityCommand, Command: "printf original-command", CWD: cwd}
	var out, errb bytes.Buffer
	if code := EmitCodex(policy.Verdict{Decision: policy.Allow}, "pre", tc, &out, &errb); code != 0 {
		t.Fatalf("%d %s", code, errb.String())
	}
	var payload struct {
		Output struct {
			Input struct {
				Command string `json:"command"`
			} `json:"updatedInput"`
		} `json:"hookSpecificOutput"`
	}
	if err := json.Unmarshal(out.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{cwd, t.TempDir()} {
		cmd := exec.Command("sh", "-c", payload.Output.Input.Command)
		cmd.Dir = dir
		output, err := cmd.CombinedOutput()
		if dir == cwd {
			if err != nil || string(output) != "original-command" {
				t.Fatalf("same directory: %v %s", err, output)
			}
		} else if err == nil || strings.Contains(string(output), "original-command") || !strings.Contains(string(output), "workdir differs") {
			t.Fatalf("other directory: %v %s", err, output)
		}
	}
}

func TestCodexAllowedShellFailsClosedWhenRuntimeShellUnknown(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows-only shell boundary")
	}
	tc := engine.ToolCall{Capability: policy.CapabilityCommand, Command: "Write-Output original-command", CWD: t.TempDir()}
	var out, errb bytes.Buffer
	if code := EmitCodex(policy.Verdict{Decision: policy.Allow}, "pre", tc, &out, &errb); code != 2 {
		t.Fatalf("exit %d, want 2; stdout=%q stderr=%q", code, out.String(), errb.String())
	}
	if out.Len() != 0 || !strings.Contains(errb.String(), "cannot prove the Windows command shell") {
		t.Fatalf("stdout=%q stderr=%q", out.String(), errb.String())
	}
}
