package adapter

import (
	"bytes"
	"encoding/json"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/CtrlCarlitos/agent-guardrails/internal/engine"
	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
)

func codexEnvelope(cwd, tool string, input any) string {
	raw, _ := json.Marshal(map[string]any{"session_id": "fixture", "cwd": cwd, "hook_event_name": "PreToolUse", "tool_name": tool, "tool_input": input})
	return string(raw)
}

func TestCodexNativeProjection(t *testing.T) {
	cwd := t.TempDir()
	cases := []struct {
		tool       string
		input      any
		capability policy.Capability
		command    string
		paths      string
	}{
		{"Bash", map[string]any{"command": "ls"}, policy.CapabilityCommand, "ls", ""},
		{"apply_patch", map[string]any{"command": "*** Begin Patch\n*** Update File: src/a.txt\n*** Move to: .env\n@@\n-old\n+new\n*** End Patch"}, policy.CapabilityMutation, "", strings.Join([]string{filepath.Join(cwd, "src", "a.txt"), filepath.Join(cwd, ".env")}, ",")},
		{"view_image", map[string]any{"path": "image.png"}, policy.CapabilityReadDiscovery, "", "image.png"},
		{"spawn_agent", map[string]any{"message": "work"}, policy.CapabilityDelegation, "", ""},
		{"mcp__server__read", map[string]any{}, policy.CapabilityDeny, "", ""},
		{"future_tool", map[string]any{}, policy.CapabilityUnknown, "", ""},
	}
	for _, tt := range cases {
		t.Run(tt.tool, func(t *testing.T) {
			tc, err := ParseCodex(strings.NewReader(codexEnvelope(cwd, tt.tool, tt.input)))
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
	cwd := t.TempDir()
	for _, raw := range []string{"null", "{}", `[]`, codexEnvelope(cwd, "Bash", nil), codexEnvelope(cwd, "Bash", map[string]any{"command": 12}), codexEnvelope(cwd, "apply_patch", map[string]any{"command": "garbage"}), strings.Replace(codexEnvelope(cwd, "Bash", map[string]any{"command": "ls"}), "PreToolUse", "UnknownEvent", 1)} {
		if _, err := ParseCodex(strings.NewReader(raw)); err == nil {
			t.Fatalf("accepted %s", raw)
		}
	}
}

func TestCodexUnknownCannotBeWaivedByAuditPosture(t *testing.T) {
	tc, err := ParseCodex(strings.NewReader(codexEnvelope(t.TempDir(), "future_tool", map[string]any{})))
	if err != nil {
		t.Fatal(err)
	}
	if v := engine.Evaluate(tc, &policy.Policy{}); v.Decision != policy.Deny {
		t.Fatalf("unknown allowed: %+v", v)
	}
}

func TestCodexRetainsDeclaredNormalizedAndContractIdentities(t *testing.T) {
	for _, tt := range []struct {
		name, declared, normalized, matched string
	}{
		{"alias", "functions__exec", "functions.exec", "functions.exec"},
		{"canonical", "Bash", "Bash", "Bash"},
		{"unknown", "future_tool", "future_tool", ""},
	} {
		t.Run(tt.name, func(t *testing.T) {
			tc, err := ParseCodex(strings.NewReader(codexEnvelope(t.TempDir(), tt.declared, map[string]any{"command": "ls"})))
			if err != nil {
				t.Fatal(err)
			}
			if tc.NativeTool != tt.declared || tc.Tool != tt.normalized || tc.ContractTool != tt.matched {
				t.Fatalf("identities = declared %q normalized %q matched %q, want %q %q %q", tc.NativeTool, tc.Tool, tc.ContractTool, tt.declared, tt.normalized, tt.matched)
			}
		})
	}
}

func TestWindowsCodexCollaborationDottedIdentities(t *testing.T) {
	cases := []struct {
		tool       string
		input      any
		capability policy.Capability
		decision   policy.Decision
	}{
		{"collaboration.spawn_agent", map[string]any{"task_name": "probe", "message": "work"}, policy.CapabilityDelegation, policy.Deny},
		{"collaboration.send_message", map[string]any{"target": "/root/probe", "message": "hello"}, policy.CapabilityDelegation, policy.Deny},
		{"collaboration.followup_task", map[string]any{"target": "/root/probe", "message": "work"}, policy.CapabilityDelegation, policy.Deny},
		{"collaboration.interrupt_agent", map[string]any{"target": "/root/probe"}, policy.CapabilitySafeControl, policy.Allow},
		{"collaboration.list_agents", map[string]any{}, policy.CapabilitySafeControl, policy.Allow},
		{"collaboration.wait_agent", map[string]any{"timeout_ms": 1000}, policy.CapabilitySafeControl, policy.Allow},
	}
	for _, tt := range cases {
		t.Run(tt.tool, func(t *testing.T) {
			tc, err := ParseCodex(strings.NewReader(codexEnvelope(t.TempDir(), tt.tool, tt.input)))
			if err != nil {
				t.Fatal(err)
			}
			if tc.NativeTool != tt.tool || tc.Tool != tt.tool || tc.Capability != tt.capability {
				t.Fatalf("tool call = %+v, want native/normalized %q and capability %q", tc, tt.tool, tt.capability)
			}
			verdict := engine.Evaluate(tc, &policy.Policy{})
			if verdict.Decision != tt.decision {
				t.Fatalf("verdict = %+v, want %q", verdict, tt.decision)
			}
			if tt.capability == policy.CapabilityDelegation {
				if verdict.RuleID != "capability-delegation-unverified" {
					t.Fatalf("verdict = %+v, want capability-delegation-unverified", verdict)
				}
				var out, errb bytes.Buffer
				if code := EmitCodex(verdict, "pre", tc, &out, &errb); code != 2 || !strings.Contains(errb.String(), "perform the work yourself") {
					t.Fatalf("code=%d stdout=%q stderr=%q", code, out.String(), errb.String())
				}
			}
		})
	}
}

func TestWindowsCodexCollaborationResumeAgentStaysUnknownWithoutRuntimeEvidence(t *testing.T) {
	tc, err := ParseCodex(strings.NewReader(codexEnvelope(t.TempDir(), "collaboration.resume_agent", map[string]any{"target": "/root/probe"})))
	if err != nil {
		t.Fatal(err)
	}
	if tc.Capability != policy.CapabilityUnknown {
		t.Fatalf("capability = %q, want unknown until a runtime capture proves this identity", tc.Capability)
	}
	if verdict := engine.Evaluate(tc, &policy.Policy{}); verdict.Decision != policy.Deny || verdict.RuleID != "unknown-native-tool" {
		t.Fatalf("verdict = %+v, want deny/unknown-native-tool", verdict)
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

func TestWindowsCodexConfiguredLauncherUsesStructuredDenials(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows launcher contract")
	}
	t.Setenv("GUARDRAIL_CODEX_STRUCTURED_WINDOWS", "1")
	for _, test := range []struct {
		event string
		want  string
	}{
		{event: "pre", want: `"permissionDecision":"deny"`},
		{event: "post", want: `"decision":"block"`},
	} {
		t.Run(test.event, func(t *testing.T) {
			var out, errb bytes.Buffer
			code := EmitCodex(policy.Verdict{Decision: policy.Deny, Reason: "fixture"}, test.event, engine.ToolCall{}, &out, &errb)
			if code != 0 || !strings.Contains(out.String(), test.want) || !strings.Contains(errb.String(), "policy denial") {
				t.Fatalf("code=%d stdout=%q stderr=%q", code, out.String(), errb.String())
			}
		})
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
