package adapter

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/CtrlCarlitos/agent-guardrails/internal/engine"
	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
)

func TestEmitClaudeAllow(t *testing.T) {
	var out, errb bytes.Buffer
	code := EmitClaude(policy.Verdict{Decision: policy.Allow}, "pre", engine.ToolCall{}, &out, &errb)
	if code != 0 || out.Len() != 0 || errb.Len() != 0 {
		t.Fatalf("allow: code=%d out=%q err=%q", code, out.String(), errb.String())
	}
}

func TestEmitClaudeDeny(t *testing.T) {
	tc, err := ParseClaude(strings.NewReader(`{"cwd":"/tmp","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"rm -rf /"}}`))
	if err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	code := EmitClaude(policy.Verdict{Decision: policy.Deny, Reason: "protected target"}, "pre", tc, &out, &errb)
	if code != 2 || !strings.Contains(errb.String(), "Guardrail denied this action: protected target.") || !strings.Contains(errb.String(), "Do not retry this exact call.") || strings.Contains(errb.String(), "Choose a safe alternative.") {
		t.Fatalf("deny: code=%d err=%q", code, errb.String())
	}
}

func TestEmitClaudeAsk(t *testing.T) {
	tc, err := ParseClaude(strings.NewReader(`{"cwd":"/tmp","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"chmod -R 777 /tmp"}}`))
	if err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	code := EmitClaude(policy.Verdict{Decision: policy.Ask, Reason: "needs approval"}, "pre", tc, &out, &errb)
	if code != 0 {
		t.Fatalf("ask code=%d", code)
	}
	var got struct {
		HookSpecificOutput struct {
			HookEventName            string `json:"hookEventName"`
			PermissionDecision       string `json:"permissionDecision"`
			PermissionDecisionReason string `json:"permissionDecisionReason"`
		} `json:"hookSpecificOutput"`
	}
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	h := got.HookSpecificOutput
	if h.HookEventName != "PreToolUse" || h.PermissionDecision != "ask" || !strings.Contains(h.PermissionDecisionReason, "Operator authorization required: needs approval.") || !strings.Contains(h.PermissionDecisionReason, `Request authorization for this exact action: Bash {"command":"chmod -R 777 /tmp"}.`) || !strings.Contains(h.PermissionDecisionReason, "If the operator approves, retry this exact tool call once.") || !strings.Contains(h.PermissionDecisionReason, "Do not alter or broaden the action.") {
		t.Fatalf("bad ask json: %+v", h)
	}
}
