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

func TestEmitClaudeOperatorActionTellsModelHowToProceed(t *testing.T) {
	tc, err := ParseClaude(strings.NewReader(`{"cwd":"/tmp","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"guardrail egress grant --scope repo --host a.example.com"}}`))
	if err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	v := policy.Verdict{Decision: policy.Complete, RuleID: "operator-action", OperatorAction: "web-host-grant", RequestID: "request-1", ApprovalURL: "http://localhost:39169/approve/request-1"}
	code := EmitClaude(v, "pre", tc, &out, &errb)
	if code != 0 || errb.Len() != 0 {
		t.Fatalf("operator action: code=%d err=%q", code, errb.String())
	}
	var got struct {
		HookSpecificOutput struct {
			HookEventName            string `json:"hookEventName"`
			PermissionDecision       string `json:"permissionDecision"`
			PermissionDecisionReason string `json:"permissionDecisionReason"`
			AdditionalContext        string `json:"additionalContext"`
			OperatorAction           string `json:"operator_action"`
			RequestID                string `json:"request_id"`
			ApprovalURL              string `json:"approval_url"`
		} `json:"hookSpecificOutput"`
	}
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	h := got.HookSpecificOutput
	if h.HookEventName != "PreToolUse" || h.PermissionDecision != "deny" || h.OperatorAction != "web-host-grant" || h.RequestID != "request-1" || h.ApprovalURL != v.ApprovalURL {
		t.Fatalf("bad operator-action json: %+v", h)
	}
	// Claude Code surfaces additionalContext (and the reason) to the model; the
	// bare fields above are invisible to it, so the guidance must be self-contained.
	for _, want := range []string{
		"Operator approval requested for web-host-grant (request request-1).",
		"Approval URL: http://localhost:39169/approve/request-1.",
		"The operator approves with their passkey and the action is applied at that moment",
		"do not re-run this command",
		"files a new request",
		"Continue other work meanwhile",
		"use the granted capability once they confirm",
	} {
		if !strings.Contains(h.AdditionalContext, want) {
			t.Fatalf("additionalContext %q lacks %q", h.AdditionalContext, want)
		}
	}
	if h.PermissionDecisionReason != h.AdditionalContext {
		t.Fatalf("reason %q != context %q", h.PermissionDecisionReason, h.AdditionalContext)
	}
}

func TestEmitClaudeOperatorActionWithoutURLStillNamesTheRequest(t *testing.T) {
	var out, errb bytes.Buffer
	v := policy.Verdict{Decision: policy.Complete, RuleID: "operator-action", OperatorAction: "night-off", RequestID: "request-2"}
	EmitClaude(v, "pre", engine.ToolCall{NativeTool: "Bash"}, &out, &errb)
	if !strings.Contains(out.String(), "Operator approval requested for night-off (request request-2).") || strings.Contains(out.String(), "Approval URL") {
		t.Fatalf("operator-action response = %s", out.String())
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
