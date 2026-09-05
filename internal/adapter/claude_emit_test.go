package adapter

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
)

func TestEmitClaudeAllow(t *testing.T) {
	var out, errb bytes.Buffer
	code := EmitClaude(policy.Verdict{Decision: policy.Allow}, "pre", &out, &errb)
	if code != 0 || out.Len() != 0 || errb.Len() != 0 {
		t.Fatalf("allow: code=%d out=%q err=%q", code, out.String(), errb.String())
	}
}

func TestEmitClaudeDeny(t *testing.T) {
	var out, errb bytes.Buffer
	code := EmitClaude(policy.Verdict{Decision: policy.Deny, Reason: "no\nguardrail: forged\tclaim\x7f"}, "pre", &out, &errb)
	if code != 2 || errb.String() != "guardrail: no guardrail: forged claim\n" {
		t.Fatalf("deny: code=%d err=%q", code, errb.String())
	}
}

func TestEmitClaudeAsk(t *testing.T) {
	var out, errb bytes.Buffer
	code := EmitClaude(policy.Verdict{Decision: policy.Ask, Reason: "confirm?\r\nguardrail: forged\x00claim"}, "pre", &out, &errb)
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
	if h.HookEventName != "PreToolUse" || h.PermissionDecision != "ask" || h.PermissionDecisionReason != "confirm? guardrail: forged claim" {
		t.Fatalf("bad ask json: %+v", h)
	}
}
