package genconfig

import (
	"testing"

	"github.com/CtrlCarlitos/agent-guardrails/internal/planecontract"
	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
)

func TestEmittedHookMatchersEqualPlanecontractMatchers(t *testing.T) {
	// Claude plane verification
	claudeFrag := legacyClaudeFragment(&policy.Policy{}, "/usr/local/bin/guardrail")
	claudeHooks, ok := claudeFrag["hooks"].(map[string]any)
	if !ok {
		t.Fatalf("ClaudeConfig emitted invalid hooks shape: %T", claudeFrag["hooks"])
	}
	claudePre := claudeHooks["PreToolUse"].([]any)[0].(map[string]any)
	if got := claudePre["matcher"].(string); got != planecontract.ClaudePreHookMatcher() {
		t.Errorf("claude PreToolUse matcher = %q, want %q", got, planecontract.ClaudePreHookMatcher())
	}
	claudePost := claudeHooks["PostToolUse"].([]any)[0].(map[string]any)
	if got := claudePost["matcher"].(string); got != planecontract.ClaudePostHookMatcher() {
		t.Errorf("claude PostToolUse matcher = %q, want %q", got, planecontract.ClaudePostHookMatcher())
	}

	// Antigravity plane verification
	agyFrag := AntigravityConfig("/usr/local/bin/guardrail")
	agyGuardrail, ok := agyFrag["guardrail"].(map[string]any)
	if !ok {
		t.Fatalf("AntigravityConfig emitted invalid guardrail shape: %T", agyFrag["guardrail"])
	}
	agyPre := agyGuardrail["PreToolUse"].([]any)[0].(map[string]any)
	if got := agyPre["matcher"].(string); got != planecontract.AntigravityPreHookMatcher() {
		t.Errorf("antigravity PreToolUse matcher = %q, want %q", got, planecontract.AntigravityPreHookMatcher())
	}
	agyPost := agyGuardrail["PostToolUse"].([]any)[0].(map[string]any)
	if got := agyPost["matcher"].(string); got != planecontract.AntigravityPostHookMatcher() {
		t.Errorf("antigravity PostToolUse matcher = %q, want %q", got, planecontract.AntigravityPostHookMatcher())
	}
}
