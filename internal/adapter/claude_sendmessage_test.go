package adapter

import (
	"strings"
	"testing"

	"github.com/CtrlCarlitos/agent-guardrails/internal/engine"
	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
)

// Payloads are the PreToolUse tool_input shapes captured from Claude Code
// 2.1.325 (#541): the harness backfills recipient/recipient_kind from `to`.
func TestParseClaudeSendMessageClassifiesByTarget(t *testing.T) {
	cases := []struct {
		name       string
		input      string
		capability policy.Capability
		decision   policy.Decision
		rule       string
	}{
		{"spawned subagent id (captured)",
			`{"to":"ad1e02b482a45705f","summary":"s","message":"probe 1","type":"message","recipient":"ad1e02b482a45705f","recipient_kind":"agent","content":"probe 1"}`,
			policy.CapabilityDelegation, policy.Allow, "delegation-inherited"},
		{"labelled subagent id",
			`{"to":"areviewer-0123456789abcdef","message":"m"}`,
			policy.CapabilityDelegation, policy.Allow, "delegation-inherited"},
		{"subagent to its parent",
			`{"to":"main","message":"m","recipient_kind":"main"}`,
			policy.CapabilityDelegation, policy.Allow, "delegation-inherited"},
		{"subagent id without backfill (older builds)",
			`{"to":"a0caa7adade7d0075","message":"m"}`,
			policy.CapabilityDelegation, policy.Allow, "delegation-inherited"},
		{"local session by name (captured)",
			`{"to":"agent-guardrails-5a","summary":"s","message":"probe 2","type":"message","recipient":"agent-guardrails-5a","recipient_kind":"name","content":"probe 2"}`,
			policy.CapabilityExternal, policy.Ask, "capability-external"},
		{"session name with ref (captured)",
			`{"to":"agent-guardrails-5a [384338]","message":"probe 3","recipient_kind":"name"}`,
			policy.CapabilityExternal, policy.Ask, "capability-external"},
		{"remote control bridge address",
			`{"to":"bridge:session_01abc","message":"m","recipient_kind":"session"}`,
			policy.CapabilityExternal, policy.Ask, "capability-external"},
		{"agent-shaped to the harness did not tag as agent",
			`{"to":"a0caa7adade7d0075","message":"m","recipient_kind":"name"}`,
			policy.CapabilityExternal, policy.Ask, "capability-external"},
		{"uppercase hex is not a spawned id",
			`{"to":"a0CAA7ADADE7D0075","message":"m"}`,
			policy.CapabilityExternal, policy.Ask, "capability-external"},
		{"surrounding space is not a spawned id",
			`{"to":" a0caa7adade7d0075","message":"m"}`,
			policy.CapabilityExternal, policy.Ask, "capability-external"},
		{"missing to fails closed",
			`{"message":"m"}`,
			policy.CapabilityDeny, policy.Deny, "capability-deny"},
		{"empty to fails closed",
			`{"to":"","message":"m"}`,
			policy.CapabilityDeny, policy.Deny, "capability-deny"},
		{"non-string to fails closed",
			`{"to":["a0caa7adade7d0075"],"message":"m"}`,
			policy.CapabilityDeny, policy.Deny, "capability-deny"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			payload := `{"cwd":"/repo","hook_event_name":"PreToolUse","tool_name":"SendMessage","tool_input":` + c.input + `}`
			tc, err := ParseClaude(strings.NewReader(payload))
			if err != nil {
				t.Fatal(err)
			}
			if tc.Capability != c.capability {
				t.Fatalf("capability = %q, want %q", tc.Capability, c.capability)
			}
			v := engine.Evaluate(tc, &policy.Policy{})
			if v.Decision != c.decision || v.RuleID != c.rule {
				t.Fatalf("verdict = %s/%s, want %s/%s", v.Decision, v.RuleID, c.decision, c.rule)
			}
		})
	}
}
