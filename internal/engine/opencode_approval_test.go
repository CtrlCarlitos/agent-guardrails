package engine

import (
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
	"github.com/CtrlCarlitos/agent-guardrails/internal/session"
)

func TestOpenCodeApprovalKeyCanonicalizesObjectOrder(t *testing.T) {
	first := openCodeToolCall(`{"z":{"b":2,"a":1},"a":"x"}`)
	second := openCodeToolCall(`{"a":"x","z":{"a":1,"b":2}}`)

	firstKey := mustOpenCodeApprovalKey(t, first)
	secondKey := mustOpenCodeApprovalKey(t, second)
	if firstKey != secondKey {
		t.Fatalf("reordered object keys produced %q and %q, want one key", firstKey, secondKey)
	}
}

func TestOpenCodeApprovalKeyChangesWithIdentity(t *testing.T) {
	tests := []struct {
		name  string
		first ToolCall
		other ToolCall
	}{
		{
			name:  "array order",
			first: openCodeToolCall(`{"items":[1,2]}`),
			other: openCodeToolCall(`{"items":[2,1]}`),
		},
		{
			name:  "scalar",
			first: openCodeToolCall(`{"value":"first"}`),
			other: openCodeToolCall(`{"value":"second"}`),
		},
		{
			name:  "bash whitespace and newline bytes",
			first: openCodeToolCall(`{"command":"printf 'a b'\n"}`),
			other: openCodeToolCall(`{"command":"printf  'a b'"}`),
		},
		{
			name:  "CWD bytes",
			first: openCodeToolCall(`{"path":"file"}`),
			other: func() ToolCall {
				tc := openCodeToolCall(`{"path":"file"}`)
				tc.CWD = "/repo/"
				return tc
			}(),
		},
		{
			name:  "session",
			first: openCodeToolCall(`{"path":"file"}`),
			other: func() ToolCall {
				tc := openCodeToolCall(`{"path":"file"}`)
				tc.SessionID = "session-2"
				return tc
			}(),
		},
		{
			name:  "normalized tool",
			first: openCodeToolCall(`{"path":"file"}`),
			other: func() ToolCall {
				tc := openCodeToolCall(`{"path":"file"}`)
				tc.Tool = "Read"
				return tc
			}(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			firstKey := mustOpenCodeApprovalKey(t, tt.first)
			otherKey := mustOpenCodeApprovalKey(t, tt.other)
			if firstKey == otherKey {
				t.Fatalf("distinct identities both produced %q", firstKey)
			}
		})
	}
}

func TestOpenCodeApprovalKeyRejectsIneligibleCalls(t *testing.T) {
	tests := []struct {
		name string
		tc   ToolCall
	}{
		{name: "missing session", tc: ToolCall{Plane: "opencode", Event: "pre", CWD: "/repo", Tool: "Bash", Arguments: json.RawMessage(`{}`)}},
		{name: "missing CWD", tc: ToolCall{Plane: "opencode", Event: "pre", SessionID: "session-1", Tool: "Bash", Arguments: json.RawMessage(`{}`)}},
		{name: "missing tool", tc: ToolCall{Plane: "opencode", Event: "pre", SessionID: "session-1", CWD: "/repo", Arguments: json.RawMessage(`{}`)}},
		{name: "missing arguments", tc: ToolCall{Plane: "opencode", Event: "pre", SessionID: "session-1", CWD: "/repo", Tool: "Bash"}},
		{name: "non-OpenCode plane", tc: ToolCall{Plane: "claude", Event: "pre", SessionID: "session-1", CWD: "/repo", Tool: "Bash", Arguments: json.RawMessage(`{}`)}},
		{name: "post event", tc: ToolCall{Plane: "opencode", Event: "post", SessionID: "session-1", CWD: "/repo", Tool: "Bash", Arguments: json.RawMessage(`{}`)}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if key, ok := OpenCodeApprovalKey(tt.tc); ok {
				t.Fatalf("OpenCodeApprovalKey = %q, true, want ineligible", key)
			}
		})
	}
}

func TestOpenCodeApprovalKeySeparatesTupleBoundaries(t *testing.T) {
	first := openCodeToolCall(`{}`)
	first.SessionID = "ab"
	first.CWD = "c"
	second := openCodeToolCall(`{}`)
	second.SessionID = "a"
	second.CWD = "bc"

	firstKey := mustOpenCodeApprovalKey(t, first)
	secondKey := mustOpenCodeApprovalKey(t, second)
	if firstKey == secondKey {
		t.Fatalf("different tuple boundaries both produced %q", firstKey)
	}
}

func TestOpenCodeApprovalKeyPreservesNumberTokens(t *testing.T) {
	integerKey := mustOpenCodeApprovalKey(t, openCodeToolCall(`{"value":1}`))
	decimalKey := mustOpenCodeApprovalKey(t, openCodeToolCall(`{"value":1.0}`))
	if integerKey == decimalKey {
		t.Fatalf("number tokens 1 and 1.0 both produced %q", integerKey)
	}
}

func TestOpenCodeApprovalKeyRejectsMalformedOrTrailingJSON(t *testing.T) {
	for _, arguments := range []string{
		`{`,
		`{"value":1}{"value":2}`,
		`{"value":1} trailing`,
	} {
		t.Run(arguments, func(t *testing.T) {
			if key, ok := OpenCodeApprovalKey(openCodeToolCall(arguments)); ok {
				t.Fatalf("OpenCodeApprovalKey = %q, true, want invalid JSON ineligible", key)
			}
		})
	}
}

func TestOpenCodeApprovalKeyRejectsNonExactJSON(t *testing.T) {
	tests := []struct {
		name      string
		arguments string
	}{
		{name: "invalid UTF-8", arguments: "{\"value\":\"\xff\"}"},
		{name: "duplicate top-level name", arguments: `{"a":1,"a":2}`},
		{name: "duplicate nested name", arguments: `{"outer":{"a":1,"a":2}}`},
		{name: "duplicate name nested in array", arguments: `{"outer":[{"a":1,"a":2}]}`},
		{name: "duplicate escape-equivalent name", arguments: `{"a":1,"\u0061":2}`},
		{name: "lone high surrogate", arguments: `{"value":"\uD83D"}`},
		{name: "lone low surrogate", arguments: `{"value":"\uDE00"}`},
		{name: "improperly paired high surrogate", arguments: `{"value":"\uD83D\u0041"}`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if key, ok := OpenCodeApprovalKey(openCodeToolCall(tt.arguments)); ok {
				t.Fatalf("OpenCodeApprovalKey = %q, true, want non-exact JSON ineligible", key)
			}
		})
	}
}

func TestOpenCodeApprovalKeyCanonicalizesValidSurrogatePair(t *testing.T) {
	escaped := mustOpenCodeApprovalKey(t, openCodeToolCall(`{"value":"\uD83D\uDE00"}`))
	scalar := mustOpenCodeApprovalKey(t, openCodeToolCall("{\"value\":\"\U0001F600\"}"))
	if escaped != scalar {
		t.Fatalf("surrogate pair and corresponding scalar produced %q and %q, want one key", escaped, scalar)
	}
}

func TestOpenCodeApprovalKeyKnownVector(t *testing.T) {
	tc := ToolCall{
		Plane: "opencode", Event: "pre", SessionID: "session-1",
		CWD: "/repo", Tool: "Bash",
		Arguments: json.RawMessage(`{"command":"echo hi"}`),
	}
	got, ok := OpenCodeApprovalKey(tc)
	if !ok || got != "4997f9c03b91b6f4878986cf95b0c54d040c4ad41f63e5f97dfefb5daeb92c5c" {
		t.Fatalf("key = %q, ok=%v", got, ok)
	}
}

func TestApplyOpenCodeApprovalTransitions(t *testing.T) {
	now := time.Date(2026, 9, 7, 12, 0, 0, 0, time.UTC)
	expiresAt := time.Date(2026, 9, 7, 12, 10, 0, 0, time.UTC)
	ask := policy.Verdict{
		Decision: policy.Ask,
		RuleID:   "P2.git-checkout-restore",
		Reason:   "restore files?",
	}
	approved := policy.Verdict{
		Decision:     policy.Allow,
		RuleID:       "ask-approved-by-retry",
		OriginRuleID: "P2.git-checkout-restore",
		Reason:       "approved by exact OpenCode retry after user confirmation",
	}

	tests := []struct {
		name        string
		verdict     policy.Verdict
		now         time.Time
		pending     map[string]session.PendingApproval
		wantVerdict policy.Verdict
		wantPending map[string]session.PendingApproval
	}{
		{
			name:        "first Ask records ten-minute expiry",
			verdict:     ask,
			now:         now,
			wantVerdict: ask,
			wantPending: map[string]session.PendingApproval{
				"digest": {OriginRuleID: ask.RuleID, ExpiresAt: expiresAt},
			},
		},
		{
			name:    "identical Ask one nanosecond before expiry approves and consumes",
			verdict: ask,
			now:     expiresAt.Add(-time.Nanosecond),
			pending: map[string]session.PendingApproval{
				"digest": {OriginRuleID: ask.RuleID, ExpiresAt: expiresAt},
			},
			wantVerdict: approved,
			wantPending: map[string]session.PendingApproval{},
		},
		{
			name:    "identical Ask exactly at expiry refreshes",
			verdict: ask,
			now:     expiresAt,
			pending: map[string]session.PendingApproval{
				"digest": {OriginRuleID: ask.RuleID, ExpiresAt: expiresAt},
			},
			wantVerdict: ask,
			wantPending: map[string]session.PendingApproval{
				"digest": {OriginRuleID: ask.RuleID, ExpiresAt: time.Date(2026, 9, 7, 12, 20, 0, 0, time.UTC)},
			},
		},
		{
			name: "changed Rule ID asks and replaces entry",
			verdict: policy.Verdict{
				Decision: policy.Ask,
				RuleID:   "P5.out-of-repo",
				Reason:   "write outside repository?",
			},
			now: now,
			pending: map[string]session.PendingApproval{
				"digest": {OriginRuleID: ask.RuleID, ExpiresAt: expiresAt},
			},
			wantVerdict: policy.Verdict{
				Decision: policy.Ask,
				RuleID:   "P5.out-of-repo",
				Reason:   "write outside repository?",
			},
			wantPending: map[string]session.PendingApproval{
				"digest": {OriginRuleID: "P5.out-of-repo", ExpiresAt: expiresAt},
			},
		},
		{
			name:    "current Deny remains unchanged and consumes",
			verdict: policy.Verdict{Decision: policy.Deny, RuleID: "P1.rm-rf", Reason: "denied"},
			now:     now,
			pending: map[string]session.PendingApproval{
				"digest": {OriginRuleID: ask.RuleID, ExpiresAt: expiresAt},
			},
			wantVerdict: policy.Verdict{Decision: policy.Deny, RuleID: "P1.rm-rf", Reason: "denied"},
			wantPending: map[string]session.PendingApproval{},
		},
		{
			name:    "current Allow remains unchanged and consumes",
			verdict: policy.Verdict{Decision: policy.Allow},
			now:     now,
			pending: map[string]session.PendingApproval{
				"digest": {OriginRuleID: ask.RuleID, ExpiresAt: expiresAt},
			},
			wantVerdict: policy.Verdict{Decision: policy.Allow},
			wantPending: map[string]session.PendingApproval{},
		},
		{
			name:        "empty Rule ID Ask creates no consumable entry",
			verdict:     policy.Verdict{Decision: policy.Ask, Reason: "unspecified confirmation"},
			now:         now,
			wantVerdict: policy.Verdict{Decision: policy.Ask, Reason: "unspecified confirmation"},
			wantPending: nil,
		},
		{
			name:    "empty Rule ID Ask clears matching stale entry only",
			verdict: policy.Verdict{Decision: policy.Ask, Reason: "unspecified confirmation"},
			now:     now,
			pending: map[string]session.PendingApproval{
				"digest":    {OriginRuleID: ask.RuleID, ExpiresAt: expiresAt},
				"unrelated": {OriginRuleID: "P6.package-install", ExpiresAt: now.Add(time.Hour)},
				"expired":   {OriginRuleID: "P5.out-of-repo", ExpiresAt: now},
			},
			wantVerdict: policy.Verdict{Decision: policy.Ask, Reason: "unspecified confirmation"},
			wantPending: map[string]session.PendingApproval{
				"unrelated": {OriginRuleID: "P6.package-install", ExpiresAt: now.Add(time.Hour)},
			},
		},
		{
			name:    "unrelated entries remain and expired entries are pruned",
			verdict: ask,
			now:     now,
			pending: map[string]session.PendingApproval{
				"unrelated": {OriginRuleID: "P6.package-install", ExpiresAt: now.Add(time.Hour)},
				"expired":   {OriginRuleID: "P5.out-of-repo", ExpiresAt: now},
			},
			wantVerdict: ask,
			wantPending: map[string]session.PendingApproval{
				"unrelated": {OriginRuleID: "P6.package-install", ExpiresAt: now.Add(time.Hour)},
				"digest":    {OriginRuleID: ask.RuleID, ExpiresAt: expiresAt},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			state := &session.State{PendingApprovals: tt.pending}
			got := ApplyOpenCodeApproval(tt.verdict, "digest", state, tt.now)
			if got != tt.wantVerdict {
				t.Errorf("verdict = %+v, want %+v", got, tt.wantVerdict)
			}
			if !reflect.DeepEqual(state.PendingApprovals, tt.wantPending) {
				t.Errorf("pending approvals = %+v, want %+v", state.PendingApprovals, tt.wantPending)
			}
		})
	}
}

func TestApplyOpenCodeApprovalIgnoresEmptyKeyOrNilState(t *testing.T) {
	now := time.Date(2026, 9, 7, 12, 0, 0, 0, time.UTC)
	verdict := policy.Verdict{Decision: policy.Ask, RuleID: "P2.git-checkout-restore", Reason: "restore files?"}
	if got := ApplyOpenCodeApproval(verdict, "digest", nil, now); got != verdict {
		t.Fatalf("nil state verdict = %+v, want unchanged %+v", got, verdict)
	}

	wantPending := map[string]session.PendingApproval{
		"expired": {OriginRuleID: verdict.RuleID, ExpiresAt: now},
	}
	state := &session.State{PendingApprovals: map[string]session.PendingApproval{
		"expired": {OriginRuleID: verdict.RuleID, ExpiresAt: now},
	}}
	if got := ApplyOpenCodeApproval(verdict, "", state, now); got != verdict {
		t.Fatalf("empty key verdict = %+v, want unchanged %+v", got, verdict)
	}
	if !reflect.DeepEqual(state.PendingApprovals, wantPending) {
		t.Fatalf("empty key changed pending approvals to %+v, want %+v", state.PendingApprovals, wantPending)
	}
}

func openCodeToolCall(arguments string) ToolCall {
	return ToolCall{
		Plane:     "opencode",
		Event:     "pre",
		SessionID: "session-1",
		CWD:       "/repo",
		Tool:      "Bash",
		Arguments: json.RawMessage(arguments),
	}
}

func mustOpenCodeApprovalKey(t *testing.T, tc ToolCall) string {
	t.Helper()
	key, ok := OpenCodeApprovalKey(tc)
	if !ok {
		t.Fatalf("OpenCodeApprovalKey(%+v) is ineligible", tc)
	}
	return key
}
