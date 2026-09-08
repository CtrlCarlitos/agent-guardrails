# OpenCode One-Shot Approval Memory Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let one exact OpenCode retry consume a recent matching Ask without weakening current Deny verdicts or creating state outside M-7's transaction.

**Architecture:** The OpenCode Adapter forwards the complete native argument object as a normalized fact. The Engine canonicalizes and hashes the approved identity tuple, stores pending approvals additively in M-7's `session.State`, and applies one-shot transitions inside the existing store-wide transaction after current policy and P7 evaluation. Audit attribution travels on the final Verdict; JavaScript remains a stateless transport.

**Tech Stack:** Go 1.23+, embedded JavaScript OpenCode Adapter, standard-library JSON/SHA-256 encoding, M-7 `session.Transaction`, existing test helpers and dependencies.

**Spec:** `docs/adr/0011-opencode-one-shot-approval-memory.md`

## Global Constraints

- Apply approval memory to every OpenCode `pre` tool call, not only Bash; other planes and post-events never use it.
- Identity is the native session ID, byte-for-byte Adapter CWD, normalized tool name, and deterministic canonical native arguments.
- Hash a domain-separated/versioned tuple with unsigned 64-bit big-endian length prefixes and SHA-256; persist neither raw arguments nor the raw session ID in approval entries.
- Object-key order is irrelevant. Array order, scalar values, and decoded Bash command bytes remain significant.
- Pending entries expire after exactly ten minutes; `now >= expires_at` is expired.
- Current policy and P7 evaluate before approval memory. Deny is never downgraded.
- A matching current Deny or Allow consumes the entry and remains unchanged.
- A matching unexpired Ask with the same nonempty Rule ID consumes the entry and becomes one Allow with `rule_id:"ask-approved-by-retry"` and `origin_rule_id` set to the Ask Rule ID.
- An absent, expired, or different-rule Ask remains Ask and records a fresh ten-minute entry. An Ask with an empty Rule ID remains Ask and cannot create consumable approval.
- Missing session, CWD, tool, or argument facts, and transaction failure, preserve the current Ask and do not record or consume approval memory.
- Use M-7's one exclusive `session.Transaction`; add no JavaScript cache, state file, or lock domain.
- P7 and approval state changes persist atomically in one transaction. Waiving P7 disables only P7 tracking, not NF-13 approval memory.
- Concurrent identical retries have exactly one consumer: one Allow, followed by one Ask that creates a fresh pending entry.
- Engine owns canonical identity and approval policy semantics. The Adapter and hook supply facts and orchestration only.
- The plugin Ask message is exactly `guardrail needs confirmation \u2014 <reason>. Ask the user; if they approve, re-run this exact tool call.` after JavaScript escape interpretation.
- Add `origin_rule_id` to audit JSON only when nonempty; existing records remain compatible.
- Do not edit external repositories, push, merge, or tag.

---

### Task 1: Carry Complete OpenCode Arguments

**Files:**
- Modify: `internal/engine/toolcall.go`
- Modify: `internal/adapter/opencode.go`
- Test: `internal/adapter/opencode_test.go`
- Modify: `internal/genconfig/opencode_plugin.js`
- Test: `internal/genconfig/opencode_test.go`

**Interfaces:**
- Produces: `engine.ToolCall.Arguments json.RawMessage`, containing the complete OpenCode `output.args` JSON value exactly as represented in the hook envelope.
- Produces: OpenCode hook envelope field `"arguments"`; the existing `command` and `paths` policy projections remain present.
- Consumes: no approval state or policy semantics.

- [ ] **Step 1: Add RED Adapter tests for complete arguments**

Add focused cases to `internal/adapter/opencode_test.go`:

```go
func TestParseOpencodeCarriesCompleteNativeArguments(t *testing.T) {
	raw := `{"session_id":"s1","event":"pre","tool":"custom","cwd":"/repo","arguments":{"z":1,"nested":{"b":true,"a":null},"items":[2,1]}}`
	tc, err := ParseOpencode(strings.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	if tc.Tool != "custom" || string(tc.Arguments) != `{"z":1,"nested":{"b":true,"a":null},"items":[2,1]}` {
		t.Fatalf("ToolCall arguments were not preserved: %+v args=%s", tc, tc.Arguments)
	}
}

func TestParseOpencodeDistinguishesMissingArguments(t *testing.T) {
	tc, err := ParseOpencode(strings.NewReader(`{"session_id":"s1","event":"pre","tool":"read","cwd":"/repo"}`))
	if err != nil {
		t.Fatal(err)
	}
	if tc.Arguments != nil {
		t.Fatalf("Arguments = %s, want missing", tc.Arguments)
	}
}
```

- [ ] **Step 2: Run the Adapter tests and verify RED**

Run:

```bash
/usr/local/go/bin/go test ./internal/adapter -run 'Opencode.*Arguments' -count=1
```

Expected: build failure because `ToolCall.Arguments` does not exist.

- [ ] **Step 3: Add the normalized argument fact**

In `internal/engine/toolcall.go`, add:

```go
Arguments json.RawMessage // complete native argument payload when the plane exposes it
```

In `internal/adapter/opencode.go`, add `Arguments json.RawMessage `json:"arguments"`` to `opencodePayload` and copy it into `ToolCall.Arguments`. Do not canonicalize it here and do not derive approval behavior in the Adapter.

- [ ] **Step 4: Run the Adapter tests and verify GREEN**

Run:

```bash
/usr/local/go/bin/go test ./internal/adapter -run 'Opencode' -count=1
```

Expected: PASS.

- [ ] **Step 5: Add RED embedded-plugin contract tests**

Extend the Node-backed tests in `internal/genconfig/opencode_test.go` so the fake binary records stdin and the runner invokes Bash, Read, Edit, Write, List, and a custom tool. Decode each captured line and assert:

```go
wantArguments := []map[string]any{
	{"command": "printf '%s\\n' hi", "timeout": float64(30)},
	{"filePath": "/repo/a.txt", "offset": float64(2), "limit": float64(4)},
	{"filePath": "/repo/a.txt", "oldString": "a", "newString": "b"},
	{"filePath": "/repo/new.txt", "content": "body"},
	{"directory": "/repo", "depth": float64(2)},
	{"nested": map[string]any{"z": float64(1), "a": true}, "items": []any{"x", "y"}},
}
```

Also assert the plugin still registers the unfiltered `tool.execute.before`, still sends the policy projections, and renders an Ask as:

```text
guardrail needs confirmation — confirm it. Ask the user; if they approve, re-run this exact tool call.
```

- [ ] **Step 6: Run the plugin tests and verify RED**

Run:

```bash
/usr/local/go/bin/go test ./internal/genconfig -run 'OpencodePlugin.*(Arguments|Allow)' -count=1
```

Expected: the captured envelopes omit `arguments`, and the old Ask guidance text differs.

- [ ] **Step 7: Forward arguments without adding Adapter memory**

Change the plugin envelope construction to include the complete object:

```js
const args = output.args ?? {};
const envelope = {
	session_id: input.sessionID ?? input.session_id,
	event: "pre",
	tool,
	cwd: directory,
	arguments: args,
};
```

Keep `command` and `paths` as separate Engine policy projections. Replace only the Ask branch message:

```js
throw new Error(`guardrail needs confirmation \u2014 ${reason}. Ask the user; if they approve, re-run this exact tool call.`);
```

- [ ] **Step 8: Verify and commit Task 1**

Run:

```bash
/usr/local/go/bin/gofmt -w internal/engine/toolcall.go internal/adapter/opencode.go internal/adapter/opencode_test.go internal/genconfig/opencode_test.go
/usr/local/go/bin/go test ./internal/adapter ./internal/genconfig -race -count=5
/usr/local/go/bin/go test ./... -count=1
git diff --check
git add internal/engine/toolcall.go internal/adapter/opencode.go internal/adapter/opencode_test.go internal/genconfig/opencode_plugin.js internal/genconfig/opencode_test.go
git commit -m "feat: carry complete OpenCode tool arguments (NF-13)"
```

---

### Task 2: Implement Engine Approval Memory

**Files:**
- Modify: `internal/session/session.go`
- Test: `internal/session/session_test.go`
- Modify: `internal/policy/policy.go`
- Create: `internal/engine/opencode_approval.go`
- Create: `internal/engine/opencode_approval_test.go`

**Interfaces:**
- Consumes: `ToolCall.Arguments json.RawMessage` from Task 1.
- Produces: `session.PendingApproval { OriginRuleID string; ExpiresAt time.Time }` and additive `State.PendingApprovals map[string]PendingApproval`.
- Produces: `policy.Verdict.OriginRuleID string`.
- Produces: `OpenCodeApprovalKey(tc ToolCall) (string, bool)`; `bool` is false for non-OpenCode/non-pre calls, missing identity, or invalid argument JSON.
- Produces: `ApplyOpenCodeApproval(v policy.Verdict, key string, st *session.State, now time.Time) policy.Verdict`.

- [ ] **Step 1: Add RED additive-state compatibility tests**

In `internal/session/session_test.go`, decode an existing M-7 JSON object without `pending_approvals`, then transact and verify its signal bits remain intact. Add a second round trip with:

```go
PendingApprovals: map[string]PendingApproval{
	"digest": {
		OriginRuleID: "P2.git-checkout-restore",
		ExpiresAt:    time.Date(2026, 9, 7, 12, 10, 0, 0, time.UTC),
	},
}
```

Assert the persisted JSON contains the digest, rule ID, and expiry but no distinctive raw session/argument strings.

- [ ] **Step 2: Run the session tests and verify RED**

Run:

```bash
/usr/local/go/bin/go test ./internal/session -run 'PendingApproval|AdditiveState' -count=1
```

Expected: build failure because `PendingApproval` and `State.PendingApprovals` do not exist.

- [ ] **Step 3: Add the state and Verdict fields**

Use additive JSON fields:

```go
type PendingApproval struct {
	OriginRuleID string    `json:"origin_rule_id"`
	ExpiresAt    time.Time `json:"expires_at"`
}

type State struct {
	SawPrivateRead   bool                       `json:"saw_private_read"`
	SawNetworkCall   bool                       `json:"saw_network_call"`
	PendingApprovals map[string]PendingApproval `json:"pending_approvals,omitempty"`
	UpdatedAt        string                     `json:"updated_at"`
}
```

Add `OriginRuleID string` to `policy.Verdict`. Do not change the M-7 transaction signature, lock, namespace, migration, or pruning behavior.

- [ ] **Step 4: Run the session tests and verify GREEN**

Run:

```bash
/usr/local/go/bin/go test ./internal/session -run 'PendingApproval|AdditiveState' -count=1
```

Expected: PASS.

- [ ] **Step 5: Add RED canonical identity tests**

Create `internal/engine/opencode_approval_test.go`. Cover:

- top-level and nested object reordering yields one key;
- array reordering, scalar changes, Bash whitespace/newlines, CWD bytes, session, and normalized tool each change the key;
- missing session/CWD/tool/arguments, non-OpenCode plane, and post-event return `ok == false`;
- tuple boundaries do not collide;
- numbers retain their token value (`1` and `1.0` differ);
- malformed/trailing argument JSON is ineligible;
- the v1 known vector below is stable.

```go
tc := ToolCall{
	Plane: "opencode", Event: "pre", SessionID: "session-1",
	CWD: "/repo", Tool: "Bash",
	Arguments: json.RawMessage(`{"command":"echo hi"}`),
}
got, ok := OpenCodeApprovalKey(tc)
if !ok || got != "4997f9c03b91b6f4878986cf95b0c54d040c4ad41f63e5f97dfefb5daeb92c5c" {
	t.Fatalf("key = %q, ok=%v", got, ok)
}
```

- [ ] **Step 6: Run canonical identity tests and verify RED**

Run:

```bash
/usr/local/go/bin/go test ./internal/engine -run 'OpenCodeApprovalKey' -count=1
```

Expected: build failure because `OpenCodeApprovalKey` does not exist.

- [ ] **Step 7: Implement deterministic canonical identity**

In `internal/engine/opencode_approval.go`, decode `Arguments` with `json.Decoder.UseNumber`, require EOF after one JSON value, and re-encode with `encoding/json` so object keys sort while arrays and scalar tokens remain significant. Hash these five length-prefixed byte strings in order:

```go
[]byte("agent-guardrails/opencode-approval/v1")
[]byte(tc.SessionID)
[]byte(tc.CWD)
[]byte(tc.Tool)
canonicalArguments
```

Write each length as `uint64` in big-endian order before its bytes. Return a lowercase 64-character SHA-256 digest. Do not clean CWD or renormalize `tc.Tool`.

- [ ] **Step 8: Run canonical identity tests and verify GREEN**

Run:

```bash
/usr/local/go/bin/go test ./internal/engine -run 'OpenCodeApprovalKey' -count=1
```

Expected: PASS.

- [ ] **Step 9: Add RED approval-transition table tests**

Use fixed `now := time.Date(2026, 9, 7, 12, 0, 0, 0, time.UTC)` and table-driven cases covering:

- first Ask remains unchanged and stores expiry `12:10:00Z`;
- identical Ask at `12:09:59.999999999Z` becomes synthetic Allow and consumes;
- identical Ask at exactly `12:10:00Z` remains Ask and refreshes expiry;
- changed Rule ID remains Ask and replaces the entry;
- current Deny and current Allow each consume a matching entry unchanged;
- an empty-Rule-ID Ask remains Ask and leaves no consumable entry;
- unrelated pending entries remain; expired entries are removed;
- the synthetic Allow has exact fields:

```go
policy.Verdict{
	Decision:     policy.Allow,
	RuleID:       "ask-approved-by-retry",
	OriginRuleID: "P2.git-checkout-restore",
	Reason:       "approved by exact OpenCode retry after user confirmation",
}
```

- [ ] **Step 10: Run approval-transition tests and verify RED**

Run:

```bash
/usr/local/go/bin/go test ./internal/engine -run 'ApplyOpenCodeApproval' -count=1
```

Expected: build failure because `ApplyOpenCodeApproval` does not exist.

- [ ] **Step 11: Implement the one-shot Engine transition**

Use an unexported `const openCodeApprovalTTL = 10 * time.Minute`. Delete expired entries before matching. Consume a matching unexpired entry before returning current Allow/Deny. For Ask, approve only when the current and stored Rule IDs are the same and nonempty; otherwise store/replace a fresh entry. Return the input unchanged for an empty key or nil state.

- [ ] **Step 12: Verify and commit Task 2**

Run:

```bash
/usr/local/go/bin/gofmt -w internal/session/session.go internal/session/session_test.go internal/policy/policy.go internal/engine/opencode_approval.go internal/engine/opencode_approval_test.go
/usr/local/go/bin/go test ./internal/session ./internal/engine -race -count=20
/usr/local/go/bin/go test ./... -count=1
git diff --check
git add internal/session/session.go internal/session/session_test.go internal/policy/policy.go internal/engine/opencode_approval.go internal/engine/opencode_approval_test.go
git commit -m "feat: add one-shot OpenCode approval state (NF-13)"
```

---

### Task 3: Integrate Transactional Approval and Audit Attribution

**Files:**
- Modify: `cmd/guardrail/hook.go`
- Test: `cmd/guardrail/hook_test.go`
- Modify: `internal/audit/audit.go`
- Test: `internal/audit/audit_test.go`
- Test: `test/adversarial/adversarial_test.go`

**Interfaces:**
- Consumes: `OpenCodeApprovalKey`, `ApplyOpenCodeApproval`, `TrifectaTrackingEnabled`, `ApplyTrifecta`, and `session.Transaction`.
- Produces: one combined OpenCode transaction in which current Engine evaluation, P7 transition, and approval consume-or-record happen under M-7's store-wide lock.
- Produces: optional `audit.Record.OriginRuleID string `json:"origin_rule_id,omitempty"`` copied from the final Verdict.

- [ ] **Step 1: Add RED hook tests for exact one-shot behavior**

Add a helper that submits a complete OpenCode envelope with `arguments`, fixed session/CWD/tool, isolated `XDG_STATE_HOME`, and a policy-triggering Ask. Assert sequential calls produce:

```text
first:  ask,  original Rule ID retained in audit
second: allow, rule_id=ask-approved-by-retry, origin_rule_id=<original>
third:  ask,  original Rule ID retained and a fresh pending entry exists
```

Use separate helper subprocesses sharing the same state/config directories for the three calls so restart persistence is tested rather than process memory.

- [ ] **Step 2: Add RED identity, precedence, and failure hook tests**

Cover:

- changed session, byte-level CWD, normalized tool, or arguments cannot consume;
- object-key-only reordering can consume;
- missing session/CWD/tool/arguments preserves Ask and writes no pending approval;
- transaction failure preserves an existing Ask and emits the existing sanitized transaction warning;
- P7 waiver does not disable NF-13 approval memory;
- a P7-generated Ask participates in the same one-shot flow;
- non-OpenCode planes and OpenCode post-events do not use approval memory;
- after seeding an Ask, a tightened Overlay makes the identical call Deny, consumes the pending entry, and a later removal of that Deny produces Ask rather than a stale Allow;
- after seeding an Ask, a current Allow consumes the entry unchanged.

- [ ] **Step 3: Add RED cross-process one-consumer test**

Seed one pending Ask, then launch two complete identical OpenCode retries concurrently as subprocesses against one `XDG_STATE_HOME`. Assert exactly one final Verdict is synthetic Allow, exactly one is the original Ask, and the final persisted map contains one fresh pending entry for the same digest. This test must use the real `session.Transaction`; no in-memory lock substitute is acceptable.

- [ ] **Step 4: Run hook tests and verify RED**

Run:

```bash
/usr/local/go/bin/go test ./cmd/guardrail -run 'OpenCodeApproval|ApprovalMemory' -race -count=1
```

Expected: every retry remains Ask because hook orchestration does not call the approval Engine operation.

- [ ] **Step 5: Integrate evaluation and state transitions in one transaction**

Refactor the pre-event path without moving policy semantics into `cmdHook`:

```go
approvalKey, approvalEnabled := engine.OpenCodeApprovalKey(tc)
needsP7 := tc.Event == "pre" && engine.TrifectaTrackingEnabled(merged)
needsState := tc.SessionID != "" && (needsP7 || approvalEnabled)

if tc.Event == "pre" && needsState {
	err := session.Transaction(tc.SessionID, func(st *session.State) error {
		v = engine.Evaluate(tc, merged)
		if needsP7 {
			if esc := engine.ApplyTrifecta(v, tc, st, merged); esc != nil {
				v = *esc
			}
		}
		if approvalEnabled {
			v = engine.ApplyOpenCodeApproval(v, approvalKey, st, time.Now().UTC())
		}
		return nil
	})
	if err == nil {
		stateApplied = true
	} else {
		highPriorityWarnings = append(highPriorityWarnings, fmt.Sprintf("guardrail: session transaction failed (%v)", err))
	}
}
```

On an unavailable transaction, evaluate current policy outside state and apply M-7's nil-state P7 escalation only when P7 is active. Do not apply approval memory without the transaction. For ineligible/non-pre calls, preserve the existing evaluation path. Ensure a complete OpenCode pre-call performs at most one transaction.

- [ ] **Step 6: Run hook tests and verify GREEN**

Run:

```bash
/usr/local/go/bin/go test ./cmd/guardrail -run 'OpenCodeApproval|ApprovalMemory|TrackingUnavailable|Trifecta' -race -count=5
```

Expected: PASS.

- [ ] **Step 7: Add RED audit attribution tests**

Add `OriginRuleID string `json:"origin_rule_id,omitempty"`` expectations to `internal/audit/audit_test.go`:

```go
Record{
	Plane: "opencode", Tool: "Bash", Decision: "allow",
	RuleID: "ask-approved-by-retry", OriginRuleID: "P2.git-checkout-restore",
}
```

Assert synthetic approval JSON includes both IDs, ordinary records omit `origin_rule_id`, and JSON without the field still decodes. Extend the strict adversarial audit contract so the declared additive field is accepted and raw arguments remain absent.

- [ ] **Step 8: Run audit tests and verify RED**

Run:

```bash
/usr/local/go/bin/go test ./internal/audit ./test/adversarial -run 'OriginRule|Audit' -count=1
```

Expected: build failure because `audit.Record.OriginRuleID` does not exist or retry audit omits it.

- [ ] **Step 9: Propagate origin attribution**

Add the optional audit field and copy `v.OriginRuleID` when constructing the record in `cmd/guardrail/hook.go`. Do not expose raw arguments in audit output. Existing JSON remains unchanged because `origin_rule_id` uses `omitempty`.

- [ ] **Step 10: Run exact stress and security verification**

Run:

```bash
/usr/local/go/bin/gofmt -w cmd/guardrail/hook.go cmd/guardrail/hook_test.go internal/audit/audit.go internal/audit/audit_test.go test/adversarial/adversarial_test.go
/usr/local/go/bin/go test ./cmd/guardrail -run 'OpenCodeApproval|ApprovalMemory' -race -count=100
/usr/local/go/bin/go test ./internal/session ./internal/adapter ./internal/engine ./internal/audit ./internal/genconfig ./cmd/guardrail -race -count=20
/usr/local/go/bin/go test ./... -count=1
/usr/local/go/bin/go vet ./...
GOOS=windows GOARCH=amd64 /usr/local/go/bin/go build ./...
git diff --check
```

Expected: all commands exit 0 with no race reports, test failures, vet findings, build errors, or whitespace errors.

- [ ] **Step 11: Inspect persisted and audit data**

Run the focused tests with retained temporary fixtures or add assertions in the tests themselves. Confirm:

- approval maps contain only digest keys, Rule IDs, and expiry timestamps;
- session filenames contain only the M-7 v2 digest;
- audit records contain no native argument object;
- only the synthetic retry Allow has `origin_rule_id`;
- current Deny never becomes Allow;
- after one consumed approval, the next identical call asks again.

- [ ] **Step 12: Commit Task 3**

```bash
git add cmd/guardrail/hook.go cmd/guardrail/hook_test.go internal/audit/audit.go internal/audit/audit_test.go test/adversarial/adversarial_test.go
git commit -m "feat: remember one OpenCode approval retry (NF-13)"
```

Stop after the local commit and independent review. Do not merge, push, publish, deploy, or tag.
