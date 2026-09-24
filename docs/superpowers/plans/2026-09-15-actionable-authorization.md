# Actionable Operator Authorization Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make every supported plane give coding agents an actionable, safe continuation message for Engine `ask` and `deny` Verdicts.

**Architecture:** Keep policy classification unchanged. A new pure adapter helper owns the shared `ask` and `deny` semantics; each Adapter owns an exact native-action display string and inserts the helper result into its own protocol response. The hook passes the normalized `engine.ToolCall` to renderers so no renderer reconstructs a broader action from policy fields.

**Tech Stack:** Go 1.25, Node.js for generated OpenCode plugin tests, Go standard library JSON encoding.

**Spec:** `docs/superpowers/specs/2026-09-15-actionable-authorization-design.md`

## Global Constraints

- Do not change any rule from `deny` to `ask` or `allow`.
- A `deny` never starts an approval interaction and must not recommend a manual bypass.
- An `ask` requires operator authorization for the exact action and permits only one identical retry under existing plane mechanics.
- Preserve protocol decisions and exits: Claude Ask remains `ask`, OpenCode Ask remains exit 0 and Deny exit 2, Antigravity Ask remains `force_ask`, and Antigravity post output remains `{}`.
- Exact action displays come from each plane's original native action data, encoded safely for a single response field.
- Retain OpenCode's existing ten-minute, exact-call, one-shot approval memory and audit behavior.

---

### Task 1: Shared Guidance Contract

**Files:**
- Create: `internal/adapter/guidance.go`
- Create: `internal/adapter/guidance_test.go`

**Interfaces:**
- Consumes: `policy.Verdict{Decision, Reason}` and a native action display string.
- Produces: `Guidance(v policy.Verdict, action string) string`, returning policy reason alone for `allow`, the approved authorization instruction for `ask`, and the approved non-authorizable instruction for `deny`.

- [ ] **Step 1: Write the failing shared-guidance tests**

```go
func TestGuidanceAskRequiresAuthorizationForExactAction(t *testing.T) {
	v := policy.Verdict{Decision: policy.Ask, Reason: "external egress needs approval"}
	got := Guidance(v, `bash {"command":"curl https://example.test"}`)
	for _, want := range []string{
		"Operator authorization required: external egress needs approval.",
		`Request authorization for this exact action: bash {"command":"curl https://example.test"}.`,
		"If the operator approves, retry this exact tool call once.",
		"Do not alter or broaden the action.",
	} {
		if !strings.Contains(got, want) { t.Fatalf("Guidance() = %q, missing %q", got, want) }
	}
}

func TestGuidanceDenyCannotBeAuthorized(t *testing.T) {
	v := policy.Verdict{Decision: policy.Deny, Reason: "destructive path is protected"}
	got := Guidance(v, `bash {"command":"rm -rf /"}`)
	if got != "Guardrail denied this action: destructive path is protected. It cannot be authorized. Choose a safe alternative." {
		t.Fatalf("Guidance() = %q", got)
	}
}
```

- [ ] **Step 2: Run the new tests to verify failure**

Run: `/usr/local/go/bin/go test ./internal/adapter/ -run 'TestGuidance(Ask|Deny)' -v`

Expected: FAIL because `Guidance` is undefined.

- [ ] **Step 3: Implement the pure semantic renderer**

```go
func Guidance(v policy.Verdict, action string) string {
	switch v.Decision {
	case policy.Ask:
		return fmt.Sprintf("Operator authorization required: %s. Request authorization for this exact action: %s. If the operator approves, retry this exact tool call once. Do not alter or broaden the action.", v.Reason, action)
	case policy.Deny:
		return fmt.Sprintf("Guardrail denied this action: %s. It cannot be authorized. Choose a safe alternative.", v.Reason)
	default:
		return v.Reason
	}
}
```

Keep escaping and output-boundary sanitization in the protocol emitters, where it already belongs; tests in subsequent tasks prove the fully composed message is safe in each wire shape.

- [ ] **Step 4: Run the shared-guidance tests to verify success**

Run: `/usr/local/go/bin/go test ./internal/adapter/ -run 'TestGuidance(Ask|Deny)' -v`

Expected: PASS.

- [ ] **Step 5: Commit the shared contract**

```bash
git add internal/adapter/guidance.go internal/adapter/guidance_test.go
```

### Task 2: Render Guidance In Every Plane

**Files:**
- Modify: `cmd/guardrail/hook.go: final Verdict emitter switch`
- Modify: `internal/adapter/claude.go: EmitClaude`
- Modify: `internal/adapter/claude_emit_test.go`
- Modify: `internal/adapter/opencode.go: EmitOpencode`
- Modify: `internal/adapter/opencode_test.go`
- Modify: `internal/adapter/antigravity.go: EmitAntigravity`
- Modify: `internal/adapter/antigravity_test.go`

**Interfaces:**
- Consumes: final `policy.Verdict` and the original `engine.ToolCall` available in `cmdHook`.
- Produces: emitters accepting the call needed to display native action data: `EmitClaude(v policy.Verdict, event string, tc engine.ToolCall, stdout io.Writer, stderr io.Writer)`, `EmitOpencode(v policy.Verdict, tc engine.ToolCall, stdout io.Writer, stderr io.Writer)`, and `EmitAntigravity(v policy.Verdict, phase string, tc engine.ToolCall, stdout io.Writer)`.

- [ ] **Step 1: Add failing per-adapter output tests**

Add one Ask and one Deny assertion to each emitter test suite. Construct a `ToolCall` from the plane's parser fixture data so the assertion covers its original native call representation. Decode JSON before asserting message content.

```go
assertContainsAll(t, decoded.HookSpecificOutput.PermissionDecisionReason,
	"Operator authorization required: needs approval.",
	"Request authorization for this exact action: Bash",
	"If the operator approves, retry this exact tool call once.",
	"Do not alter or broaden the action.",
)
assertContainsAll(t, stderr.String(),
	"Guardrail denied this action: protected target.",
	"It cannot be authorized.",
	"Choose a safe alternative.",
)
```

For Antigravity, assert pre-hook Ask remains `force_ask`, pre-hook Deny remains `deny`, and a post-hook call remains exactly `{}`. For OpenCode, assert Ask still exits successfully and Deny still returns exit 2.

- [ ] **Step 2: Run adapter tests to verify failure**

Run: `/usr/local/go/bin/go test ./internal/adapter/ -run 'TestEmit(Claude|Opencode|Antigravity)' -v`

Expected: FAIL because the current emitters receive no action and return only the policy reason.

- [ ] **Step 3: Pass `ToolCall` to the renderers and format native actions**

In `cmdHook`, pass the final `tc` through all three emitter calls. In each adapter, format the plane's original action as `<native tool name> <JSON-encoded original arguments>`:

```go
func nativeAction(tool string, arguments any) string {
	b, err := json.Marshal(arguments)
	if err != nil { return tool }
	return tool + " " + string(b)
}
```

Use the original parsed raw/native argument object for the relevant plane rather than normalized `Command` or `Paths`. Call `Guidance(v, action)` before the existing protocol-specific reason sanitization. Keep `allow` response content and post-hook Antigravity behavior unchanged.

- [ ] **Step 4: Run the adapter tests to verify success**

Run: `/usr/local/go/bin/go test ./internal/adapter/ -v`

Expected: PASS, including prior sanitization and protocol-shape tests.

- [ ] **Step 5: Run hook integrations and extend missing Ask coverage**

Add Claude and Antigravity Ask cases in `cmd/guardrail/hook_test.go`; decode their emitted JSON and assert the shared authorization instruction, policy reason, and action. Retain the existing OpenCode approval-memory tests without semantic changes.

Run: `/usr/local/go/bin/go test ./cmd/guardrail/ -run 'TestHook(Claude|Opencode|Antigravity)|TestOpenCodeApproval' -v`

Expected: PASS, including the test where a current Deny overrides a pending OpenCode approval.

- [ ] **Step 6: Commit the cross-plane rendering**

```bash
git add cmd/guardrail/hook.go cmd/guardrail/hook_test.go internal/adapter/claude.go internal/adapter/claude_emit_test.go internal/adapter/opencode.go internal/adapter/opencode_test.go internal/adapter/antigravity.go internal/adapter/antigravity_test.go
```

### Task 3: Make OpenCode Use The Shared Message

**Files:**
- Modify: `internal/genconfig/opencode_plugin.js: callGuardrail`
- Modify: `internal/genconfig/opencode_test.go: OpenCode plugin message tests`

**Interfaces:**
- Consumes: the existing Go adapter JSON payload `{decision, reason}` where `reason` now holds the shared guidance for `ask` and `deny`.
- Produces: a plugin error equal to `guardrail: <reason>` for every non-allow decision; no plugin-local authorization prose.

- [ ] **Step 1: Update plugin tests to expect the shared messages**

Replace the old exact Ask expectation containing `needs confirmation` and `Ask the user`. Make Ask expect the full Go-provided authorization instruction and make Deny expect the `cannot be authorized` and `Choose a safe alternative` guidance. Add an assertion that neither message contains `needs confirmation` or `re-run this exact tool call` from legacy plugin composition.

```go
if !strings.Contains(errText, "Operator authorization required: external egress needs approval.") { t.Fatal(errText) }
if strings.Contains(errText, "needs confirmation") { t.Fatal(errText) }
```

- [ ] **Step 2: Run the plugin test to verify failure**

Run: `/usr/local/go/bin/go test ./internal/genconfig/ -run TestOpencodePluginRequiresExplicitAllow -v`

Expected: FAIL because the JavaScript plugin still adds its own legacy Ask prose.

- [ ] **Step 3: Simplify the plugin non-allow throw**

Replace the decision-specific throw branches with one error built from the Go response reason:

```js
if (response.decision !== "allow") {
  throw new Error(`guardrail: ${response.reason}`)
}
```

Do not change envelope construction, process execution, or the approval-memory retry key.

- [ ] **Step 4: Run generated-plugin tests to verify success**

Run: `/usr/local/go/bin/go test ./internal/genconfig/ -run TestOpencodePlugin -v`

Expected: PASS, including warning-plus-Ask coverage.

- [ ] **Step 5: Commit OpenCode rendering alignment**

```bash
git add internal/genconfig/opencode_plugin.js internal/genconfig/opencode_test.go
```

### Task 4: Align ADRs And Run The Full Gate

**Files:**
- Modify: `docs/adr/0007-opencode-wire-format-and-ask-via-throw.md`
- Modify: `docs/adr/0011-opencode-one-shot-approval-memory.md`
- Test: repository-wide Go, vet, adversarial, and formatting checks.

**Interfaces:**
- Consumes: the approved design at `docs/superpowers/specs/2026-09-15-actionable-authorization-design.md`.
- Produces: ADRs that retain their historical protocol decisions while pointing readers to the current agent-facing authorization contract.

- [ ] **Step 1: Update the superseded wording**

In ADR-0007 and ADR-0011, retain the documented OpenCode throw and approval-memory constraints. Replace the quoted `needs confirmation` copy with a short note that the adapter now emits the Engine-adapter shared operator-authorization guidance from `2026-09-15-actionable-authorization-design.md`; state that a Deny cannot be authorized.

- [ ] **Step 2: Run focused documentation and regression checks**

Run: `/usr/local/go/bin/go test ./test/ -v && /usr/local/go/bin/go test ./test/adversarial/ -v`

Expected: PASS. Contract behavior remains valid because decisions and exits are unchanged; adversarial protocol classification retains valid Ask JSON handling.

- [ ] **Step 3: Run the complete repository gate**

Run: `make check && /usr/local/go/bin/go test ./... && /usr/local/go/bin/go build ./...`

Expected: PASS with no `gofmt` output, successful vet and adversarial tests, all package tests passing, and a successful binary build.

- [ ] **Step 4: Inspect final changes and commit documentation**

Run: `git status --short && git diff --check && git diff -- docs/adr/0007-opencode-wire-format-and-ask-via-throw.md docs/adr/0011-opencode-one-shot-approval-memory.md`

Expected: only intentional ADR wording changes and no whitespace errors.

```bash
git add docs/adr/0007-opencode-wire-format-and-ask-via-throw.md docs/adr/0011-opencode-one-shot-approval-memory.md
```
