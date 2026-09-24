# Capability Boundary Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Turn every hook-visible tool in Claude, OpenCode, and Antigravity into an explicit, tested Guardrail capability boundary.

**Architecture:** Policy owns the capability vocabulary, unknown-tool posture, and exact-host allowance model. Adapters provide declared native tool inventories and safe extracted inputs; the Engine dispatches those capabilities through existing path, mutation, shell, and new direct-web rules. A local operator-owned broker persists web allowances and executes designated operator actions only after an independent browser or TTY approval.

**Tech Stack:** Go 1.25, TOML policy/config, generated JavaScript OpenCode plugin, local loopback HTTP, GitHub-hosted plane configuration.

**Spec:** `docs/superpowers/specs/2026-09-15-capability-boundary-design.md`

## Global Constraints

- Cover Claude Code, OpenCode, and Antigravity; Codex is out of scope.
- Every hook-visible native tool is explicitly classified; missing classification is audit in `audit` posture and Deny in `deny` posture.
- External direct web fetch is Ask unless localhost or an exact operator-authorized hostname; no external Base defaults, paths, ports, URLs, wildcards, or redirects as persistent authorization.
- Search is Ask until its provider destination is verifiable; delegation is Allow only with proven child Guardrail inheritance.
- Never write raw tool arguments, URLs, content, or secrets to audit/session/broker state.
- Browser approval is loopback-only; headless approval requires a separate operator TTY; broker failure, expiry, replay, malformed input, or missing inherited child guard Denies.
- Registered operator actions, initially night mode on/off and persistent web-host grant/revoke, are broker-executed; agents never retry or directly execute their privileged command.

---

### Task 1: Capability Policy And Unknown Posture

**Files:**
- Modify: `internal/policy/policy.go`, `internal/policy/config.go`, `internal/policy/merge.go`, `internal/policy/base.toml`
- Modify: `internal/engine/toolcall.go`
- Create: `internal/policy/capability_test.go`

**Interfaces:**
- Produces `policy.Capability`, `policy.UnknownToolPosture`, and `engine.ToolCall{Plane, NativeTool, Capability, URL, InputShape}`.
- Consumed by Engine evaluation and every adapter inventory.

- [ ] **Step 1: Write failing parser/default tests**

```go
func TestBaseDefaultsUnknownToolsToAudit(t *testing.T) {
	p := mustLoadBase(t)
	if p.UnknownToolPosture != policy.UnknownAudit { t.Fatal(p.UnknownToolPosture) }
}

func TestUnknownPostureRejectsOtherValues(t *testing.T) {
	_, err := policy.ParseUnknownToolPosture("allow")
	if err == nil { t.Fatal("expected error") }
}
```

- [ ] **Step 2: Run the tests and verify RED**

Run: `/usr/local/go/bin/go test ./internal/policy -run 'Test(BaseDefaultsUnknownToolsToAudit|UnknownPostureRejectsOtherValues)' -v`

Expected: FAIL because capability posture does not exist.

- [ ] **Step 3: Add the vocabulary and strict TOML decoding**

Define `Capability` constants `command`, `read_discovery`, `mutation`,
`web_fetch`, `web_search`, `delegation`, `safe_control`, `deny`, and `unknown`.
Define `UnknownAudit` and `UnknownDeny`; Base defaults to audit. Reject every
other persisted posture value during load/merge.

- [ ] **Step 4: Verify GREEN and commit**

Run: `/usr/local/go/bin/go test ./internal/policy -v`

```bash
git add internal/policy internal/engine/toolcall.go
```

### Task 2: Engine Capability Dispatch And Safe Unknown Audit

**Files:**
- Modify: `internal/engine/evaluate.go`, `internal/engine/rules_path.go`, `internal/engine/trifecta_signals.go`
- Modify: `internal/audit/audit.go`, `cmd/guardrail/hook.go`
- Test: `internal/engine/evaluate_test.go`, `internal/engine/rules_path_test.go`, `internal/audit/audit_test.go`, `cmd/guardrail/hook_test.go`

**Interfaces:**
- Consumes Task 1 `ToolCall.Capability` and posture.
- Produces capability-specific Verdicts and audit fields `native_tool`, `capability`, `input_shape`, `audit_kind`.

- [ ] **Step 1: Write failing dispatch tests**

```go
func TestUnknownToolAuditsButAllowsInAuditPosture(t *testing.T) {
	v := engine.Evaluate(engine.ToolCall{NativeTool: "new_tool", Capability: policy.Unknown}, auditPolicy())
	if v.Decision != policy.Allow || v.AuditKind != "unknown-native-tool" { t.Fatal(v) }
}

func TestUnknownToolDeniesInDenyPosture(t *testing.T) {
	v := engine.Evaluate(engine.ToolCall{NativeTool: "new_tool", Capability: policy.Unknown}, denyPolicy())
	if v.Decision != policy.Deny { t.Fatal(v) }
}
```

Add path tests proving `read_discovery` gets directory/file/ambiguous-secret
behavior identical to `Read`, and `mutation` gets write protections.

- [ ] **Step 2: Verify RED**

Run: `/usr/local/go/bin/go test ./internal/engine ./internal/audit -run 'Test(UnknownTool|ReadDiscovery|Mutation)' -v`

Expected: FAIL because capability dispatch/audit fields are absent.

- [ ] **Step 3: Implement dispatch without raw-input logging**

Replace hard-coded file-tool predicates with capability predicates. Dispatch
unknown audit/deny before fallback Allow. Pass only bounded adapter-provided
`InputShape` into audit records; never serialize `Arguments` or raw URL.

- [ ] **Step 4: Verify GREEN and commit**

Run: `/usr/local/go/bin/go test ./internal/engine ./internal/audit ./cmd/guardrail -v`

```bash
git add internal/engine internal/audit cmd/guardrail/hook.go cmd/guardrail/hook_test.go
```

### Task 3: Guardrail-Owned Exact-Host Fetch Proxy

**Files:**
- Modify: `internal/policy/{policy.go,config.go,operator.go,merge.go}`
- Modify: `internal/engine/rules_net.go`, `internal/engine/rules_net_test.go`
- Create: `internal/fetch/proxy.go`, `internal/fetch/proxy_test.go`
- Modify: `cmd/guardrail/run.go`
- Test: `internal/policy/{config_test.go,operator_test.go,merge_test.go}`

**Interfaces:**
- Produces `NormalizeWebFetchURL(raw) (host string, err error)`, exact global/repository web-host allowances, and `guardrail fetch <URL>`.
- Native plane web fetch Denies. The proxy permits only unauthenticated HTTP(S) GET, validates every redirect host, normalizes allowed text response types, caps output at 1 MiB, and Asks for unapproved hosts.

- [ ] **Step 1: Write failing URL and scope-isolation tests**

```go
func TestFetchAsksForUnapprovedExternalHost(t *testing.T) {
	v := checkFetchURL("https://pkg.go.dev/net", emptyPolicy())
	if v.Decision != policy.Ask { t.Fatal(v) }
}
func TestWebHostAllowanceRejectsURLAndWildcard(t *testing.T) {
	if err := policy.ValidateWebHost("https://pkg.go.dev"); err == nil { t.Fatal("accepted URL") }
	if err := policy.ValidateWebHost("*.example.com"); err == nil { t.Fatal("accepted wildcard") }
}
```

- [ ] **Step 2: Verify RED**

Run: `/usr/local/go/bin/go test ./internal/engine ./internal/policy -run 'TestWeb(Fetch|Host)' -v`

Expected: FAIL because the Guardrail fetch proxy does not exist.

- [ ] **Step 3: Implement strict hostname policy**

Add operator-global and exact-repository host fields as a new explicit Operator
config table; preserve existing Overlay grant behavior for repo scope. Implement
only `guardrail fetch <URL>` as an agent-callable Guardrail subcommand. Require
absolute `http`/`https` URLs, canonical lowercase hostnames, no port/URL
allowance values, and no glob matching. Use a proxy HTTP client with no cookies,
credentials, bodies, arbitrary headers, proxy settings, or non-GET methods;
validate each redirect host before following; accept text/HTML/Markdown/JSON,
normalize HTML, and cap output at 1 MiB. Do not weaken existing Bash P6 matching.

- [ ] **Step 4: Verify GREEN and commit**

Run: `/usr/local/go/bin/go test ./internal/engine ./internal/policy -v`

```bash
git add internal/policy internal/engine/rules_net.go internal/engine/rules_net_test.go
```

### Task 4: Trusted Allowance And Operator-Action Broker

**Files:**
- Create: `internal/approval/broker.go`, `internal/approval/daemon.go`, `internal/approval/browser.go`, `internal/approval/broker_test.go`
- Modify: `internal/session/session.go`, `internal/audit/audit.go`, `internal/engine/rules_path.go`
- Modify: `cmd/guardrail/run.go`, `cmd/guardrail/hook.go`, `cmd/guardrail/night.go`
- Create: `cmd/guardrail/approvals.go`, `cmd/guardrail/approvals_test.go`
- Test: `cmd/guardrail/hook_test.go`, `cmd/guardrail/night_test.go`

**Interfaces:**
- Produces `approval.Request{ID, Plane, SessionID, RepoRoot, Host, Scope, Reason, Action, Parameters, ExpiresAt}` and atomic `Approve`/`Deny`/`Expire` transitions.
- Provides `guardrail approvals --request <id>` only to an operator TTY and loopback browser approval when desktop transport is available.
- Produces a structured operator-action verdict for registered self-configuration requests; approval executes the internal operation and completes the request without allowing agent command replay.
- Starts an authenticated user-level daemon on demand; hooks submit then exit, and the daemon exits after ten idle minutes with no pending requests or active clients.
- Supports Unix/WSL and macOS through a 0700 Unix socket directory; Windows persistent/operator approvals fail closed until a native named-pipe implementation is validated. Browser approval uses a random 256-bit single-use token that is only passed to the OS browser launcher and never persisted, audited, or returned to the agent.

- [ ] **Step 1: Write failing lifecycle and TTY tests**

```go
func TestApproveConsumesExactUnexpiredRequestOnce(t *testing.T) {
	r := broker.Create(request("repo", "api.example.test"))
	if err := broker.Approve(r.ID, approval.RepoScope); err != nil { t.Fatal(err) }
	if err := broker.Approve(r.ID, approval.RepoScope); err == nil { t.Fatal("replay accepted") }
}
func TestApprovalsRefusesNonTerminal(t *testing.T) {
	if code := cmdApprovals([]string{"--request", "x"}, false, io.Discard, io.Discard); code == 0 { t.Fatal("accepted pipe") }
}
func TestNightRequestCompletesOnlyThroughBroker(t *testing.T) {
	v := evaluateOperatorAction(nightOnUntil("08:00"))
	if v.OperatorAction != "night-on" || v.Decision != policy.Ask { t.Fatal(v) }
	if err := broker.Approve(v.RequestID, approval.Allow); err != nil { t.Fatal(err) }
	if !nightActive() { t.Fatal("night mode inactive") }
}
```

- [ ] **Step 2: Verify RED**

Run: `/usr/local/go/bin/go test ./internal/approval ./cmd/guardrail -run 'Test(Approve|Approvals)' -v`

Expected: FAIL because the broker and CLI do not exist.

- [ ] **Step 3: Implement secure state and transports**

Reuse session transactions for hashed, 0600, atomic, bounded, expiry-aware
records. Start an authenticated user-level daemon when no local broker socket
exists; hooks submit requests then exit. Browser transport binds loopback only
and renders the exact request; TTY transport renders the same fields. The daemon
stays alive for pending requests and active clients, then exits after ten idle
minutes. Browser/TTY responses write policy
allowances directly or call the internal registered operator-action handler.
Generate one browser token per request, bind it to the request and expiry, and
pass it only to the OS browser launcher. Enforce 0700 Unix socket ownership or
fail closed on Windows until a current-user pipe implementation exists; stale
Unix sockets restart safely.
Intercept only canonical night on/off and allowance grant/revoke requests before
the normal self-config Deny; all other self-config mutations remain Deny. A
completed action reports completion to the adapter rather than allowing a retry.
No response, browser failure, wrong scope, replay, expiry, or malformed action
permits the caller.

Accept persistent-host actions only in these exact canonical forms:

```text
guardrail egress grant --scope repo|global --host <exact-host>
guardrail egress revoke --scope repo|global --host <exact-host>
```

Reject reordered/extra arguments, shell extensions, URLs, ports, paths,
wildcards, and non-canonical hosts. The approval UI displays and can approve or
deny only the requested scope; it cannot broaden scope.

- [ ] **Step 4: Verify GREEN and commit**

Run: `/usr/local/go/bin/go test ./internal/approval ./cmd/guardrail ./internal/session ./internal/audit -v`

```bash
git add internal/approval internal/session internal/audit cmd/guardrail
```

### Task 5: Claude Capability Inventory And Contract

**Files:**
- Create: `internal/planecontract/claude.go`, `internal/planecontract/contract_test.go`
- Modify: `internal/adapter/claude.go`, `internal/genconfig/claude.go`
- Test: `internal/adapter/claude_test.go`, `internal/genconfig/claude_test.go`, `cmd/guardrail/hook_test.go`, Claude fixtures/goldens

**Interfaces:**
- Produces exact Claude native `ToolSpec` inventory and catch-all pre-hook matcher derived from it.
- Extracts command, path, URL, search, mutation, and delegation inputs into Task 1 `ToolCall`.

- [ ] **Step 1: Write failing inventory/matcher tests**

```go
func TestClaudePreHookCoversEveryInventoryTool(t *testing.T) {
	for _, spec := range planecontract.RegisteredTools("claude") {
		if !generatedClaudePreMatcherMatches(spec.NativeTool) { t.Fatal(spec.NativeTool) }
	}
}
```

- [ ] **Step 2: Verify RED, implement, and verify GREEN**

Run: `/usr/local/go/bin/go test ./internal/adapter ./internal/genconfig -run Claude -v`

Implement classified extraction for Bash/PowerShell, read/discovery, mutation
including NotebookEdit, WebFetch/WebSearch, and explicit MCP unknown denial.
Use a catch-all pre matcher so unclassified calls reach audit/deny posture.
Repeat the command and require PASS.

- [ ] **Step 3: Commit**

```bash
git add internal/planecontract internal/adapter/claude.go internal/genconfig/claude.go internal/adapter/claude_test.go internal/genconfig/claude_test.go cmd/guardrail/hook_test.go test/fixtures/claude
```

### Task 6: OpenCode And Antigravity Capability Contracts

**Files:**
- Modify: `internal/planecontract/*`, `internal/adapter/{opencode,antigravity}.go`
- Modify: `internal/genconfig/{opencode_plugin.js,opencode.go,antigravity.go}`
- Test: associated adapter/genconfig/hook tests and fixtures for both planes

**Interfaces:**
- Extends the shared inventory with every installed-version OpenCode and documented Antigravity hook-visible tool.
- OpenCode plugin forwards tool-specific paths/URL/query; Antigravity uses a catch-all pre matcher and retains `{}` post responses.

- [ ] **Step 1: Write failing matrix tests**

Add fixtures proving OpenCode `apply_patch`, `grep`, `glob`, `webfetch`, and
unknown custom/MCP calls; add Antigravity list/search, direct URL, web search,
mutation, and unknown calls. Assert discovery secret denial, unapproved fetch
Ask, web-search Ask, and unknown audit/deny behavior.

- [ ] **Step 2: Verify RED**

Run: `/usr/local/go/bin/go test ./internal/adapter ./internal/genconfig ./cmd/guardrail -run 'OpenCode|Antigravity' -v`

Expected: FAIL because these native shapes are absent or normalized incorrectly.

- [ ] **Step 3: Implement both inventories and generated contracts**

Classify OpenCode safe controls explicitly; deny custom/MCP until declared.
Use Antigravity `"*"` pre matching and preserve mandatory `{}` post output.
Known path-bearing calls without safe path extraction Deny. Do not add
delegation Allow until Task 7 proves child inheritance.

- [ ] **Step 4: Verify GREEN and commit**

Run: `/usr/local/go/bin/go test ./internal/adapter ./internal/genconfig ./cmd/guardrail -v`

```bash
git add internal/planecontract internal/adapter internal/genconfig cmd/guardrail test/fixtures
```

### Task 7: Delegation Evidence, Rollout, And Adversarial Gate

**Status: Deferred.** Native delegation remains explicitly denied. None of the
currently supported planes supplies hook-visible, verifiable evidence that binds
a distinct child Guardrail registration to its parent delegation, plane, and
repository. Do not implement an Allow path until a plane-specific evidence
transport and its replay, scope, lifecycle, and native-host tests are designed
and approved.

**Files:**
- Create: `internal/delegation/gate.go`, `internal/delegation/gate_test.go`
- Modify: `cmd/guardrail/hook.go`, `cmd/guardrail/doctor.go`, adapter contracts
- Modify: `test/adversarial/adversarial_test.go`, `test/adversarial/corpus.json`, `README.md`, plane docs

**Interfaces:**
- Produces `engine.DelegationGate` backed by single-use child-registration evidence.
- Doctor reports audit/deny posture and unknown-tool event count.

- [ ] **Step 1: Write failing inheritance and rollout tests**

```go
func TestDelegationDeniesWithoutDistinctChildRegistration(t *testing.T) {
	v := gate.Check(parentDelegation())
	if v.Decision != policy.Deny { t.Fatal(v) }
}
func TestDelegationAllowsRegisteredChildOnce(t *testing.T) {
	gate.Register(childEvidence())
	if v := gate.Check(parentDelegation()); v.Decision != policy.Allow { t.Fatal(v) }
}
```

- [ ] **Step 2: Verify RED, implement, and verify GREEN**

Run: `/usr/local/go/bin/go test ./internal/delegation ./cmd/guardrail -run 'TestDelegation|TestDoctor' -v`

Implement atomic evidence binding by plane/session/repository and deny all
missing, expired, replayed, or wrong-child evidence. Document the fourteen-day
zero-unknown operational exit criterion; do not auto-switch posture.

- [ ] **Step 3: Run the final adversarial and full gates**

Run:

```sh
/usr/local/go/bin/go test ./test -count=1
/usr/local/go/bin/go test ./test/adversarial -count=1
make check
/usr/local/go/bin/go test ./...
```

Expected: PASS. Add corpus cases for each former read/write/egress bypass and
state the hosted/opt-out limits plainly in README and plane docs.

- [ ] **Step 4: Commit**

```bash
git add internal/delegation cmd/guardrail test/adversarial README.md docs
```
