# WebAuthn Operator Approval Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Require a local WebAuthn/FIDO2 assertion to execute every persistent operator action, so coding-plane IPC cannot self-approve it.

**Architecture:** Add a focused `internal/operatorauth` module that persists public credentials, creates request-bound WebAuthn ceremonies, and verifies assertions. The loopback browser page becomes the only completion path; the Unix daemon accepts submission/status only, while the existing Broker retains canonical action execution and durable state transitions.

**Tech Stack:** Go 1.24, `github.com/go-webauthn/webauthn@v0.15.0`, browser WebAuthn API, `agent-browser` for loopback UI failure-path tests.

**Spec:** `docs/superpowers/specs/2026-09-16-webauthn-operator-approval-design.md`

## Global Constraints

- Support Unix/WSL and macOS only; Windows operator actions remain fail-closed.
- Bind every assertion to one canonical request ID, issued time, action, canonical action parameters, repository path, scope, exact host, and expiry.
- Require WebAuthn user verification. Never accept a presence-only assertion.
- Bind browser ceremonies to loopback `http://localhost:<ephemeral-port>` and the `localhost` RP ID; never listen beyond loopback.
- Persist only public credential data and public-key WebAuthn state. Never persist private keys, OTP seeds, browser tokens, URLs, challenges, raw assertions, or authenticator labels.
- Socket IPC exposes only submission and non-sensitive status. It must never approve, deny, enroll, manage credentials, reveal a URL/token, or mutate persistent policy.
- Remove TTY approval. A terminal, PTY, and same-UID socket peer do not prove operator identity.
- Fail closed on unavailable browser/authenticator, malformed WebAuthn data, wrong origin/RP ID/challenge/request digest, expiry, replay, missing user verification, or any durable write failure.
- Render canonical request data as escaped text only. Audit only a stable privacy-safe credential fingerprint and `webauthn` transport.
- Initial enrollment is trust-on-first-use performed before coding agents run. Adding/removing credentials requires an enrolled authenticator. Recovery reset disables approvals.
- The dotfiles integration is a later follow-up; it may guide enrollment but must not initiate it automatically.

---

## File Structure

| File | Responsibility |
| --- | --- |
| `internal/operatorauth/store.go` | Private public-credential store, enrollment invariant, credential fingerprints, atomic state persistence. |
| `internal/operatorauth/webauthn.go` | WebAuthn RP construction, request-digest challenge generation, registration/assertion verification. |
| `internal/operatorauth/operatorauth_test.go` | Unit tests for storage, binding, replay, user verification, and redaction. |
| `internal/approval/browser.go` | Loopback page and JSON ceremony endpoints; executes Broker only after verified WebAuthn assertion. |
| `internal/approval/daemon.go` | Submission/status-only IPC and browser lifecycle. |
| `internal/approval/broker.go` | Canonical immutable approval-binding serialization and transport-attributed completion audit hook. |
| `internal/approval/*_test.go` | Socket bypass, loopback endpoint, replay, and daemon lifecycle regressions. |
| `cmd/guardrail/operator.go` | Initial enrollment, authenticated add/remove, and fail-closed recovery-reset commands. |
| `cmd/guardrail/approvals.go` | Daemon-only dispatch; removes terminal approval client. |
| `cmd/guardrail/run.go` | Dispatches `operator`; preserves non-TTY daemon bootstrap. |
| `cmd/guardrail/*_test.go` | CLI parsing and browser-launch integration coverage. |
| `docs/...` and `README.md` | Operator setup, supported authenticators/platforms, limitations, and dotfiles handoff. |

### Task 1: Public Credential Store And Canonical Request Binding

**Files:**
- Create: `internal/operatorauth/store.go`
- Create: `internal/operatorauth/webauthn.go`
- Create: `internal/operatorauth/operatorauth_test.go`
- Modify: `go.mod`, `go.sum`
- Modify: `internal/approval/broker.go`
- Test: `internal/operatorauth/operatorauth_test.go`, `internal/approval/broker_test.go`

**Interfaces:**
- Produces `operatorauth.Store`, `operatorauth.Credential`, `operatorauth.Binding`, and `operatorauth.Ceremony`.
- Consumes `approval.Request` through `operatorauth.BindingFor(approval.Request)`.
- Later tasks call `Store.BeginAssertion(Request, origin)` and `Store.FinishAssertion(requestID, response)`.

- [ ] **Step 1: Write failing public-state and binding tests**

```go
func TestBindingChangesForEveryAuthorizationField(t *testing.T) {
    base := approval.Request{ID: "r1", Action: "web-host-grant", RepoRoot: "/repo", Host: "example.com", Scope: approval.RepoScope, ExpiresAt: time.Now().Add(time.Minute)}
    want := operatorauth.BindingFor(base).Digest()
    for _, changed := range []approval.Request{
        {ID: "r2", Action: base.Action, RepoRoot: base.RepoRoot, Host: base.Host, Scope: base.Scope, ExpiresAt: base.ExpiresAt},
        {ID: base.ID, Action: base.Action, RepoRoot: "/other", Host: base.Host, Scope: base.Scope, ExpiresAt: base.ExpiresAt},
        {ID: base.ID, Action: base.Action, RepoRoot: base.RepoRoot, Host: "other.example", Scope: base.Scope, ExpiresAt: base.ExpiresAt},
        {ID: base.ID, Action: base.Action, RepoRoot: base.RepoRoot, Host: base.Host, Scope: approval.GlobalScope, ExpiresAt: base.ExpiresAt},
    } {
        if got := operatorauth.BindingFor(changed).Digest(); got == want { t.Fatal("changed authorization field retained digest") }
    }
}

func TestStoreWritesOnlyPublicCredentialFields(t *testing.T) {
    store := operatorauth.NewStore(t.TempDir())
    if err := store.Replace([]operatorauth.Credential{{ID: "AQI", PublicKey: "public", Algorithm: -7}}); err != nil { t.Fatal(err) }
    data, err := os.ReadFile(store.Path()); if err != nil { t.Fatal(err) }
    if bytes.Contains(data, []byte("challenge")) || bytes.Contains(data, []byte("assertion")) { t.Fatal("secret ceremony data persisted") }
}
```

- [ ] **Step 2: Run the new tests to verify RED**

Run: `/usr/local/go/bin/go test ./internal/operatorauth ./internal/approval -run 'TestBinding|TestStoreWritesOnly' -count=1`

Expected: FAIL because `operatorauth` does not exist.

- [ ] **Step 3: Add the pinned verifier dependency and minimal store**

Run:

```bash
/usr/local/go/bin/go get github.com/go-webauthn/webauthn@v0.15.0
/usr/local/go/bin/go mod tidy
```

Implement these exact public types:

```go
type Credential struct {
    ID        string `json:"id"`
    PublicKey string `json:"public_key"`
    Algorithm int    `json:"algorithm"`
    SignCount uint32 `json:"sign_count"`
}

type Binding struct {
    RequestID string `json:"request_id"`
    IssuedAt  string `json:"issued_at"`
    Action    string `json:"action"`
    Parameters []Parameter `json:"parameters"`
    RepoRoot  string `json:"repo_root"`
    Host      string `json:"host"`
    Scope     string `json:"scope"`
    ExpiresAt string `json:"expires_at"`
}

func BindingFor(request approval.Request) Binding
func (b Binding) Digest() [32]byte
```

Define `type Parameter struct { Key, Value string }`; populate it from the
durable request parameter map in lexical key order. Add `IssuedAt time.Time`
to `approval.Request` and `session.ApprovalRequest`; assign it once in
`Broker.Create` before durable persistence. `Binding.Digest` serializes this fixed-field struct, prefixed with
`guardrail-approval-v1\x00`, using UTC RFC3339Nano expiry. Do not hash a map or
agent-controlled free text. `Store` writes `authenticators.json` under a
private operator-auth directory using a temporary file, file `Sync`, atomic
rename, and parent-directory `Sync`; reject non-private directories, symlinks,
non-regular files, malformed base64url IDs/keys, duplicate IDs, and empty
replacement sets.

- [ ] **Step 4: Run the Task 1 tests to verify GREEN**

Run: `/usr/local/go/bin/go test ./internal/operatorauth ./internal/approval -run 'TestBinding|TestStoreWritesOnly' -count=1`

Expected: PASS.

- [ ] **Step 5: Commit Task 1**

```bash
git add go.mod go.sum internal/operatorauth internal/approval/broker.go internal/approval/broker_test.go
```

### Task 2: WebAuthn Registration And Assertion Verification

**Files:**
- Modify: `internal/operatorauth/webauthn.go`
- Modify: `internal/operatorauth/operatorauth_test.go`

**Interfaces:**
- Consumes `Store`, `Binding`, and request-bound expiry from Task 1.
- Produces `RegistrationOptions`, `FinishRegistration`, `AssertionOptions`, and `FinishAssertion`.
- Task 3 serves options and submits browser responses through these functions.

- [ ] **Step 1: Write failing WebAuthn ceremony tests**

```go
func TestAssertionRequiresUserVerificationAndExactBinding(t *testing.T) {
    store := enrolledStore(t)
    ceremony, err := store.BeginAssertion(request("repo", "example.com"), "http://localhost:12345")
    if err != nil { t.Fatal(err) }
    if ceremony.Options.Response.UserVerification != protocol.VerificationRequired { t.Fatal("user verification is optional") }
    if err := store.FinishAssertion(ceremony.ID, assertionForWrongChallenge(t)); err == nil { t.Fatal("wrong challenge accepted") }
    if err := store.FinishAssertion(ceremony.ID, assertionWithoutUserVerification(t)); err == nil { t.Fatal("presence-only assertion accepted") }
}

func TestAssertionCannotReplayOrAuthorizeDifferentRequest(t *testing.T) {
    store := enrolledStore(t)
    first := beginAndSign(t, store, request("repo-a", "example.com"))
    if err := store.FinishAssertion(first.ID, first.Response); err != nil { t.Fatal(err) }
    if err := store.FinishAssertion(first.ID, first.Response); err == nil { t.Fatal("replay accepted") }
}
```

- [ ] **Step 2: Run the ceremony tests to verify RED**

Run: `/usr/local/go/bin/go test ./internal/operatorauth -run 'TestAssertion' -count=1`

Expected: FAIL because ceremony APIs do not exist.

- [ ] **Step 3: Implement strict WebAuthn ceremony APIs**

Implement:

```go
type Ceremony struct {
    ID        string
    Binding   Binding
    ExpiresAt time.Time
    Options   any
}

func (s *Store) BeginRegistration(origin string) (Ceremony, error)
func (s *Store) FinishRegistration(ceremonyID string, response []byte) (Credential, error)
func (s *Store) BeginAssertion(request approval.Request, origin string) (Ceremony, error)
func (s *Store) FinishAssertion(ceremonyID string, response []byte) (Credential, error)
```

Construct the WebAuthn RP with `RPID: "localhost"` and only the exact dynamic
`http://localhost:<port>` origin for the current browser. Registration and
assertion ceremonies are in-memory, expire with the approval request, and are
deleted before returning either success or failure. Require `UserVerification:
protocol.VerificationRequired`, restrict assertion allow credentials to enrolled
IDs, and verify the signed challenge embeds the Task 1 binding digest. Return
only a stable SHA-256 prefix fingerprint of the credential ID to callers.

- [ ] **Step 4: Run verifier tests to verify GREEN**

Run: `/usr/local/go/bin/go test ./internal/operatorauth -count=1`

Expected: PASS, including wrong origin, RP ID, challenge, expiry, replay, and
missing-user-verification coverage.

- [ ] **Step 5: Commit Task 2**

```bash
git add internal/operatorauth
```

### Task 3: Replace Browser Buttons With WebAuthn-Only Completion

**Files:**
- Modify: `internal/approval/browser.go`
- Modify: `internal/approval/broker.go`
- Modify: `internal/approval/broker_test.go`
- Create: `internal/approval/browser_e2e_test.go`

**Interfaces:**
- Consumes `operatorauth.Store.BeginAssertion` and `FinishAssertion` from Task 2.
- Produces `StartBrowser(broker, authStore, requestID)` and a browser-only
  completion path that invokes `Broker.Approve` after verified assertion.
- Task 4 supplies the default store to the daemon.

- [ ] **Step 1: Write failing loopback-handler tests**

```go
func TestBrowserNeverCompletesFromFormChoice(t *testing.T) {
    page := newApprovalPage(t, enrolledStore(t), pendingRequest(t))
    response := postForm(t, page.URL, url.Values{"choice": {"approve"}})
    if response.StatusCode != http.StatusNotFound { t.Fatalf("form approval = %d", response.StatusCode) }
    if got := pendingRequestState(t); got != "pending" { t.Fatalf("status = %s", got) }
}

func TestBrowserAssertionCompletesExactRequestOnce(t *testing.T) {
    page := newApprovalPage(t, enrolledStore(t), pendingRequest(t))
    assertion := validAssertionForPage(t, page)
    postJSON(t, page.URL+"/assertion", assertion).Result().StatusCode == http.StatusOK
    if got := pendingRequestState(t); got != "completed" { t.Fatalf("status = %s", got) }
    if postJSON(t, page.URL+"/assertion", assertion).Result().StatusCode != http.StatusGone { t.Fatal("replay accepted") }
}
```

- [ ] **Step 2: Run handler tests to verify RED**

Run: `/usr/local/go/bin/go test ./internal/approval -run 'TestBrowser(Never|Assertion)' -count=1`

Expected: FAIL because form buttons currently call `Broker.Approve` and
`Broker.Deny` directly.

- [ ] **Step 3: Implement the loopback ceremony page**

Replace the token/form page with a page that displays escaped canonical request
fields and calls `navigator.credentials.get({publicKey: options})`. It posts the
browser's base64url-encoded credential response to one `/assertion` endpoint.
That endpoint calls `FinishAssertion`; only on success it calls
`Broker.Approve(requestID, storedScope)`, closes the page, and emits a
completion audit through the existing action handler path.

The page has no HTML form choice, no generic completion endpoint, and no token
in query strings. `GET /` returns 410 for non-pending/expired requests;
`POST /assertion` returns 404 for malformed/missing data, 403 for failed
verification, and 410 for expired/consumed requests. Closing the browser
leaves the request pending until expiry; it must never create a socket/HTTP
completion or denial mutation without an assertion.

- [ ] **Step 4: Add `agent-browser` failure-path coverage**

Run the browser E2E test against a loopback page and assert that canonical
fields are visible, a page with no WebAuthn credential cannot complete, and a
raw form/JSON approval attempt leaves the request pending. Keep successful
authenticator approval as a manual smoke test because CI has no physical
authenticator.

- [ ] **Step 5: Run Task 3 tests to verify GREEN**

Run: `/usr/local/go/bin/go test ./internal/approval -count=1`

Expected: PASS.

- [ ] **Step 6: Commit Task 3**

```bash
git add internal/approval
```

### Task 4: Lock Down Daemon IPC And Remove TTY Approval

**Files:**
- Modify: `internal/approval/daemon.go`
- Modify: `internal/approval/daemon_test.go`
- Modify: `internal/approval/daemon_internal_test.go`
- Modify: `cmd/guardrail/approvals.go`
- Modify: `cmd/guardrail/run.go`
- Modify: `cmd/guardrail/approvals_test.go`
- Modify: `cmd/guardrail/run_test.go`

**Interfaces:**
- Consumes browser-only completion from Task 3.
- Produces a daemon protocol that accepts exactly `submit` and `status`.
- Task 5 consumes the daemon and the new `operator` CLI dispatch.

- [ ] **Step 1: Write failing bypass regression tests**

```go
func TestDaemonRejectsApproveAndDenyMessages(t *testing.T) {
    daemon, socket, request := runningDaemonWithPendingRequest(t)
    defer daemon.Close()
    for _, message := range []daemonMessage{{Operation: "approve", ID: request.ID, Scope: request.Scope}, {Operation: "deny", ID: request.ID}} {
        reply := sendRaw(t, socket, message)
        if reply.Error == "" { t.Fatalf("%s accepted", message.Operation) }
        if got := brokerStatus(t, request.ID); got != "pending" { t.Fatalf("%s changed request to %s", message.Operation, got) }
    }
}

func TestApprovalsRejectsTTYClientMode(t *testing.T) {
    if got := cmdApprovalsInput([]string{"--request", "known"}, true, strings.NewReader("y\n"), io.Discard, io.Discard); got != 2 { t.Fatalf("exit = %d", got) }
}
```

- [ ] **Step 2: Run bypass tests to verify RED**

Run: `/usr/local/go/bin/go test ./internal/approval ./cmd/guardrail -run 'TestDaemonRejects|TestApprovalsRejects' -count=1`

Expected: FAIL because the daemon accepts `approve`/`deny` and the TTY client
calls them.

- [ ] **Step 3: Make IPC submission/status-only**

Replace `request` with `status`, returning only request ID, pending/completed
state, and expiry; never return plane, repo, host, action, scope, parameters,
or browser material. Delete exported `approval.Approve`, `approval.Deny`, and
`approval.Lookup` socket clients. Delete all interactive `approvals --request`
parsing; retain only the internal `approvals daemon` invocation and dispatch it
before the terminal check in `run`.

In `Daemon.handle`, reject every operation other than `submit` and `status`
with one generic error and ensure neither branch calls `Broker.Approve`,
`Broker.Deny`, registration, or policy mutation. Keep browser launch failure
fail-closed: the pending request expires without a completion fallback.

- [ ] **Step 4: Run Task 4 tests to verify GREEN**

Run: `/usr/local/go/bin/go test ./internal/approval ./cmd/guardrail -count=1`

Expected: PASS, including production-binary daemon/on-demand tests.

- [ ] **Step 5: Commit Task 4**

```bash
git add internal/approval cmd/guardrail
```

### Task 5: Authenticator Management CLI, Audit, Documentation, And Gates

**Files:**
- Create: `cmd/guardrail/operator.go`
- Create: `cmd/guardrail/operator_test.go`
- Modify: `cmd/guardrail/run.go`
- Modify: `cmd/guardrail/hook.go`
- Modify: `cmd/guardrail/doctor.go`
- Modify: `README.md`
- Create: `docs/operator-approvals.md`
- Modify: `test/adversarial/corpus.json`, `test/adversarial/adversarial_test.go`
- Modify: `docs/superpowers/specs/2026-09-16-webauthn-operator-approval-design.md`

**Interfaces:**
- Consumes `operatorauth.Store` and ceremony APIs from Tasks 1-2; daemon
  browser completion from Task 3; restricted IPC from Task 4.
- Produces `guardrail operator enroll`, `add-authenticator`,
  `remove-authenticator`, and `recover-reset` commands plus final deployment
  documentation.

- [ ] **Step 1: Write failing CLI and audit tests**

```go
func TestInitialEnrollmentRequiresNoExistingCredential(t *testing.T) {
    if got := cmdOperator([]string{"enroll"}, testTerminal(), io.Discard, io.Discard); got != 0 { t.Fatalf("first enrollment = %d", got) }
    if got := cmdOperator([]string{"enroll"}, testTerminal(), io.Discard, io.Discard); got != 2 { t.Fatalf("second enrollment = %d", got) }
}

func TestCredentialManagementRequiresAssertionAndNeverEmptiesStore(t *testing.T) {
    // Add/remove management requests require a valid assertion; removing the
    // last credential is rejected before state mutation.
}

func TestAdversarialSocketApprovalCannotPersistEgressGrant(t *testing.T) {
    // Submit canonical egress grant, send raw approve over socket, assert no
    // Operator config or Overlay grant exists after expiry.
}
```

- [ ] **Step 2: Run Task 5 tests to verify RED**

Run: `/usr/local/go/bin/go test ./cmd/guardrail ./test/adversarial -run 'Test(InitialEnrollment|CredentialManagement|AdversarialSocketApproval)' -count=1`

Expected: FAIL because `operator` commands and the final adversarial fixture do
not exist.

- [ ] **Step 3: Implement management commands and audit attribution**

Add `operator` dispatch. `enroll` is permitted only with an empty store and
requires an interactive local terminal; it starts registration and waits for the
local browser ceremony. `add-authenticator` and `remove-authenticator` use an
existing-authenticator assertion. Reject removal of the final credential.
`recover-reset` deletes public credential state only after explicit local
confirmation, writes an audit record, and leaves all operator actions disabled.

Extend approval completion audit data with `transport: "webauthn"` and a
fingerprint derived from the credential ID. Do not add raw WebAuthn artifacts.
Update doctor to report `operator approvals: disabled` when no credential is
enrolled and `operator approvals: WebAuthn` otherwise, while retaining Windows
fail-closed reporting.

Document initial trust-on-first-use, exact canonical prompt fields, physical
authenticator/manual smoke requirements, vendor-neutral passkey support,
cross-device limitations, recovery behavior, same-user OS bypass limits, and
the deferred dotfiles enrollment guidance. Do not claim browser automation or
same-UID OS isolation is impossible to bypass.

- [ ] **Step 4: Run final automated gates**

Run:

```bash
/usr/local/go/bin/go test ./test -count=1
/usr/local/go/bin/go test ./test/adversarial -count=1
make check
/usr/local/go/bin/go test ./... -count=1
/usr/local/go/bin/go vet ./...
GOOS=windows GOARCH=amd64 /usr/local/go/bin/go build -o /tmp/guardrail-windows-test.exe ./cmd/guardrail
```

Expected: PASS. The Windows build must pass while runtime operator actions
remain explicitly fail-closed.

- [ ] **Step 5: Run manual authenticator smoke tests**

On each supported browser/platform pair, enroll a physical FIDO2 key or
platform passkey, submit a night-mode action and an exact-host grant, verify the
browser displays canonical fields, satisfy authenticator user verification,
confirm one completion audit per action, and verify replay/expired pages fail.

- [ ] **Step 6: Commit Task 5**

```bash
git add cmd/guardrail internal/operatorauth internal/approval test README.md docs
```

## Plan Self-Review

- Spec coverage: Tasks 1-2 implement public-only credentials and strict,
  request-bound WebAuthn verification. Task 3 makes WebAuthn the only browser
  completion path. Task 4 removes the socket/TTY bypass. Task 5 covers
  enrollment, management, audit, docs, adversarial tests, manual supported-host
  validation, Windows fail-closed posture, and the dotfiles handoff.
- Placeholder scan: every implementation/test step specifies the behavior,
  interfaces, and commands needed; no work is deferred inside this plan.
- Type consistency: Task 1 defines `Binding`, `Store`, and `Credential`; Task 2
  defines ceremony methods; Task 3 consumes them; Task 4 restricts the daemon;
  Task 5 exposes the resulting operations.
