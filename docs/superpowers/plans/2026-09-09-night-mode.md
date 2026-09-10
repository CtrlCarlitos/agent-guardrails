# Night Mode Implementation Plan

> **For OpenCode:** REQUIRED SUB-SKILL: Use superpowers:test-driven-development while implementing each task.

**Goal:** Add an operator-controlled, expiring night mode that turns every runtime Ask into an audited Allow without weakening any Deny on Claude, OpenCode, or Antigravity.

**Architecture:** A small `internal/night` package owns the marker's platform path, strict TOML lifecycle, and active-state/banner model. The command-hook pipeline reads that state once for every invocation, suppresses OpenCode approval-memory mutation while active, and applies one Engine-owned Verdict transform after all normal policy and Recipe evaluation but before audit and Adapter emission. CLI, doctor, and Claude SessionStart consume the same package; the existing Engine Bash classifier protects the command itself as `P5.self-config`, while the CLI independently requires terminal stdin for `night on` and `night off`.

**Tech Stack:** Go, BurntSushi TOML, existing Engine/Adapter/audit packages, table-driven tests, adversarial JSON corpus.

---

### Task 1: Marker Model And Platform Path

**Files:**
- Create: `internal/night/night.go`
- Create: `internal/night/night_test.go`
- Modify: `internal/policy/operator.go`
- Modify: `internal/policy/operator_test.go`

**Step 1: Write the failing path and lifecycle tests**

Cover Linux/XDG, home fallback, Windows APPDATA, invalid relative environment paths, missing marker, active marker, exact-expiry inactivity, expired marker retention, malformed TOML, missing/zero `until`, unknown keys, and unreadable/non-regular marker behavior. Use `t.Setenv` plus test-only explicit path/time inputs so tests never read or alter the operator's real marker.

**Step 2: Run the focused tests to verify RED**

Run: `go test ./internal/night ./internal/policy`

Expected: FAIL because the night package and shared Operator-config-directory resolver do not exist.

**Step 3: Implement the minimal marker API**

Export a validated Operator config directory helper from `internal/policy/operator.go` and continue deriving `waivers.toml` from it. In `internal/night/night.go`, define the marker path `night.toml`, a marker containing `Until time.Time` and `SetBy string`, strict loading, `Active(now)`, atomic `0600` persistence under a `0700` directory, idempotent removal, and a single-line `NIGHT MODE until <time>` banner. Treat absence and expiry as inactive; return malformed/unreadable state as an error without deleting or enabling it.

**Step 4: Run focused tests to verify GREEN**

Run: `go test ./internal/night ./internal/policy`

Expected: PASS.

**Step 5: Commit**

```bash
git add internal/night/night.go internal/night/night_test.go internal/policy/operator.go internal/policy/operator_test.go
git commit -m "feat(night): add expiring operator marker"
```

### Task 2: Night CLI Lifecycle

**Files:**
- Create: `cmd/guardrail/night.go`
- Create: `cmd/guardrail/night_test.go`
- Modify: `cmd/guardrail/run.go`
- Modify: `cmd/guardrail/run_test.go`

**Step 1: Write failing command tests**

Test help/dispatch and the exact approved lifecycle: `on` defaults to eight hours, `--for` accepts one positive Go duration, `--until HH:MM` chooses the next local occurrence, the two expiry flags are mutually exclusive, unexpected arguments and invalid/non-positive expiry fail without changing the marker, `off` is idempotent, and `status` reports active/inactive/error with the specified output and exit codes. Assert `set_by` is `<hostname>:<pid>`, require terminal stdin for `on` and `off` but not `status`, cover a renamed binary under null stdin, and isolate storage with `XDG_CONFIG_HOME` or an injected path.

**Step 2: Run the focused tests to verify RED**

Run: `go test ./cmd/guardrail -run 'Test(RunNight|Night)'`

Expected: FAIL because `night` is not dispatched.

**Step 3: Implement the CLI**

Add `night` to usage and dispatch. Parse arguments with a private `flag.FlagSet`, compute deadlines using local time before storing RFC3339-capable absolute instants, persist through `internal/night`, reject `on` and `off` before marker access unless stdin is a terminal, sanitize operator-facing errors, and keep all status output deterministic and single-line where the spec requires it.

**Step 4: Run focused tests to verify GREEN**

Run: `go test ./cmd/guardrail -run 'Test(RunNight|Night)'`

Expected: PASS.

**Step 5: Commit**

```bash
git add cmd/guardrail/night.go cmd/guardrail/night_test.go cmd/guardrail/run.go cmd/guardrail/run_test.go
git commit -m "feat(cli): add night mode controls"
```

### Task 3: Shared Verdict Rendering And Audit Provenance

**Files:**
- Create: `internal/engine/night.go`
- Create: `internal/engine/night_test.go`
- Modify: `cmd/guardrail/hook.go`
- Modify: `cmd/guardrail/hook_test.go`

**Step 1: Write failing transform and hook tests**

Table-test inactive Allow/Ask/Deny and active Allow/Ask/Deny. The only active rewrite must be Ask to `policy.Allow` with `rule_id = "ask-allowed-by-night-mode"`, the prior rule in `origin_rule_id`, and a stable reason. Add hook coverage proving the same emitted Allow on Claude, OpenCode, and Antigravity, Deny preservation, one marker read per invocation, live on/off changes between invocations, audit provenance, no consumption/creation of OpenCode approval memory while active, and fail-closed normal posture plus a warning for malformed/unreadable markers.

**Step 2: Run the focused tests to verify RED**

Run: `go test ./internal/engine ./cmd/guardrail -run 'Test.*Night'`

Expected: FAIL because the transform and hook integration do not exist.

**Step 3: Implement the shared pipeline seam**

Add the pure Engine transform. Load night state once near the start of each hook call; append a sanitized high-priority warning on load failure and remain inactive. While active, disable OpenCode approval-memory handling for that call. Apply the transform after Engine, Trifecta, approval-memory, and Recipe checks, then use the transformed Verdict for the existing audit record and Adapter emission. If that night-mode audit write fails, fall back to the original Ask rather than emitting an unaudited Allow. Do not add plane-specific night policy branches.

**Step 4: Run focused tests to verify GREEN**

Run: `go test ./internal/engine ./cmd/guardrail -run 'Test.*Night'`

Expected: PASS.

**Step 5: Commit**

```bash
git add internal/engine/night.go internal/engine/night_test.go cmd/guardrail/hook.go cmd/guardrail/hook_test.go
git commit -m "feat(engine): render asks through night mode"
```

### Task 4: Operator Visibility And P5 Self-Protection

**Files:**
- Modify: `cmd/guardrail/doctor.go`
- Modify: `cmd/guardrail/doctor_test.go`
- Modify: `cmd/guardrail/hook.go`
- Modify: `cmd/guardrail/hook_test.go`
- Modify: `internal/session/session.go`
- Modify: `internal/engine/rules_bash.go`
- Modify: `internal/engine/rules_bash_test.go`
- Modify: `internal/engine/rules_path.go`
- Modify: `internal/engine/rules_path_test.go`
- Modify: `internal/genconfig/claude.go`
- Modify: `internal/genconfig/claude_test.go`
- Modify: `internal/genconfig/opencode_plugin.js`
- Modify: `internal/genconfig/opencode_test.go`
- Create: `cmd/guardrail/main_test.go`

**Step 1: Write failing visibility and protection tests**

Assert that active doctor output and Claude SessionStart context begin with the shared night banner, inactive output is unchanged, and invalid marker state is visible without claiming activation. For OpenCode and Antigravity, persist the announced expiry in existing session state and include the banner in the first pre-tool response for each active-mode expiry, without adapter-local memory. Table-test direct and absolute-path `guardrail night on|off|status` Bash invocations as `P5.self-config`; verify equivalent parsed calls from all three planes reach the same Deny and remain Deny under active night mode.

**Step 2: Run focused tests to verify RED**

Run: `go test ./internal/adapter ./internal/engine ./cmd/guardrail -run 'Test.*(Night|Posture|Doctor|SelfConfig)'`

Expected: FAIL because visibility and command protection are absent.

**Step 3: Implement visibility and self-protection**

Prepend the banner before doctor's version line and before Claude's existing autonomy posture. Track OpenCode/Antigravity announcement by exact expiry and plane in the existing session transaction, prefixing only the first response reason where their schemas allow it; have the OpenCode plugin surface that Allow reason through its supported toast API. Extend normalized Bash classification to recognize direct, unresolved-but-visible, and opaque-interpreter `guardrail night` invocations and return the existing `P5.self-config` Deny. Protect `night.toml` at arbitrary Operator config roots in both the runtime Engine and generated Declarative floors, retaining ordinary P5 waiver behavior and normal strongest-Verdict selection. Do not edit installed settings: generated floors change only for future explicit generation/sync.

**Step 4: Run focused tests to verify GREEN**

Run: `go test ./internal/adapter ./internal/engine ./cmd/guardrail -run 'Test.*(Night|Posture|Doctor|SelfConfig)'`

Expected: PASS.

**Step 5: Commit**

```bash
git add cmd/guardrail/doctor.go cmd/guardrail/doctor_test.go cmd/guardrail/hook.go cmd/guardrail/hook_test.go cmd/guardrail/main_test.go internal/session/session.go internal/engine/rules_bash.go internal/engine/rules_bash_test.go internal/engine/rules_path.go internal/engine/rules_path_test.go internal/genconfig/claude.go internal/genconfig/claude_test.go internal/genconfig/opencode_plugin.js internal/genconfig/opencode_test.go
git commit -m "feat(night): expose posture and protect controls"
```

### Task 5: One Adversarial Regression And Full Gate

**Files:**
- Modify: `test/adversarial/corpus.json`
- Modify: `test/adversarial/adversarial_test.go`

**Step 1: Add exactly one corpus entry**

Add one case showing that an active-mode self-control attempt such as `guardrail night off` is still denied by `P5.self-config`. Extend the harness just enough to activate a marker and assert the rule ID for that row. Do not add a second night-mode corpus row; keep broader combinations in unit/integration tests.

**Step 2: Run the adversarial test**

Run: `go test ./test/adversarial -run TestAdversarialCorpus`

Expected: PASS with the new entry.

**Step 3: Run formatting and the complete repository gate**

Run:

```bash
gofmt -w cmd/guardrail internal/night internal/policy internal/engine internal/adapter
go test ./...
go test -race ./...
go vet ./...
GOOS=windows GOARCH=amd64 go build ./cmd/guardrail
make check
git diff --check
```

Expected: every command exits 0. Remove only the cross-compiled binary produced by this branch after confirming it is untracked; do not touch unrelated worktree changes.

**Step 4: Inspect scope and commit**

Run `git status --short`, `git diff --stat main...HEAD`, and `git diff main...HEAD`; confirm there is exactly one new corpus entry, no generated settings edits, and no unrelated changes.

```bash
git add test/adversarial/corpus.json test/adversarial/adversarial_test.go
git commit -m "test(adversarial): keep night controls protected"
```

If the harness required no source change, omit `test/adversarial/adversarial_test.go` from staging. If formatting changed earlier task files after their commits, stage those intended formatting-only changes with this final commit.

**Step 5: Stop at the review boundary**

Report branch name, commits, changed behavior, exact verification results, and any residual risks. Do not push, merge, tag, install, deploy, edit settings, or restart a plane.
