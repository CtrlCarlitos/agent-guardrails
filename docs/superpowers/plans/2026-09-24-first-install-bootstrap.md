# First-install bootstrap — implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans (this plan was executed inline by the designing agent) or superpowers:subagent-driven-development task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** On a machine with no enrolled operator, `guardrail setup` and `guardrail plane enable` arm every detected plane without an approval, audit it as `transport: bootstrap`, verify, and tell the operator to enroll; every loosening action stays approval-only; mediated agents cannot invoke the lifecycle subcommands.

**Architecture:** One new branch in the two enable paths (`setupEnable`, `cmdPlaneLifecycle`) that calls the same in-process `enablePlaneIntegration` the approved action already runs, plus one audit helper, one doctor wording, and a generalisation of the engine's night self-control rule. No new state on disk.

**Spec:** `docs/superpowers/specs/2026-09-24-first-install-bootstrap-design.md`. **ADR:** `docs/adr/0030-first-install-bootstrap-arms-without-approval.md`.

**Plan style:** behaviour, file scope, exact messages and exact test names. The executor writes the code and must run every test named here.

## Global constraints

- Branch `feat/326-first-install-bootstrap`, stacked on `fix/326-unenrolled-setup-diagnosable` (#327): the preflight seams `operatorEnrolled`, `requireOperatorEnrolled` and `exitNotEnrolled` come from there.
- `gofmt` clean, `go vet ./...` clean, `go test ./...` green on Linux (WSL) and, on Windows, green except the pre-existing `TestSetupReenablesOnHandlerDrift` host failure.
- Hermetic tests only (`internal/testenv`); seams are package-level function vars restored by the test.
- Exact strings below are matched with `strings.Contains` on the full line.

## File map

| File | Change |
|---|---|
| `cmd/guardrail/action_audit.go` | `writeBootstrapAudit(planes []string) error` |
| `cmd/guardrail/plane.go` | `bootstrapPlanes(planes []string, stdout io.Writer) error`; `cmdPlaneLifecycle` bootstrap branch and terminal-gate reorder |
| `cmd/guardrail/setup.go` | `cmdSetup` terminal-gate reorder; `setupEnable` bootstrap branch; enrollment instruction at the end |
| `cmd/guardrail/doctor.go` | `operatorApprovalStatus(enrolled, armed bool)`; `anyPlaneRegistered()` |
| `internal/engine/rules_bash.go` | `checkNightControlInvocation` → `checkSelfControlInvocation` covering setup/plane/operator/recover |
| Tests | `cmd/guardrail/bootstrap_test.go` (new), edits to `enrollment_test.go`, `setup_test.go`, `doctor_test.go`, `internal/engine/rules_bash_test.go` |
| Docs | README, `docs/OPERATIONS.md`, `docs/operator-approvals.md`, `docs/adr/0029-*.md` (status note), `install.sh` / `install.ps1` headers, `CHANGELOG.md` |

---

## Task 1 — audit record

- [ ] `writeBootstrapAudit(planes)` writes, via `writeActionAudit`, `audit.Record{Plane: "operator", Tool: "guardrail", Event: "operator-action", Decision: "completed", OperatorAction: "plane-enable", Transport: "bootstrap", Reason: "bootstrap: no operator enrolled; planes <comma-joined>"}` to `audit.DefaultPath("")`. No request id, no fingerprint, no journal (nothing to recover: the merge is idempotent and re-run by the next setup).
- [ ] Test `TestBootstrapAuditRecordShape` (bootstrap_test.go): stub `writeActionAudit`, call the helper, assert every field above.

## Task 2 — `bootstrapPlanes`

- [ ] `bootstrapPlanes(planes, stdout)`: for each plane `enablePlaneIntegration(plane)`; on error return `fmt.Errorf("%s: %w", plane, err)` (caller prints `guardrail: setup: <plane>: <err>` / `guardrail: <plane>: <err>`). After all planes, print `<plane> enabled (bootstrap: no operator enrolled)` per plane, then `writeBootstrapAudit`; if that fails print `guardrail: <cmd>: bootstrap audit record not written: <err>` to stderr and still return nil.
- [ ] Shared instruction printer `printBootstrapInstruction(cmd string, planes []string, stdout)`, lines exactly:
  - `<cmd>: planes armed without an approval because no operator authenticator is enrolled.`
  - `<cmd>: run 'guardrail operator enroll' from a real terminal to take control; every later plane change needs your passkey.`
  - `<cmd>: for Codex, run /hooks inside Codex to review and trust the generated hooks; restart the agents you wired.` — only when `codex` is in the batch; otherwise `<cmd>: restart the agents you wired.`

## Task 3 — setup

- [ ] `cmdSetup`: parse arguments first (unchanged validation, exit 2). Terminal gate becomes: `if !terminal && !(state == "enabled" && !operatorEnrolled())` → today's exit-2 message. The staging-path refusal and the `setup: registering` line stay in order after it.
- [ ] `setupEnable`: with a non-empty batch, `if !operatorEnrolled()` → `bootstrapPlanes`; else the existing daemon path. Both continue into the convergence check (`setupEnableReason` must return "" for each plane), the gates and `setupPrintStatus`. After the status block, the bootstrap run prints the instruction via `printBootstrapInstruction("setup", batch, stdout)`.
- [ ] Tests (bootstrap_test.go): `TestSetupBootstrapsWhenNoOperatorEnrolled` (exit 0, plane registered on disk, enabled line, no submit, gates once, instruction last on stdout, one audit record with transport bootstrap); `TestSetupBootstrapSkipsTerminalGate` (via `run([]string{"setup"}, strings.NewReader(""), …)` with `operatorEnrolled=false` and a sandboxed home: exit 0 and the plane registered); `TestSetupEnrolledStillRequiresTerminal` (same call with `operatorEnrolled=true`: exit 2, untouched home — this is today's `TestSetupRequiresInteractiveTerminal` with the seam pinned); `TestSetupBootstrapContinuesWhenAuditWriteFails` (audit seam errors: exit 0, warning on stderr, plane registered); `TestSetupBootstrapFailsWhenEnableFails` (a plane whose config path is unwritable → exit 1). Remove/replace `TestSetupWithoutEnrollmentExitsNeedsEnrollment` from #327 (its expectation is now the bootstrap). `TestSetupDisableWithoutEnrollmentExitsNeedsEnrollment` and `TestSetupSteadyStateNeedsNoEnrollment` keep passing.

## Task 4 — plane enable

- [ ] `cmdPlaneLifecycle`: compute `bootstrap := action == "plane-enable" && !operatorEnrolled()` before the terminal check; skip the check when `bootstrap`. With a non-empty batch and `bootstrap` → `bootstrapPlanes` then `printBootstrapInstruction("plane enable", batch, stdout)`, exit 0; error → `guardrail: <plane>: <err>`, exit 1. Disable keeps `requireOperatorEnrolled` (exit 3) and the terminal gate.
- [ ] Tests: `TestPlaneEnableBootstrapsWhenNoOperatorEnrolled` (replaces `TestPlaneEnableWithoutEnrollmentExitsNeedsEnrollment`), `TestPlaneEnableBootstrapSkipsTerminalGate` (terminal=false), `TestPlaneDisableWithoutEnrollmentExitsNeedsEnrollment`, `TestPlaneDisableWithoutEnrollmentAndTerminalExits2`.

## Task 5 — doctor

- [ ] `anyPlaneRegistered()` over `supportedPlanes`; `operatorApprovalStatus(enrolled, armed)`: enrolled → `operator approvals: WebAuthn`; not enrolled and armed → `operator approvals: disabled (no authenticator enrolled; planes armed by bootstrap; run guardrail operator enroll)`; otherwise #327's line.
- [ ] Tests: extend `TestOperatorApprovalStatusReportsEnrollmentOnEveryOS` with the three cases; `TestDoctorReportsBootstrapArmedPlanes` (sandboxed home with a registered claude plane and no credentials → the armed line).

## Task 6 — engine self-control rule

- [ ] `checkSelfControlInvocation`: direct match when head is guardrail and argv[1] is one of `night` (except exact `night status`), `setup`, `plane` (except exact `plane status`), `operator`, `recover`. Opaque match when an opaque executor's input mentions guardrail plus any of those five words. Reasons: direct → `the guarded plane cannot change its own guardrail posture (<subcommand>)`; keep `NightMentionReason` for opaque night, add `SelfControlMentionReason` for the others with the same shape. Adapters that key on `NightMentionReason` keep working.
- [ ] Tests (rules_bash_test.go): `TestGuardrailLifecycleInvocationIsSelfConfigDeny` (the spec's deny list, including `.exe`, absolute path, `python3 -c`, `node -e`, heredoc); `TestReadOnlyGuardrailSubcommandsAreAllowedFromSessions` (`plane status`, `doctor`, `selftest`, `audit`, `version`, `night status`). `TestGuardrailNightInvocationIsSelfConfigDeny` and `TestReadOnlyNightStatusIsAllowedFromSessions` unchanged and green. Run `go test ./test/adversarial/` to confirm the corpus still passes.

## Task 7 — docs and changelog

- [ ] README: the "first install" sentences become "The installer arms every detected host on its own the first time; enroll a passkey afterwards to take control" and the enroll block loses the `--no-setup` requirement. OPERATIONS: setup paragraph (bootstrap, exit table), `--no-setup` paragraph (now optional), runbook row for the doctor line. operator-approvals: the paragraph from #327 gains the bootstrap sentence. ADR-0029: status line notes amendment by ADR-0030. Installer headers: exit 3 wording narrows to `--state disabled`. CHANGELOG `Unreleased`: one entry under Grants & Approvals, one under Engine Enforcement & Policy for Task 6.

## Task 8 — verification

- [ ] `gofmt -l`, `go vet ./...`, `go test ./...` on Windows; full suite on Linux via WSL (recipe in memory); installer harness `test/installer/install_sh_test.sh` on WSL if `dist/` is available, else rely on CI's installer job.
