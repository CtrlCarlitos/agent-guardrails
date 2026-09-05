# Task 7 Report: Surface Policy Warnings

## Status

Implemented one explicit, nonduplicated `policy warnings:` section in Doctor.
The section prints `none` when Merge returns no warnings; otherwise it prints
every warning once as a bullet in Merge's deterministic order.

Confirmed that Claude SessionStart posture receives unauthorized-waiver Merge
warnings through Task 5's shared sanitization and cumulative 20-warning cap.

## RED

Focused command:

```text
/usr/local/go/bin/go test ./cmd/guardrail -run 'TestDoctorBasics|TestDoctorShowsEveryPolicyWarningOnceInMergeOrder' -count=1 -v
```

Result: FAIL as expected.

- The no-warning case omitted `policy warnings: none`.
- The warning case printed all five warnings through the old unlabeled loop and
  omitted the required `policy warnings:` heading and bullet markers.

The Claude adapter and SessionStart tests characterize behavior already supplied
by Task 5. After correcting the control-character fixture so normalization was
asserted independently of punctuation placement, both passed before Doctor's
production change.

## GREEN

Focused commands after implementation and `gofmt`:

```text
/usr/local/go/bin/go test ./cmd/guardrail -run 'TestDoctor|TestHookSessionStartSurfacesSanitizedUnauthorizedWaiverWarning|TestHookCumulativeWarningCapPreservesSessionStartOperatorWarning' -count=1 -v
/usr/local/go/bin/go test ./internal/adapter -run 'TestPostureText|TestEmitClaudeSessionStart' -count=1 -v
```

Result: PASS.

Full-suite command, run once after implementation and self-review:

```text
/usr/local/go/bin/go test ./... -count=1
```

Result: FAIL only in the pre-existing generated-config golden checks:

- `TestGenConfigClaudeGolden`: generated output contains Task 6's relative and
  `//`-anchored operator-config denies, but the checked-in golden omits them.
- `TestGenConfigOpencodeGolden`: generated output contains Task 6's relative
  operator-config denies, but the checked-in golden omits them.

All other packages passed, including `cmd/guardrail`, `internal/adapter`, and
`test/adversarial`. Task 7 does not modify generated permissions or goldens.

## Files

- `cmd/guardrail/doctor.go`: replaced the unlabeled warning loop with the single
  explicit none-or-bullets section.
- `cmd/guardrail/doctor_test.go`: covers the zero-warning form and verifies the
  rejected waiver, `secret_allow`, `audit_log`, external `safe_root`, and wildcard
  egress warnings each appear once, as bullets, in Merge order.
- `cmd/guardrail/hook_test.go`: confirms an unauthorized waiver containing
  injected controls reaches Claude SessionStart as one sanitized posture warning.
- `internal/adapter/claude_test.go`: directly locks `PostureText`'s one-line
  sanitization of unauthorized-waiver warnings.
- `.superpowers/sdd/2026-09-04-remediation-phase3-overlay-trust/task-7-report.md`:
  records Task 7 evidence and review.

`internal/adapter/claude.go` required no production change: it already iterates
over `sanitizeWarnings(warnings)`, and `cmdHook` already supplies Merge warnings
to `PostureText` with high-priority posture diagnostics prepended.

## Self-Review

- Doctor emits exactly one `policy warnings:` label on a successful Merge.
- Zero warnings use the stable single-line form `policy warnings: none`.
- Nonzero warnings are emitted only by the replacement loop, preventing the old
  unlabeled/labeled duplication described in the brief.
- Warning ordering is inherited directly from the Merge slice; no map, sort, or
  secondary collection can reorder it.
- The comprehensive Doctor fixture causes exactly the five requested refusal
  classes and verifies each distinguishing message occurs once in expected order.
- Doctor still returns exit code 0 and retains all surrounding operator-facing
  output unchanged.
- SessionStart coverage decodes the real Claude JSON response and checks the
  model-visible `additionalContext`, rather than asserting an intermediate value.
- Injected newline, tab, and DEL content collapses into one warning paragraph.
- The existing cumulative-cap regression still proves the generic operator-load
  warning remains ahead of lower-priority Merge warnings and cannot be starved.
- `gofmt` and `git diff --check` completed cleanly.

## Concerns

- The full suite is not green because Task 6's generated operator-config deny
  entries have not been propagated to the Claude and OpenCode golden fixtures.
  Updating those unrelated fixtures is outside Task 7's no-unrelated-edits scope.
