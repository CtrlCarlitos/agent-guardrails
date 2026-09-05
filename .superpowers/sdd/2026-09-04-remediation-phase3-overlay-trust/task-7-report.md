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

- Resolved after Task 7: Task 6 fix commit `edb4a9a` synchronized the Claude and
  OpenCode golden fixtures. The uncached full suite then passed with
  `/usr/local/go/bin/go test ./... -count=1`.

## Fix Round 1

### Status

Sanitized every dynamic, potentially untrusted Doctor display value through the
shared adapter boundary while preserving fixed labels, exit semantics, every
Merge warning, and useful error status around the 200-rune per-value cap.

Reworked policy-warning assertions to parse the exact lines between
`policy warnings:` and `waivers:` and compare the complete ordered bullet slice.

### RED

Focused commands:

```text
/usr/local/go/bin/go test ./internal/adapter -run TestSanitizeForDisplay -count=1 -v
/usr/local/go/bin/go test ./cmd/guardrail -run 'TestDoctor(Basics|ShowsEveryPolicyWarningOnceInMergeOrder|StaleConfig|SanitizesOverlayParseErrorPath|SanitizesOperatorConfigError|SanitizesAuthorizedAuditPath)$' -count=1 -v
```

Results: FAIL as expected.

- The adapter package had no exported display sanitizer.
- Newline, tab, and DEL characters in CWD, config/overlay paths, refused values,
  operator-config errors, and authorized audit paths forged extra Doctor lines
  and fake `policy warnings:`/`waivers:` headings.
- A second RED cycle showed that sanitizing a complete long parse/operator
  diagnostic could consume the cap before fixed `PARSE ERROR` or
  `treating as empty` status text.

### GREEN

Focused commands after implementation and `gofmt`:

```text
/usr/local/go/bin/go test ./internal/adapter -run 'TestSanitizeForDisplay|TestSanitizeForModel|TestEmitModelWarnings|TestPostureText' -count=1 -v
/usr/local/go/bin/go test ./cmd/guardrail -run TestDoctor -count=1 -v
```

Result: PASS.

Full-suite command, run once uncached after implementation and self-review:

```text
/usr/local/go/bin/go test ./... -count=1
```

Result: PASS for every package, including `test` and `test/adversarial`.

### Files

- `internal/adapter/sanitize.go`: exported `SanitizeForDisplay`; retained
  model-facing behavior by making `sanitizeForModel` delegate to it.
- `internal/adapter/sanitize_test.go`: locks control stripping, whitespace
  normalization, and the 200-rune Unicode-safe display cap.
- `cmd/guardrail/doctor.go`: sanitizes version, CWD, config and overlay paths,
  discovery/load diagnostics, base/operator/Merge errors, every warning, waiver
  display, audit path, and Claude settings state.
- `cmd/guardrail/doctor_test.go`: parses the exact warning section, compares all
  25 expected bullets in order, proves no Doctor list cap, and covers forged
  paths, refused values, parse/operator errors, and an authorized audit path.
- `.superpowers/sdd/2026-09-04-remediation-phase3-overlay-trust/task-7-report.md`:
  records fix-round evidence and review.

### Self-Review

- `SanitizeForDisplay` is the sole implementation of control stripping,
  whitespace normalization, and rune truncation; `sanitizeForModel` delegates,
  so model and terminal semantics cannot drift.
- Doctor applies the sanitizer per dynamic value, not to fixed labels or counts.
- Parse paths and parse errors receive independent 200-rune budgets, preserving
  the fixed `PARSE ERROR` marker even for long paths.
- Operator errors receive their own 200-rune budget while the fixed
  `operator config unreadable` and `treating as empty` text remains visible.
- Warning sanitization occurs inside the existing loop with no slice cap; the
  exact 25-bullet test includes external `safe_root`, wildcard egress,
  `secret_allow`, `audit_log`, and 21 rejected waivers.
- Newline, tab, and DEL injection in valid TOML becomes one exact bullet line;
  injected CWD/config/overlay text cannot create a second heading or status.
- The authorized audit-path test proves the final `audit log:` value is also
  sanitized, not only its unauthorized warning form.
- Existing labels, warning order, no-warning form, surrounding output, and exit
  code 0 remain unchanged.
- `gofmt` and `git diff --check` completed cleanly.

### Concerns

None.
