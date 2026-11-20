# Selftest probes as shared fixtures — design (approved for planning, 2026-11-19)

Issue #107. Claimed by the Linux session; this design records the rulings
the issue body leaves open. The plan beside it is the executable version.

## Intent

Selftest probes are Go literals in `cmd/guardrail/selftest.go` (+ a
`runtime.GOOS`-gated Windows file), while `test/fixtures/<plane>/` holds the
same information in a richer recorded shape. One fixture format serves both
consumers: `go test` asserts them as contract tests, and the installed
binary embeds and runs them through the real hook path. The probe count
stops being a README fact that goes stale; every recorded payload becomes
proof on the installed binary.

## Rulings

1. **The files live under an importable, embeddable package — not
   `test/selftest/` as the issue sketches.** `//go:embed` cannot reference
   paths outside the embedding package's module directory, and `test/`
   (package `test`) cannot import `cmd/guardrail` (package `main`). So the
   tree is `internal/selftestfixtures/fixtures/<plane>/…`, the package
   exports `FS` (embed.FS) plus a loader, and both `cmd/guardrail` and
   `test/` consume it. Cost of deviating from the issue's literal path:
   none functionally; the issue's path was conceptual.
2. **Layout mirrors the contract fixtures exactly**: `<plane>/<name>.json`
   is the hook payload; `<plane>/expected.json` maps name →
   `{decision, rule}` (the probe struct's `WantDecision`/`WantRuleID`).
   Hook arguments derive from the plane (`hook <plane>`, plus `pre` for
   antigravity), replacing the per-probe `Args` field.
3. **Platform variants are directories** — `<plane>/windows/<name>.json`
   selected at load by `runtime.GOOS` — replacing `selftest_windows_probes.go`'s
   compile-time gating. Non-variant fixtures run everywhere; a variant
   overrides its base name on its OS only.
4. **The count comes from the directory.** `guardrail selftest` prints
   "runs every recorded fixture (N)" with N counted at load; the README
   stops quoting numbers.
5. **Out of scope for this PR**: extending #632's contract-coverage linter
   to the selftestfixtures tree (its `expected.json` has no `exit` field;
   the linter's shape assumptions differ). Noted as a follow-up on #107.

## Goals

- All 19 existing probes migrate byte-for-byte (payloads unchanged,
  verdicts unchanged); the Windows variants move into `windows/` dirs.
- `guardrail selftest` behavior is unchanged apart from the count line and
  the source of probes; night-preserved selection and rule-from-audit
  (#61's mechanism) keep working because the loader feeds the same runner.
- `go test ./cmd/guardrail/` exercises the loaded set through the same
  harness the current `selftest_test.go` uses.

## Non-goals

- No new probes, no verdict changes, no contract-fixture deduplication
  with `test/fixtures/` (the two trees keep different jobs: recorded
  evidence vs. curated installed-binary proof).
- No CHANGELOG entry requirement: internal test infrastructure, no shipped
  behavior change — except the count line wording, which gets one line
  under Unreleased if the release PR has not already been cut.

## Verification

Red first: a test asserting the loader serves 19+ probes with the exact
current payload/verdict pairs fails until migration completes. Green: that
test, `go test ./...` on Linux, and `guardrail selftest` on this host
before/after producing equivalent verdict lines for every probe.
