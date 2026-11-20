# Selftest Fixtures Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Move guardrail's selftest probes from Go literals into an embedded fixture tree shared by `go test` and the installed binary's `guardrail selftest`.

**Architecture:** One new package, `internal/selftestfixtures`, owns the fixture files and exports an embed.FS plus a loader producing the existing probe shape. `cmd/guardrail`'s selftest runner and `test/`'s contract harness both consume the loader. Platform variants are `windows/` subdirectories selected at load time.

**Tech Stack:** Go 1.26, `embed.FS`, `testing`. No new dependencies.

**Spec:** `docs/superpowers/specs/2026-11-19-selftest-fixtures-design.md` — its five Rulings are binding; read them before Task 1.

## Global Constraints

- Payloads and verdicts migrate **byte-for-byte** — this is a move, not a re-authoring. Any verdict change is a bug in the migration.
- Files: `internal/selftestfixtures/fixtures/<plane>/<name>.json` (payload, compact single-line JSON, trailing newline) and `<plane>/expected.json` (`{name: {decision, rule?}}`, 1-space indent, sorted, trailing newline).
- Hook args derive from plane: `hook <plane>` everywhere except antigravity's `hook antigravity pre`.
- Windows variants: `fixtures/<plane>/windows/<name>.json` overriding the same name on `runtime.GOOS == "windows"` only.
- Repo rules: gofmt clean, `go vet ./...` clean, `go test ./... -count=1` green on Linux before push; conventional commit with `(#107)`.

## Review Focus

- A payload that silently changed during migration (whitespace, a re-quoted key) — pinned by the Task 1 golden test comparing loaded payloads against the literal probe slice before it is deleted.
- A Windows variant that stops loading after the `runtime.GOOS` file is deleted — pinned by loading with `goos: "windows"` in Task 3's test.
- `expected.json` referencing a missing payload, or a payload with no expectation — loader errors, named.
- The count line claiming a number the loader did not serve — count derives from the loaded slice in the same test.
- Empty plane directory (future plane) — loader errors loudly rather than serving zero probes silently.

---

### Task 1: The loader package, proven against the old probes

**Files:**
- Create: `internal/selftestfixtures/selftestfixtures.go`, `internal/selftestfixtures/fixtures/` (empty until Task 2), `internal/selftestfixtures/selftestfixtures_test.go`
- Reference: `cmd/guardrail/selftest.go` (the `selftestProbe` struct and `selftestProbes` slice)

**Interfaces:**
- Produces: `type Probe struct { Plane, Name string; Args []string; Payload string; WantDecision, WantRuleID string }`; `func Load(goos string) ([]Probe, error)`; `var FS embed.FS`.

- [ ] **Step 1: Write the failing test** — `Load("linux")` must return the same probe set as the current literal slice: same count, same plane/name/args/payload/decision/rule for each. Since the fixture tree is empty, this fails (zero probes) for the right reason.
- [ ] **Step 2: Run it, watch it fail** with "0 probes, want 19".
- [ ] **Step 3: Implement the loader** — walk `fixtures` in `FS`; parse each plane's `expected.json`; join with payload files; apply `windows/` overrides when `goos == "windows"`; derive Args from the plane; error naming any mismatch (missing file, orphan expectation, empty plane).
- [ ] **Step 4: Task 2 populates the tree; this test goes green then.**

### Task 2: Migrate the 19 probes (and Windows variants)

**Files:**
- Create: 19+ payload files + 4 `expected.json` + Windows variant files under `internal/selftestfixtures/fixtures/`
- Reference: `cmd/guardrail/selftest.go`, `cmd/guardrail/selftest_windows_probes.go`

**Interfaces:**
- Consumes: Task 1's `Load`.

- [ ] **Step 1: Write a migration script** (throwaway, `/tmp`): read the Go literal slice from `selftest.go`/`selftest_windows_probes.go` — copy the payloads by hand from the source into the script's table, do not parse Go — emit payload files and `expected.json` per the Global Constraints' formats. Windows probes emit into `windows/`.
- [ ] **Step 2: Run it; Task 1's test goes green** — the golden comparison against the still-present literal slice is the migration proof.
- [ ] **Step 3: Run `go test ./internal/selftestfixtures/`** — green.

### Task 3: Switch the consumers, delete the literals

**Files:**
- Modify: `cmd/guardrail/selftest.go` (runner reads `selftestfixtures.Load(runtime.GOOS)`; count line becomes "runs every recorded fixture (N)"), `cmd/guardrail/selftest_test.go`, `README.md` (stop quoting a probe count)
- Delete: `cmd/guardrail/selftest_windows_probes.go`, the `selftestProbes` slice
- Create: `test/selftestfixtures_contract_test.go`

**Interfaces:**
- Consumes: `selftestfixtures.Load`.

- [ ] **Step 1: Write the failing contract test** in `test/`: every loaded probe's payload parses as JSON and its expectation names a decision.
- [ ] **Step 2: Switch the runner to the loader.** Keep the night-preserved selection and #61's rule-from-audit exactly as-is; only the probe source changes.
- [ ] **Step 3: Measure `guardrail selftest` before and after** on this host — build the branch binary, capture the verdict lines, diff against the installed binary's run. Equivalent per probe or the migration is wrong.
- [ ] **Step 4: Delete the literal slice and the GOOS file.** Task 1's golden test now compares `Load` against nothing — replace it with a frozen-shape test (count ≥ 19, every plane present, spot-check three known probes).
- [ ] **Step 5: Full verification** — gofmt, vet, `go test ./... -count=1`; update the count-line wording in the README if it quotes numbers.
- [ ] **Step 6: Commit, PR, checks, merge command for the operator.** PR body: root cause (probe literals drift from recorded fixtures), the five Rulings, the before/after selftest diff, and the follow-up note for #107 (extending #632's linter to this tree).
