# Contract Coverage Linter Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fail CI when a contracted plane tool has no fixture coverage, or when a fixture file is dead (unreferenced by `expected.json`).

**Architecture:** One new test file in package `test`, beside the existing fixture harness. No production code changes: the linter reads `internal/planecontract` (via `RegisteredTools`) and `test/fixtures/<plane>/` directly, closing #85's reverse-direction gap (contract → fixtures) that the existing per-plane fixture tests (fixtures → verdicts) leave open.

**Tech Stack:** Go testing, `encoding/json`, `os.ReadDir`. No new dependencies.

**Spec:** `docs/superpowers/specs/2026-11-19-contract-coverage-linter-design.md`

## Global Constraints

- Planes: exactly `claude`, `opencode`, `antigravity`, `codex` (the four keys `RegisteredTools` accepts).
- Tool-name extraction per plane, pinned from real fixtures: claude and codex payloads carry top-level `tool_name`; opencode envelopes carry `tool` (V1-native contract names, ADR-0007); antigravity payloads carry `toolCall.name`.
- A tool counts as covered only if named by a fixture that `expected.json` references. A dead file must not count as coverage.
- Non-payload files exempt from the dead-fixture check: `expected.json`, `README.md`, `*.golden.json`.
- Every exemption in the coverage test carries the tool name and a one-line reason, inline in the test source.
- V2-native opencode spellings are out of scope (plugin layer covers them: `opencode_plugin_v2_test.go`, the #627 concurrency test).
- Repo rules: gofmt clean, `go vet ./...` clean, full `go test ./... -count=1` green on Linux before push; conventional commit with `(#85)`.

## Review Focus

- Dead fixture counted as coverage — pinned by coverage reading only `expected.json`-referenced files plus `TestEveryFixtureIsExpected`.
- Malformed fixture JSON silently skipped — the extractor must `t.Fatalf` naming the file, not `continue`.
- `expected.json` entry whose file is missing — loader fails naming the entry (the existing per-plane tests also pin this).
- Name aliasing (claude `Task` native vs `Agent` contract name) — coverage matches a fixture name against `NativeTool` **or** `Tool`.
- A future plane addition with an empty fixture dir — iterating `RegisteredTools` output means a new plane's tools fail uncovered automatically; no plane list to update in the linter beyond the four fixed keys.

---

### Task 1: The linter test, driven red on real gaps

**Files:**
- Create: `test/contract_coverage_test.go`
- Modify (only if the red run finds cheap, correct fixtures to add): `test/fixtures/<plane>/*.json` and the matching `test/fixtures/<plane>/expected.json`
- Reference: `internal/planecontract` (`RegisteredTools(plane string) []ToolSpec`; `ToolSpec{NativeTool, Tool string; Capability policy.Capability}`)

**Interfaces:**
- Consumes: `planecontract.RegisteredTools`, the `test/fixtures/<plane>/` layout, `expected.json`'s schema (`map[string]struct{Exit int; Decision, Rule string}` — keys are fixture file names).
- Produces: nothing outside the test binary.

- [ ] **Step 1: Write the failing coverage test with no exemptions**

`TestEveryContractedToolHasAFixture` in `test/contract_coverage_test.go`:
helper `coveredTools(t *testing.T, plane string) map[string][]string` — unmarshal `fixtures/<plane>/expected.json`; for each referenced fixture file, `os.ReadFile` + `json.Unmarshal` into `map[string]any`; extract the tool name per the plane's pinned field (`tool_name` / `tool` / `toolCall.name`), `t.Fatalf` on unreadable file, missing key, or malformed JSON naming the file; return tool name → fixture files. In the test: for each `spec` in `planecontract.RegisteredTools(plane)`, `covered[spec.NativeTool]` or `covered[spec.Tool]` must exist, else collect `spec.NativeTool`. Exemption map `map[plane]map[tool]reason` starts **empty**. Fail listing every uncovered tool per plane.

- [ ] **Step 2: Run it and capture the real gap list**

Run: `go test ./test/ -run TestEveryContractedToolHasAFixture -count=1`
Expected: FAIL — the audit output. Record the uncovered list verbatim (it seeds Step 3 and the follow-up issue).

- [ ] **Step 3: Resolve each uncovered tool — fixture or reasoned exemption**

For each uncovered tool: if a minimal payload drives it through `hook <plane>` stdin (matching how sibling fixtures for that plane look), add the fixture file plus an `expected.json` entry with the verdict the engine actually returns (measure by running the harness case, never guessed). Otherwise add the exemption entry with a one-line reason (e.g. "host-side only; cannot be driven through hook stdin"). Bias: real fixtures over exemptions where the payload is obvious; exemptions must not merely say "no fixture yet" for a drivable tool without the follow-up issue carrying it.

- [ ] **Step 4: Run the coverage test to green**

Run: `go test ./test/ -run TestEveryContractedToolHasAFixture -count=1 -v`
Expected: PASS.

- [ ] **Step 5: Write the dead-fixture test**

`TestEveryFixtureIsExpected` in the same file: for each plane dir, every `*.json` except `expected.json` and `*.golden.json` must be a key in that plane's `expected.json`; fail naming each dead file. Before deleting anything the test flags, grep the repo for other uses of that file name (other tests may load it directly); files used elsewhere get named in an in-test exclusion with a reason instead of deletion.

- [ ] **Step 6: Run it; resolve to green**

Run: `go test ./test/ -run TestEveryFixtureIsExpected -count=1 -v`
Expected: PASS after resolving (reference in `expected.json`, reasoned exclusion, or deletion of a truly dead file).

- [ ] **Step 7: Full verification**

Run: `gofmt -l test/` (empty); `go vet ./...`; `go test ./... -count=1`
Expected: clean, clean, exit 0 with all packages ok.

- [ ] **Step 8: File the follow-up issue for exempted-but-fixable tools**

If Step 3 exempted any drivable tool, `gh issue create` enumerating them with the reason each was deferred; reference it in a comment on #85. If none, comment the measured before/after on #85 (tools uncovered → tools exempted with reasons, fixtures added).

- [ ] **Step 9: Commit and PR**

Branch `test/contract-coverage-linter-85` off main. Commit includes this plan, the spec doc, the test, and any fixtures: `test(contracts): every contracted tool needs a fixture; every fixture must be expected (#85)`. Push, open the PR with root cause (the one-directional fixture verification), the Step 2 gap list verbatim, and the verification block; hand the merge command to the operator.
