# Contract coverage linter — design (approved 2026-11-19)

Issue #85. Approach A (Go test linter) picked by the operator after B (CLI
subcommand) and C (golden manifest) were laid out; A adds no new surface and
CI already runs the suite on every PR.

## Intent

Fixtures currently verify one direction only: every fixture listed in
`test/fixtures/<plane>/expected.json` exists and produces its pinned
verdict. Nothing verifies the reverse — that every tool a plane's contract
registers has at least one fixture exercising it — so a newly contracted
tool ships with zero coverage and nothing fails (#42's `notebook_edit`,
`sed_file`, `delete_knowledge` drift was exactly this).

## Goals

- Per plane (claude, opencode, antigravity, codex): every
  `planecontract.RegisteredTools(plane)` entry is named by at least one
  fixture that `expected.json` actually references (a dead file must not
  count as coverage).
- Dead fixtures are flagged: payload files in `fixtures/<plane>/` that
  `expected.json` never references (excluding `expected.json` itself,
  `README.md`, and `*.golden.json`, which are not hook payloads).
- Exemptions are explicit and reasoned: contracted tools that cannot be
  driven through `hook <plane>` stdin are named in the test with a one-line
  reason each; the audit is part of the work, and tools that merely lack a
  fixture (but could have one) get exemptions plus a follow-up issue
  enumerating them, not silent passage.

## Non-goals

- No CLI subcommand, no manifest files, no changes to the engine or the
  contracts themselves.
- V2-native opencode spellings (`shell`/`patch`/`subagent`, `path` args)
  stay covered at the plugin layer (`opencode_plugin_v2_test.go`, the #627
  concurrency test); fixtures speak the shared V1-native envelope names by
  ADR-0007 and the linter does not require V2 fixtures.
- Closing every coverage gap the linter finds (first run lands the linter
  plus honest exemptions; a follow-up issue carries the fixable gaps).

## How

Two tests in `test/contract_coverage_test.go`, package `test`:

- `TestEveryContractedToolHasAFixture`: for each plane, extract the tool
  name from every fixture payload referenced by `expected.json` (per-plane
  probe of the JSON shape: claude `tool_name`, opencode envelope `tool`,
  codex/antigravity per their payload shapes), then diff against
  `RegisteredTools(plane)`; fail naming each uncovered tool (or its
  exemption reason for why it is listed instead).
- `TestEveryFixtureIsExpected`: every payload-shaped `.json` in each
  plane's fixture directory must appear in `expected.json`.

Failure messages name the exact tool or file and the directory to fix.

## Verification

Suite green on Linux (and CI's matrix); the linter demonstrably fails when
a contracted tool's fixtures are (temporarily) considered absent — the TDD
red step.
