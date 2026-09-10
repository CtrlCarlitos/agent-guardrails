# NF-19 Conservative Loop Redesign Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Subagents and reviewers are prohibited for this task.

**Goal:** Replace exact finite-loop execution with conservative per-item policy-candidate enumeration that cannot hide syntactic body commands or invent post-loop shell state.

**Architecture:** Keep `Normalize(command, cwd)` and policy evaluation unchanged. For an eligible word-form loop, normalize the complete body independently from the pre-loop state with each concrete iterator binding, retain only the resulting `Simple` candidates in item/body order, and return invalidated state with indeterminate status; remove all special handling for `break` and `continue` reachability.

**Tech Stack:** Go, `mvdan.cc/sh/v3/syntax`, existing Engine behavior-test helpers.

**Spec:** `.superpowers/sdd/2026-09-06-remediation-phase5/task-nf19-brief.md`

## Global Constraints

- Keep `Normalize(command, cwd)` and all policy interfaces unchanged.
- Keep `P3.unresolved` unwaivable and strongest-Verdict aggregation unchanged.
- Use existing dependencies only; do not modify another repository or push, merge, tag, publish, or install.
- Preserve standalone parameter, `PWD`/`HOME`, adjacent-expansion, deterministic corpus `HOME`, and provenance behavior.
- Enumerate at most 16 literal items and only when the loop is not nested in another loop and contains no nested loop. Larger, nested, and non-literal loops remain unresolved without partial enumeration.
- Reuse NF-18's action-aware `find` parser for cross-iteration filesystem evidence; the resolver must not duplicate policy classification.

---

### Task 1: Lock Conservative Candidate Behavior

**Files:**
- Modify: `internal/engine/tokenize_test.go`

**Interfaces:**
- Consumes: `Normalize(string, string) ([]Simple, error)` and the real Bash policy path through `evalBash`.
- Produces: behavior locks for complete candidate ordering, Deny retention, rejected iterator binding, and unresolved post-loop state/status.

- [x] **Step 1: Replace exact-control expectations with conservative expectations**

Assert that plain `break` and `continue`, `builtin`/`command` wrappers, function-shadowed controls, and function-mutated controls retain a later concrete `rm -rf /etc/...` candidate for every item. Name the exact old production behavior each test would catch.

- [x] **Step 2: Extend iterator and post-loop behavior tests**

Assert real Ask `P3.unresolved` Verdicts for `readonly` variants, nameref and case-transforming iterators, post-loop `$iterator`, post-loop `$PWD` after a body `cd`, and a target selected through the loop's status. Preserve a direct literal post-loop `/etc` Deny control.

- [x] **Step 3: Run focused RED tests**

Run:

```bash
/usr/local/go/bin/gofmt -w internal/engine/tokenize_test.go
/usr/local/go/bin/go test ./internal/engine -run 'TestNF19' -count=1
```

Expected: FAIL because `staticFor` truncates bodies at recognized control commands and publishes final iterator/cwd/status; unsupported `readonly` variants can still enter exact binding.

### Task 2: Replace Exact Execution With Candidate Enumeration

**Files:**
- Modify: `internal/engine/tokenize.go`
- Test: `internal/engine/tokenize_test.go`

**Interfaces:**
- Consumes: `staticForItems`, `staticForIterator`, `normalizeWithState`, and the loop statement's inherited pipeline positions.
- Produces: a private finite-loop candidate enumerator whose only durable output is `w.replacements[stmt]`; its returned `cwdOutcome` has invalidated state and both possible statuses.

- [x] **Step 1: Remove exact loop-control machinery**

Delete `loopControl`, `staticForControl`, control unwrapping/scanning, function-prefix analysis, and all early-break/continue execution branches.

- [x] **Step 2: Enumerate the full body independently for every item**

For each item, bind the proven ordinary scalar iterator to a clone of the pre-loop state, call `normalizeWithState` on the complete body source, and append every returned `Simple` in order. Do not feed an iteration's outcome or functions into the next item.

- [x] **Step 3: Invalidate post-loop state and status**

After retaining candidates, do not publish enumerated variables, cwd, function environment, iterator, or status. Return `bothOutcome(unknownCwd(invalidateNamedVariables(state, nil, true)))`; conservatively merge any possible function definitions rather than selecting one enumerated execution.

- [x] **Step 4: Reject `readonly` declaration variants**

Treat a `syntax.DeclClause` whose variant is `readonly` as carrying assignment semantics that make iterator binding ineligible, alongside the existing nameref and `aAilnru` flags.

- [x] **Step 5: Run focused GREEN tests**

Run:

```bash
/usr/local/go/bin/gofmt -w internal/engine/tokenize.go internal/engine/tokenize_test.go
/usr/local/go/bin/go test ./internal/engine -run 'TestNF19|TestNF5b' -count=1
/usr/local/go/bin/go test -race ./internal/engine -run 'TestNF19|TestNF5b' -count=1
```

Expected: PASS with complete concrete loop candidates and conservative post-loop Ask behavior.

### Task 3: Verify, Report, Self-Review, And Commit

**Files:**
- Modify: `.superpowers/sdd/2026-09-06-remediation-phase5/task-nf19-report.md`
- Modify: `docs/superpowers/plans/2026-09-08-nf19-conservative-loop-redesign.md`

**Interfaces:**
- Consumes: repository verification commands and the RED/GREEN outputs from Tasks 1 and 2.
- Produces: the required `Conservative Loop Redesign` report section and one local commit on `phase5-nf19`.

- [x] **Step 1: Remove superseded tests and inspect the diff for hidden Deny-to-Allow paths**

Delete tests whose contract is exact early exit, exact final iterator/cwd/function state, or exact loop status. Confirm every eligible item sees the complete body and every ineligible binding remains unresolved.

- [x] **Step 2: Run required verification**

Run `/usr/local/go/bin/gofmt` on edited Go files, `git diff --check`, focused Engine race tests, `/usr/local/go/bin/go test ./...`, `/usr/local/go/bin/go test -race ./...`, `/usr/local/go/bin/go vet ./...`, and `GOOS=windows GOARCH=amd64 CGO_ENABLED=0 /usr/local/go/bin/go build ./...`.

- [x] **Step 3: Append exact evidence to the report**

Record implementation, changed files, exact RED/GREEN commands and relevant outputs, full verification, removed obsolete behavior, self-review findings, and concerns under `## Conservative Loop Redesign`.

- [x] **Step 4: Commit locally**

Stage only the NF-19 redesign files and commit with subject `fix: enumerate conservative loop candidates (NF-19)`.
