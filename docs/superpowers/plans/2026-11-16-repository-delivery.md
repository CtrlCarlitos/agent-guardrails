# Repository-authorized delivery implementation plan

> For agentic workers: implement inline with superpowers:executing-plans, TDD and verification-before-completion. Native Codex delegation remains blocked; do not route around it.

**Goal:** after one operator opt-in for a repository, an authorized `/deliver` task can fix red CI, merge its exact green head and clean up its own confirmed merged resources without separate approvals for each routine action.

**Architecture:** keep authorization in Guardrail's existing operator config. Add a bounded `guardrail delivery` operation that validates and executes merge/cleanup; arbitrary `gh` and destructive Git commands keep their existing policy. `/deliver` retains task authorization and uses that operation when configured. No separate service or credential system.

**Decision:** the operator selected once-per-repository authorization in this conversation. This accepts the existing account/Guardrail trust boundary; it does not claim isolation from that account's administrator privileges. Repository rules and designated CI paths remain protected; this is not blanket Ask relaxation. Earlier #606 recommendations against every merge exception are superseded by this explicit, bounded operator-authorized design.

**Repositories:** `CtrlCarlitos/agent-guardrails` (#606) and `CtrlCarlitos/skills` (`skills/deliver`). Separate branches from main and separate PRs. Update the source skill, not the installed `.agents` copy.

## Global constraints

- Preserve design-only, documentation-only and stop-at-PR endpoints. `/deliver` applied to an implementation task selects end-to-end delivery; material scope expansion still needs authorization.
- Authorization is granted/revoked through the existing operator terminal/passkey machinery. A repository Overlay, skill file, conversational claim or task registration cannot grant it.
- A missing/corrupt policy, API error, stale head, missing/pending/cancelled check, ambiguous cleanup proof or failed audit stops the affected operation. Existing Denies stay enforced.
- No administrator bypass, force push, test weakening or protected CI changes. Read current rules per merge attempt; no stale positive API cache.
- Signed conventional commits, TDD, one PR per issue; full native Windows and Linux build/vet/test before each push. Windows-only tests start `TestWindows`.

## Task 1: operator-owned delivery policy

Files: `internal/policy/operator.go`, new `internal/policy/delivery.go` and tests; operator-config serializer/transaction and new CLI tests in `cmd/guardrail`.

- [ ] Add failing tests: absent authorization denies; canonical repository/worktree identity resolves correctly; other repository cannot reuse it; Overlay cannot enable it; corrupt policy fails closed; unrelated config writes preserve the delivery policy.
- [ ] Add a typed repository delivery policy with pinned GitHub repository identity, base/default branch, merge method and protected paths. Keep it separate from consumable exact-action grants.
- [ ] Add terminal-authenticated enable/revoke/status using existing prompt/passkey and private-file transaction patterns. Revocation applies before subsequent operations.
- [ ] Verify policy tests and operator config round trips. Commit with signed conventional message.

## Task 2: exact-head merge under standing authorization

Files: new focused package `internal/delivery` (policy/API checks, executor, tests); `cmd/guardrail/delivery.go`, `run.go`, CLI integration tests.

- [ ] Write failing fixture tests for the full successful operation and each rejection: wrong repo/base/head, absent/empty checks, non-strict rules, current-user bypass, wrong method, workflow/protected-path modification including rename/delete, incomplete file listing, check pending/cancelled/missing, API/auth/rate-limit error and revoked policy.
- [ ] Implement bounded GitHub reads, complete protected-path scan, live rule/check validation, required review satisfaction through GitHub, explicit expected-head merge and confirmed-merge readback. Bind execution to the inspected repository and head. Never treat auto-merge/queue enrollment as completion.
- [ ] GitHub API reads and merge remain in the executor; the Engine does not grow a network client. The CLI rechecks authorization itself; allowing the entry point does not authorize enabling delivery.
- [ ] Add audit records for authorization, failed conditions, attempted merge and confirmed result. Failed prerequisite audit prevents mutation.
- [ ] Verify fixture and CLI tests; commit signed.

## Task 3: safe task cleanup

Files: focused cleanup module/tests in `internal/delivery`, CLI resume/status integration.

- [ ] Failing real Git fixtures: ancestry; exact squash-tree match; squash with base movement; extra local commit; wrong PR/head; dirty index; untracked and ignored files; checked-out/shared/default branch; symlink/junction escape; API failure; partial completion and retry.
- [ ] Prove branch tip by ancestry or exact recorded squash-tree equality with a confirmed merged PR and reachable merge commit. Patch-id is never authority. State explicitly that squash proof preserves final tracked content rather than original commit metadata.
- [ ] Restrict removal to the registered task worktree and branch. Inspect actual files including ignored files, refuse unsupported layouts and concurrent-state changes, remove without force, and compare-and-delete the exact proved ref under locking. Never delete the primary checkout or another task's resources.
- [ ] Persist/report partial completion safely: merged/cleanup-blocked remains resumable without re-merging or deleting unrelated work. No blanket authorization for arbitrary `git branch -D` or `worktree remove`.
- [ ] Verify on native Windows and Linux; commit signed. If worktree race safeguards cannot be implemented reliably, keep that operation blocked and report the exact limit rather than claim completion.

## Task 4: `/deliver` lifecycle contract

Files in skills repo: `skills/deliver/SKILL.md`, `references/compatibility-map.md`, relevant `references/cross-harness.md` wording, `evals/evals.json`.

- [ ] Add scenario expectations before editing: explicit `/deliver` implementation task; standing merge/fix/cleanup instruction; resume after compaction; explicit stop-at-PR; design-only; missing repository opt-in; red CI; dirty or ambiguous squash cleanup.
- [ ] Make task endpoint and enforcement authority separate: user instruction authorizes the lifecycle; repository opt-in permits its bounded execution. Preserve both across turns and resume. Do not re-ask for authorization already supplied.
- [ ] Use the Guardrail operation when available and authorized. Older/unconfigured Guardrail remains a reported enforcement blocker; the skill never manufactures a grant or works around a denial.
- [ ] Keep green/review requirements, current-tree validation, actual merge confirmation and safe cleanup as completion criteria. Stop only for concrete exceptions, not at PR creation or each routine lifecycle step.
- [ ] Run existing skill Python tests plus scenario review. Report model-eval/delegation limitations honestly; no invented live results. Separate signed PR in skills repo.

## Task 5: verification, documentation and rollout

- [ ] Amend ADR-0035 with the bounded repository authorization, exact trust assumption and unchanged default protections. Update OPERATIONS/CLI help and CHANGELOG.
- [ ] Post the revised direction and evidence on #606 before the Guardrail PR; link both repository PRs as created.
- [ ] Run Linux and native Windows full Go validation before each Guardrail push, plus each repo's actual CI contract. Fix red checks without weakening expectations.
- [ ] Confirm green CI/reviews, merge when authorized, confirm landed, clean only task resources. Until the new behavior is installed, obey existing exact-action grants for this change itself.
- [ ] Operator enables delivery once on the installed release. Rehearse the complete lifecycle on an authorized disposable repository before asserting live end-to-end support. Report release tag and remaining operator setup.

## Review focus

1. Registration is not authorization: no agent-writable record can widen the operator policy.
2. Revoked policy, modified head or changed GitHub rules must invalidate an earlier eligible result.
3. Protected-path rename/deletion, CI script delegation and file-list truncation cannot bypass the designated boundary.
4. Squash cleanup preserves content, not original history; no heuristic fallback on mismatch.
5. Retries/resumes and concurrent operations must neither double-merge nor delete a moved branch/dirty worktree.
