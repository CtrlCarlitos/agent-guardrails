# Multi-Agent Handoff and Review-Closure Protocol

Lightweight coordination format for concurrent human and AI-agent sessions
sharing this repository (tracked by #96). It complements the house rules in
[`CONTRIBUTING.md`](../CONTRIBUTING.md) and the worktree teardown runbook in
[`OPERATIONS.md`](OPERATIONS.md#multi-agent-worktree-lifecycle-and-teardown)
without introducing a centralized workflow engine.

## Required vs optional handoff fields

Use this record whenever work changes hands (session end, cross-OS verification,
review synthesis, or explicit delegation). Chat alone does not reliably preserve
exact scope or closure state.

| Field | Status | What to record |
|---|---|---|
| **Base SHA** | **Required** | Exact `main` commit the branch or worktree was cut from (`git rev-parse --short main`). |
| **Branch / worktree** | **Required** | Branch name, linked worktree path (if any), and PR number once opened. |
| **Owned files or seams** | **Required** | Files, packages, or behavioral seams this branch owns so concurrent agents do not edit the same surface silently. |
| **Checks actually run** | **Required** | Verbatim commands and measured results per OS (e.g., Windows local, Linux/WSL, or CI gate). Never claim checks that did not run. |
| **Unresolved limitations** | **Required** | Known gaps, skipped tests, upstream blockers, or pending follow-ups (`none` if none). |
| **Next responsible owner** | **Required** | Exact session, host, or human operator expected to take the next action and what that action is. |
| **Dependencies & related issues** | Optional | Blocking/related issue or PR numbers and whether any other branch touches adjacent files (such as `CHANGELOG.md`). |
| **Untracked / generated artifacts** | Optional | Local artifacts present in the worktree (`dist/`, scratch scripts, coverage dumps) that must stay out of git. |
| **Empirical evidence links** | Optional | Paths to evidence files or PR transcripts supporting any runtime or cross-OS claim. |

## Conflict ownership

- **The branch owner owns conflict resolution** unless they explicitly delegate
  it in the handoff record (naming the delegate and branch).
- Do **not** rebase, force-push, or push fixup commits onto another owner's
  branch without explicit delegation.
- When `origin/main` advances while a PR is open (common on shared files like
  `CHANGELOG.md`), the branch owner recovers with a merge commit — never
  `git push --force` (`P1.git-push-force` is denied):
  ```
  git fetch origin
  git merge origin/main
  ```
- Never stack a PR on another owner's branch. Cut every issue branch directly
  from `main` (`git worktree add .worktrees/<name> -b <branch> main`) and run
  `make check-branch` (`scripts/check-branch.sh` / `scripts/check-branch.ps1`)
  before pushing if branch history is uncertain.

## Explicit-file staging

Worktrees frequently accumulate generated or temporary artifacts (`dist/`,
nested `.worktrees/*`, scratch logs, test binaries). Always stage explicit
paths:

```
git status --short
git add <path1> <path2> ...
git diff --cached --stat
```

Avoid `git add -A` or `git add .` when untracked files exist in the worktree.
Before finishing, clean merged branches, linked worktrees
(`scripts/worktree-clean.sh` / `scripts/worktree-clean.ps1`), and `dist/`.

## Review preflight

Before calling a reviewer tool, identify the active plane from the session
context and check its inheritance determination in
[ADR-0013](adr/0013-delegation-inherits-enforcement-in-process.md).
When the plane has verified child mediation and the current workflow
authorizes delegation, request independent review through that plane's
mediated reviewer tool.

For Codex, an unknown plane, or a plane without verified inheritance, go
directly to inline review. Use the same fallback if Guardrail denies
delegation after preflight. Review the diff against the task and repository
requirements, address findings, and report **Inline review completed.
Independent review unavailable.** Record this in the PR or handoff.

If the repository or task requires independent review, record the missing
review as a delivery blocker. Continue other authorized work while waiting
for an eligible reviewer. Inline review leaves that requirement pending.

## Review-closure protocol

When a PR synthesizes multi-reviewer feedback or documentation across multiple
agents, chat summaries frequently mark findings "addressed" while the final
diff silently drops or reverts a fix.

1. **Map every review finding to its concrete resolution** in the PR comment or
   handoff record (finding ID, concise summary, exact file/line or commit SHA,
   and disposition: `fixed`, `deferred` with issue number, or `wontfix` with
   rationale).
2. **Originating reviewer verifies closure.** A synthesized finding is not
   closed until the originating reviewer (or the explicitly delegated reviewer
   named in the handoff) inspects the final diff and confirms closure.
3. **Re-open on regression.** If a subsequent merge or edit re-introduces a
   closed finding, re-open the row rather than adding a separate unstructured
   comment.

## Copyable handoff template

```markdown
### Handoff — #<issue> (<short title>)

- **Base SHA:** `<short-sha>` (`main`)
- **Branch / worktree:** `<branch>` (`.worktrees/<name>`, PR #<pr>)
- **Owned files or seams:** `<path-or-package list>`
- **Checks actually run:**
  - Windows: `<command -> result>`
  - Linux / macOS: `<command -> result, or "CI gate only (no local Linux)">`
- **Unresolved limitations:** `<list or "none">`
- **Next responsible owner:** `<agent/host/operator — exact next step>`
- **Dependencies / related (optional):** `#<n>`
- **Artifacts to exclude (optional):** `<e.g. dist/, scratch files>`
- **Conflict delegation (optional):** `branch owner retains` (or `delegated to <owner>`)
```

## Finding-to-resolution example

Example from a multi-agent documentation/code synthesis review:

| Finding | Source reviewer | Resolution (commit / file:line) | Originating reviewer closure |
|---|---|---|---|
| `F-1` | Linux reviewer | `CHANGELOG.md` dropped `#83` bullet during conflict resolution → restored both `#110` and `#83` entries (`129920a`, `CHANGELOG.md:9-47`). | Verified by Linux reviewer (`129920a`) |
| `F-2` | Windows reviewer | `doctor` inserted `overlay trust:` between `policy warnings:` and `waivers:`, breaking section parser → moved `printDoctorTrustDiff` after `waivers:` (`345d00f`, `cmd/guardrail/doctor.go:398-401`). | Verified by Windows reviewer (`345d00f`) |
| `F-3` | Codex reviewer | Native `webauthn.dll` request in `#86` conflicts with ADR-0021 §5/§7 → deferred/closed as superseded by ADR-0021 + ADR-0033 (`#86` comment). | Verified by operator |

## PR and handoff checklist

- [ ] Branched directly off current `main` (not stacked on another PR's branch).
- [ ] Owned files/seams match the issue scope; explicit paths staged (`git diff --cached --stat` inspected).
- [ ] TDD: failing test observed before fix; root cause stated in PR body.
- [ ] Verification reported per OS with measured results only (`gofmt`, `go build ./...`, `go vet ./...`, `go test ./... -count=1`, plus CI status).
- [ ] Review findings mapped to commit/file:line and closed by the originating reviewer (for synthesized or multi-reviewer changes).
- [ ] Post-merge house cleaning complete: `main` fast-forwarded, merged branch and `.worktrees/<name>` removed, no `dist/` left behind.

## Trial notes and overhead adjustments

Trialed across the 2026-11-21 concurrent Windows + Linux delivery cycle (PRs
`#647`, `#648`, `#651`–`#657` spanning `#82`, `#83`, `#84`, `#92`, `#95`,
`#102`, `#109`, `#110`, `#131`):

- **What prevented rework:** Claiming issues via a one-line issue comment naming
  base SHA and owned scope eliminated duplicate work; keeping conflict resolution
  with the branch owner (`git merge origin/main` on `CHANGELOG.md` contention)
  prevented owner-external rebase accidents.
- **Overhead trimmed:** Made dependencies, artifacts, and evidence links
  explicitly optional for single-owner, single-PR issues so routine fixes need
  only the 6 required fields, while keeping the finding-to-resolution table
  mandatory only for synthesized or multi-reviewer changes.
