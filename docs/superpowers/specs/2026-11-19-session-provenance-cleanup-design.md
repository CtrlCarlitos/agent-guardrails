# Session-provenance cleanup — design (#630)

## Intent

An agent session that creates a resource pays an operator hand-off to clean
it up (worst case: one approval per command — measured live on 2026-11-19:
`git worktree remove`, `git branch -D`, `gh pr merge` in sequence). The
operator asked for a design that removes that friction without weakening the
gates for resources the session did **not** create.

## Non-goals

- Loosening any rule for resources without provenance. No prefixes, no
  "similar path", no cross-session matches.
- Compound-command denial semantics (an unrelated edit lost when one part
  trips a rule) — separate issue, not solved here.
- `--scope session` for night mode (#83) — orthogonal.

## The families and their friction today

| Cleanup | Rule | Default posture | Creation record available? |
|---|---|---|---|
| `git worktree remove <path>` | P2.git-worktree-remove | ask | yes — `git worktree add <path>` carries the exact path |
| `git branch -D <name>` | (branch safety) | ask | weak — creation is `checkout -b`/`switch -c`/`push -u`; names collide |
| `docker compose -p <name> down -v` | P1.docker-down | deny | yes — `compose -p <name> up` carries the project name |
| `rmdir <dir>` | P1.rmdir | ask | weak — `mkdir` may predate the session or be implicit |
| `git push --force-with-lease` | P1.git-push-force | deny | partial — branch "ownership" is not a creation fact |

## Approaches

1. **Session-provenance allowance (recommended, narrow v1).** The hook
   layer — which already has the session ID and the audit log — checks,
   before emitting a cleanup-class verdict, whether the **exact resource
   identity** (worktree path, compose project name) has a creation record
   from the **same session** in the audit log. Proven → the verdict carries
   a provenance annotation and downgrades one step (deny → ask; ask →
   allow), with the audit record naming the evidence. Not proven → today's
   verdict, unchanged. V1 covers **worktrees only**: one exact-path
   command pair, the highest-repeat friction, zero name-collision risk.
   `docker compose` is the v2 candidate (exact project name, but a deny
   rule with volume deletion — deserves its own measurement). Branches,
   `rmdir` and force-push stay out until creation records are trustworthy.
2. **Full four-family table now.** Same machinery, all families at once.
   Rejected for v1: two of the five creation records are weak, and a
   provenance check on a weak record is a hole, not a feature.
3. **Documentation only.** A runbook section: batch the hand-offs, grant
   the exact commands. Zero risk, zero relief — the measured cost is one
   operator round-trip per cleanup, and today's session showed three in a
   row. Rejected as the whole answer; the section ships regardless.

## Enforcement point

The engine stays pure (no audit access): the check lives in the hook layer
(`cmd/guardrail`), which converts the verdict after evaluation and before
emission, mirroring how `host-auto-ask-escalated` post-processing already
works at the engine boundary. Evidence lookup reuses the per-session scan
shape from `internal/audit/evidence.go`.

## Security posture

- The allowance is **subtractive friction only for self-created state**: a
  session can only unmake what the same session made, identified exactly.
  It cannot reach resources that predate it or belong to others.
- Spoofing ceiling: a hostile session reusing its own session ID gains
  nothing it did not already create. Cross-session replay fails the
  session match.
- Every allowance is audited with the creation record's timestamp and
  command, so `guardrail explain` and the operator can see why a cleanup
  was allowed.
- Fails closed: unreadable or missing audit → today's verdict.

## Decision requested

1. v1 scope: worktrees only (recommended), or worktrees + compose projects?
2. Proven downgrade: ask → **allow** for worktrees (recommended — creation
   was itself allowed/asked in-session), or ask → ask-with-cheaper-path?
3. This needs an ADR (P2 semantics + a new evidence-based allowance);
   number 0039 unless taken by then.
