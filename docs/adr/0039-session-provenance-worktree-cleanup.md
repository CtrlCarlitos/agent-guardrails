# ADR-0039: A session may remove the worktree it created

## Status

Accepted (operator approval on #630, 2026-11-19: worktrees-only v1, proven
downgrade ask → allow, location-agnostic).

## Context

Auto-mode hosts turn every ask into a deny (ADR-0035), so cleaning up a
worktree the session itself created costs an operator hand-off each time —
measured live on 2026-11-19: `git worktree remove`, `git branch -D`,
`gh pr merge` in sequence, one approval each (#630, from #616 §5).

The audit log already records every mediated `git worktree add <path>` with
its session ID and decision. That record is creation evidence the deny path
currently ignores.

## Decision

1. When the verdict for `git worktree remove [--force] <path>` is an ask
   (or an auto-host escalation of one) under `P2.git-worktree-remove`, the
   hook layer looks for a **same-session** audit record of
   `git worktree add … <path>` whose decision was allow or ask. Found → the
   verdict becomes **allow**, reason naming the creation record's timestamp
   and command; the audit record of the allowance says the same.
2. The path match is **exact** after canonicalization (relative paths
   resolve against the current call's working directory; Windows compares
   case-insensitively). No prefixes, no cross-session matches, no
   flag-shaped lookalikes.
3. The allowance is **location-agnostic**: a worktree inside the repository
   (`.worktrees/<name>`) and one outside the root (`../<name>`) are treated
   identically — provenance is the exact path this session created, not
   where it lives.
4. Fails closed: unreadable or missing audit, unparsable paths, or no
   creation record leave the verdict exactly as it was.
5. v1 scope is worktrees only. Compose projects, branches, `rmdir` and
   force-push stay gated: their creation records are either weak
   (branch creation has no single command; `mkdir` may be implicit) or the
   rule is a hard deny for reasons provenance does not erase
   (`P1.git-push-force` on shared branches). Widening needs its own
   measurement first.

## Security posture

- Subtractive friction only: a session can unmake what the same session
  made, identified exactly. It cannot reach resources that predate it.
- A denied `git worktree add` is not evidence (the creation never happened);
  only allow/ask records count — an ask the operator refused leaves the
  worktree nonexistent, so a later remove fails at git's level, harmlessly.
- Spoofing ceiling: reusing a session ID gains nothing the session did not
  already create; cross-session replay fails the session match.
- Creation evidence expires: records older than 24 hours no longer count
  (a stale session resuming next day pays the normal ask).

## Consequences

- The engine stays pure (no audit access); the check lives in the hook
  layer, mirroring how host-auto escalation and command grants already
  post-process verdicts at that boundary.
- `guardrail explain` shows the allowance with its evidence (the reason
  names the creating command).
- The design doc (`docs/superpowers/specs/2026-11-19-session-provenance-
  cleanup-design.md`) records the rejected alternatives, including the
  full-family table postponed by decision 5.
