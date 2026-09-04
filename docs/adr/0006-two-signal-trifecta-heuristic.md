# P7 lethal-trifecta gate: two signals, ask not deny, session-state, v1 scope

The classic lethal-trifecta pattern is three legs: private-data access,
untrusted-content ingestion, outbound network capability. The third leg
isn't classifiable from what this codebase tracks today — `PostToolUse`
`tool_response` content isn't parsed anywhere, and there's no taxonomy yet
of which tools/results count as "untrusted." Building that taxonomy well
is real design work with real false-positive risk, deferred until there's
a concrete case for it (confirmed scope decision, 2026-09-04).

Decision: v1 tracks only the two legs the existing `ToolCall` model already
observes — a P4-secret-glob-matching path access, and an invocation of a
P6 network tool — in a small per-session state file (`internal/session`).
When the *second* leg appears in a session that already saw the *first*,
an otherwise-`allow` verdict is escalated to `ask`, never `deny` (a
heuristic earns a confirmation prompt, not a hard block) and never
overrides an existing non-allow verdict (don't stomp a more specific
reason). Firing is scoped to `PreToolUse` only — by `PostToolUse` the
action already happened. `waive = ["P7.trifecta"]` turns it off per repo.

The private-data signal is deliberately independent of P4's own
enforcement: it fires even when `P4.secret-path` is waived. That is the
point — a waiver removes the primary read guard, and the trifecta gate is
what keeps watching for that data being followed by an egress attempt.

## Consequences

- Session state has no dedicated cleanup command; `internal/session.Save`
  opportunistically prunes files older than 24h as a side effect of every
  write. Acceptable for now — sessions are small JSON files, not a real
  storage concern.
- A network attempt to `localhost` or an allowlisted host still counts as
  the "network" leg for trifecta purposes, even though P6 itself would
  allow it — the trifecta gate cares about capability, not destination.
