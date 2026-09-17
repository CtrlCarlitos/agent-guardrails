# ADR-0013: Delegation Inherits Enforcement In-Process

## Status

Accepted

## Context

OpenCode's `task` and Claude's subagent delegation were classified as a
delegation capability and denied ("delegation requires verified child guardrail
inheritance") because a spawned agent could otherwise act outside the Guardrail
Policy. The blanket denial stalled agents: they are built to parallelize through
delegation, and guidance could only tell them to work inline.

## Decision

Delegation is allowed on planes whose runtime mediates every tool call —
including subagent calls — through the same Guardrail adapter as the parent.
Today that is OpenCode (the plugin intercepts all tool calls, subagents
included) and Claude Code (hooks fire for all tool calls, Task subagents
included). On these planes delegation inherits enforcement by construction:
each child tool call is normalized and evaluated individually against the
merged policy, so allowing the delegation primitive itself grants no bypass.

Planes without verified child mediation (Antigravity today, Codex planned)
continue to deny delegation with proceed-inline guidance until their runtime
guarantee is established.

## Consequences

- `task` on OpenCode allows (RuleID `delegation-inherited`); per-call verdicts
  inside the child are unchanged.
- Adding a plane requires an explicit inheritance determination before its
  delegation capability can allow.
- The determination is architectural, not evidence-carried: a future
  out-of-process delegation (separate agent host) still needs the denial path
  and an inheritance evidence transport.
