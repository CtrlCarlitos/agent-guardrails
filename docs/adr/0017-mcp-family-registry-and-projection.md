# ADR-0017: MCP Family Registry and Argument Projection

## Status

Accepted

## Context

The four-plane coverage audit (2026-09-18) found one root cause behind every
coverage gap: MCP server tools arrive under plane-specific naming with their
arguments unprojected. opencode delivered them under bare names that missed
the `mcp*` prefix rule entirely (`CapabilityUnknown` → allow-by-default; 131
unevaluated hits, 89 of them mutations). claude and antigravity caught
`mcp__`-prefixed names with a blanket External/Deny, but a serena write to a
secret-tier path got an Ask rather than the P4/P5 Deny a native edit earns —
and night mode relaxes that Ask to Allow. antigravity additionally exposes
`call_mcp_tool`, a generic invoker no prefix rule can catch.

## Decision

1. **Central registry** (`internal/planecontract.MatchMCPTool`): known MCP
   families (serena, graft) map each tool to a capability plus the argument
   names that carry file paths. Matching accepts every plane's naming — bare
   `serena_replace_content`, family-joined, and `mcp__server__tool`.
2. **Argument projection**: adapters project the spec's path arguments into
   `ToolCall.Paths` (opaque ids resolve under their store, e.g. serena
   memories under `.serena/memories/`), so MCP mutations and reads run
   through the full path policy — secret tiers, protected machinery, symlink
   escape — identical to native tools. Projection failures fail closed
   (path capability without paths denies).
3. **Unknown posture by plane**: opencode's unclassified tools now Ask
   (cheap under the ADR-0015 host dialog) instead of silently allowing;
   claude keeps audit-allow for native unknowns with `mcp__` → External;
   antigravity and codex stay fail-closed. Generic invokers
   (`call_mcp_tool`, `tool_caller`) cannot be re-dispatched safely and stay
   denied at their planes.
4. Registry typing outranks the `mcp`/`custom` prefix rules; unknown
   prefixed names keep their plane's blanket treatment.

## Consequences

- The audited serena/graft surface is now typed with real path evaluation on
  every plane whose adapter wires the registry (opencode ships here; claude
  and antigravity wire in their follow-up PRs).
- New MCP servers surface as opencode Asks — a one-time operator decision
  per tool — instead of silent allows; adding a family is a registry entry.
- Registry entries are trust decisions: a path-arg name that a server can
  change silently is accepted deliberately, same as a plane's own contract.
