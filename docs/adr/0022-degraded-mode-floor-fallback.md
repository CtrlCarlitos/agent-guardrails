# ADR-0022: Degraded mode — the Declarative floor enforces when the Engine is unreachable

## Status

Proposed (the communication valve is landed as PR #161; the read/mutation
generalization below lands only after this ADR is accepted)

## Context

The opencode adapter mediates every tool call by spawning the Engine. When
the Engine cannot spawn — the #132 Windows failure class (CreateProcess +
NTFS + Defender scan latency vs the spawn budget) — the plugin failed
closed on every call, and the 2026-09-20 session locked out for hours:
the agent could not run commands, list directories, or even ask the
operator a question through any tool.

What actually happened during that lockout teaches the design:

1. **The Declarative floor runs host-side, before the adapter.** In-repo
   file reads kept working while the Engine was down: opencode evaluated
   its native permission layer (`opencode.json`, generated from the Policy)
   and only calls that passed it reached the plugin. The floor did its
   documented job — "remains enforced when the Engine is unavailable" —
   by accident of ordering, while the plugin's fail-closed then killed
   exactly those floor-allowed calls.
2. **Fail-closed is correct for what it protects.** A missing engine must
   not become an allow path for commands, egress, or unknown tools. The
   failure was not the denial; it was denying *everything equally*,
   including the recovery channel and floor-covered reads.
3. **The cost asymmetry is real.** A total lockout's cost is measured in
   operator hours and abandoned sessions; a bounded, loud, audited
   degradation's cost is a temporarily coarser policy.

The cross-plane review (claude, codex, antigravity; 2026-09-20) already
accepted the narrowest case unanimously: direct human-communication tools
stay open during an outage (PR #161, `planecontract.DegradedAllow`). This
ADR proposes the general rule.

## Decision

**Degraded mode** is the adapter state entered when the Engine cannot be
spawned (transport failure — `spawnSync` error — after the applicable
retry budget: the full #133 ladder for ordinary tools, one short probe for
DegradedAllow tools). A reachable Engine that denies, exits non-zero, or
returns garbage is NOT degraded mode; it fails closed as today.

In degraded mode, per capability:

| Capability | Behavior | Rationale |
|---|---|---|
| DegradedAllow communication | **allow**, notice, deferred audit (landed, #161) | The ask channel is the recovery path; silencing it removes the guard's own escape |
| ReadDiscovery | **proceed under the floor** | The floor's secret-tier read globs are enforced host-side before the adapter; reads that reach the plugin have already passed them |
| Mutation (edit/write) | **proceed under the floor**, notice, deferred audit | The floor's edit deny/ask globs ran host-side. **Accepted risk:** P5.out-of-repo, overlays, waivers, and session rules are unenforced for the outage window — bounded by duration, noticed per call, and audited after the fact |
| Command (bash) | **fail closed with terminal-fallback guidance** | The floor's bash coverage is enumerated destructive patterns only; arbitrary command execution without engine analysis is the largest exposure and must not proceed |
| WebFetch / WebSearch / External / Delegation / Unknown / MCP | **fail closed** (unchanged) | Egress, recurrence, and unknown surfaces have no floor equivalent |

Every degraded allow emits a stderr notice naming the outage, informs the
agent in the verdict reason ("enforcement is offline for this call"), and
buffers a report that the next healthy Engine call flushes into the audit
log (`transport: "plugin-degraded"`), so ADR-0020 record-counting still
sees mediation across the outage window. One banner per outage window
summarizes the degradation on recovery.

Degraded mode exits the moment any spawn succeeds; full mediation resumes
with no carry-over state beyond the pending audit reports.

## Rejected alternatives

- **Total fail-closed (pre-#161 status quo):** measured cost — the
  #132 lockout, recovery only via operator relay.
- **Trust the floor for everything, including bash:** the floor's command
  coverage is an enumerated pattern list; this converts an engine outage
  into an arbitrary-execution window.
- **Permanent per-tool carve-outs (review's design A):** a standing class
  of unmediated, unaudited calls; rejected unanimously in cross-plane
  review for invariant, drift, and evidence reasons.

## Per-plane applicability

The mechanism requires an adapter we own: today, only the opencode plugin.
Claude Code and Antigravity hooks are bare host-executed commands — their
behavior on spawn failure is host-determined and must be **reported, not
assumed** (Claude Code's silent no-op on a failed hook spawn is exactly
the fail-open class issue #151 tracks; this ADR's floor-first ordering
argument does not excuse it). The contract entries for those planes
(`AskUserQuestion`, `ask_question`) are landed; their valves activate when
those adapters gain a shim.

## Consequences

- An Engine outage degrades to: floor-enforced reads and edits, open
  communication, closed commands/egress/unknowns — instead of a total
  lockout.
- The outage window trades P5/overlay/session enforcement on mutations for
  availability. This is the accepted cost, visible in three places: stderr
  notices, the verdict reason shown to the agent, and post-hoc audit
  records.
- `planecontract.DegradedAllow` becomes one input of degraded mode rather
  than its whole definition; the capability table above is the contract.
- Follow-ups (not blocked on this ADR): a post-hook "N unflushed degraded
  allows" marker when opencode exposes a post surface; doctor surfacing
  observed outage windows; verdict caching to reduce spawn volume is
  explicitly out of scope.
