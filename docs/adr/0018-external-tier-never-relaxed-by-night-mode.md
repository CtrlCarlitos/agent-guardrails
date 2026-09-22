# ADR-0018: The External Tier Is Never Relaxed by Night Mode

## Status

Accepted

## Context

Night mode relaxes Ask verdicts to Allow so unattended overnight work is not
blocked on routine confirmations. As the cycle added the External tier
(CapabilityExternal: artifact publication, cron, MCP reach, schedule
recurrence) and per-plane unknown-tool asks, night mode silently widened:
it began granting *outward reach* — publishing artifacts, creating cron
jobs, calling unknown MCP families — which was never its intent. Claude's
coverage-cycle review flagged this as the highest-risk remaining gap.

## Decision

1. Night mode relaxes only in-session asks. Verdicts whose subject is
   outward reach or classification are preserved: `capability-external`,
   `capability-web-search`, and `unknown-native-tool` stay Ask overnight.
   `P1.power` (#140) joins the set on the same property — a machine-level
   act is a per-call operator decision, and an overnight window must not
   answer "may I reboot?" on the operator's behalf. Deny invariance is
   unchanged.
2. Claude's unknown-tool posture joins opencode's: unclassified tools Ask
   rather than allow (audit posture remains only for unattributed calls).
   ADR-0017's registry and ADR-0015's host dialogs make asking cheap.
3. Glossary (CONTEXT.md): the External tier — tools whose effect leaves the
   session (publication, scheduling, MCP servers, external services) — are
   per-call operator decisions, never blanket-denied, never night-relaxed.
   Text-mention verdicts (`P4.secret-in-text`,
   `P5.self-config`/NightMentionReason) distinguish a secret or control
   *named inside command text* from a *path access*: still Deny, with
   Write/Edit redirection guidance.

## Consequences

- Overnight autonomy no longer implies overnight egress or publication.
- New unclassified tools surface as asks on both dialog-capable planes.
- Preserved-ask set is explicit in the Engine and test-pinned; adding an
  outward-reach rule — or, since #140, a machine-level-effect rule — means
  adding it there.
