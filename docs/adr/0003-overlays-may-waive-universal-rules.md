# Overlays may waive universal rules, logged — not an immutable base

> **Superseded in part by [ADR-0010](./0010-operator-scoped-loosening.md) (2026-09-04).**
> The rationale for a Waiver still stands. ADR-0010 superseded repository
> self-authorization and defines the current Operator authorization boundary.

A guardrail system whose base rules cannot be switched off sounds safer, but real
projects need real Waivers, and if the only choices are "comply" or "disable the
whole guard," people disable the whole guard.

Historical decision: an Overlay could add rules, extend allowlists, and fill
parameterized slots freely; it could not silently downgrade a Base `deny` to
`allow`. It could switch a named Base rule off with `waive = ["P6"]`, without
authorization outside the repository. Every effective Waiver was intended to be
written to the audit log on every hit and printed in Claude's SessionStart
posture. A visible, deliberate, logged Waiver was preferred to disabling the
whole policy.

## Historical Consequences

- The audit log and Claude's SessionStart posture were intended to surface active
  Waivers.
- Repository review was the only authorization boundary for Waivers; ADR-0010
  superseded that behavior.

## Current Boundary

An Overlay's `waive` entry is only a request. It takes effect only when the
Operator config grant for that exact repository authorizes the exact rule ID.
Every effective Waiver is written to the audit log on every hit and printed in
Claude's SessionStart posture. See ADR-0010 for the complete current boundary,
including rules that can never be waived.
