# Overlays may waive universal rules, logged — not an immutable base

A guardrail system whose base rules cannot be switched off sounds safer, but real
projects hit real exceptions, and if the only choices are "comply" or "disable the
whole guard," people disable the whole guard.

Decision: an Overlay may add rules, extend allowlists, and fill parameterized slots
freely; it may **not** silently downgrade a Base `deny` to `allow`. It *may* switch a
named Base rule off with `waive = ["P6"]` — and every waived rule is written to the
audit log on every hit and printed in the agent's session-start banner. A visible,
deliberate, logged exception keeps the rest of the policy alive and leaves a trail.

## Consequences

- The audit log and session-start banner must surface active waivers prominently.
- `guardrail.toml` review in a project's PR flow is where waivers get scrutinised.
