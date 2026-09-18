# ADR-0015: OpenCode asks are answered by the host permission dialog

## Status

Accepted (amends ADR-0011; retry inference remains only as fallback)

## Context

ADR-0011 inferred operator approval from an exact retry because opencode's
`tool.execute.before` could only return or throw, and the permission events
were believed uncorrelatable. As of opencode 1.18.31 (verified against the
installed `@opencode-ai/plugin` and `@opencode-ai/sdk` types):

- the `permission.ask` plugin hook intercepts permission evaluation with an
  output of `ask | deny | allow`; leaving `ask` renders opencode's native
  host dialog;
- `Permission` objects carry `sessionID` and `callID`, and are published on
  the event bus as `permission.updated`;
- the human's reply is published as `permission.replied`
  (`{sessionID, permissionID, response}` with `once | always | reject`);
- `tool.execute.before` receives the same `callID`.

## Decision

The host permission dialog is the Approve control. The plugin subscribes to
the event stream and correlates `permission.updated` → `permission.replied`
to the exact `callID`. When `tool.execute.before` fires for a call whose
`callID` the human allowed, the envelope carries `host_approved: true` and
`call_id`; the Engine converts a current Ask into an Allow audited as
`ask-approved-by-host` with the originating rule preserved. Evidence is
in-memory, per-process, and consumed exactly once for that call only.

`host_approved` is set exclusively by our plugin; model-controlled arguments
never reach it, so it holds the same trust class as the plugin-supplied
paths and command. A current Deny is never downgraded regardless of
evidence. Engine asks that produce no host dialog (uncovered by the
declarative floor) fall back to ADR-0011 retry inference with actionable
guidance.

## Consequences

- Approval strength on OpenCode rises from model honesty to a human click,
  for every ask covered by the declarative floor.
- The floor's ask globs now double as dialog coverage; gaps fall back to
  retry inference and should be closed over time.
- ADR-0011's ten-minute memory remains for the fallback path only.
