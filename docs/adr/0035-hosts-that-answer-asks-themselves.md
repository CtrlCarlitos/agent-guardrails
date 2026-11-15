# ADR-0035: On hosts that answer asks themselves, asks deny

## Status

Accepted (operator ruling on #559, 2026-11-15).

## Context

Claude Code reports the session's permission posture in every PreToolUse
payload (`permission_mode`). In auto/bypass modes the host answers
permission asks **itself** — live evidence on #555 (v0.23.39-dev): a
cross-session `SendMessage` classified External→ask produced no dialog and
did not block. The README's documented stance was "use the passkey", but
the operator runs autonomous agents and ruled for fail-closed: an ask the
operator will never see is an allow in disguise.

## Decision

When the adapter-validated host posture says the host answers permission
asks itself (`ToolCall.HostAutoApproves`; claude wires it from
`permission_mode` `"bypassPermissions"` or `"auto"`, the value Claude Code
2.1.325 reports for auto mode; #151), **every Ask verdict denies**
with guidance naming the posture and the operator's terminal as the honest
channel (`host-auto-ask-escalated`; the originating ask rule is preserved
in `OriginRuleID`). Operator actions in prompt mode take the same shape as
codex's cannot-ask case (`operator-action-terminal`). Allow and Deny
verdicts, night mode's ask→allow relaxation, and passkey mode are
unchanged — a passkey ceremony never depended on the host dialog.

## Boundaries and open work

- `acceptEdits` and `plan` are deliberately not escalated: they do not
  auto-approve tool permission asks. Neither is `dontAsk`, which denies
  permission asks itself.
- opencode `--auto` and codex full-auto are the same hazard but their hook
  payloads do not expose the posture yet; wiring them needs payload
  evidence (#519-style capture), tracked on #559.
- ADR-0011 retry inference is unreachable on such hosts by construction:
  a denied ask cannot be consumed by a retry, which is the intended
  fail-closed reading of the ruling.
