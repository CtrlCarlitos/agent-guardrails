# Actionable operator authorization for coding agents

**Status:** agreed with Carlitos 2026-09-15. This design supersedes the
agent-facing wording in ADR-0007 and ADR-0011; their OpenCode wire and
approval-memory mechanics remain in force.

## Why

A Guardrail block must leave a coding agent with a safe, actionable next step.
Today an OpenCode `ask` says to ask the user and retry, but calls this a
"confirmation" and does not explicitly distinguish it from a hard Deny. Agents
can misread a Deny as something the operator can overcome by running the command
manually, or give up rather than request the intended approval.

## Decision

The Guardrail Policy retains three Verdicts with these agent-facing contracts:

- `allow`: the Adapter permits the attempted tool call.
- `ask`: **operator authorization required**. The Adapter tells the coding agent
  to request authorization using the plane's operator-approval interaction. Its
  request must identify both the policy reason and the exact attempted action.
  The agent retries only the identical tool call, and only after the operator
  approves it.
- `deny`: **cannot be authorized**. The Adapter tells the coding agent that it
  must choose a safe alternative. It must not request approval, recommend a
  manual bypass, or imply that operator approval can change the Verdict.

`ask` remains the only authorization-eligible Verdict. A definitive secret,
unsafe destructive operation such as `rm -rf /`, or other categorical policy
boundary stays a Deny without an approval prompt. This work does not reclassify
any existing rule.

## Adapter Rendering

The Engine owns the semantic distinction between an authorization-required Ask
and a non-authorizable Deny. Each Adapter renders that distinction using its
plane's native blocked-call mechanism. Where a plane has a real approval prompt,
the Adapter uses it. Where it can only block and return context to the coding
agent, the Adapter returns the instruction that causes the agent to use the
plane's approval interaction.

All planes receive equivalent guidance, but adapters retain control of their
native output shapes and exact rendering. The action shown to the agent is the
exact native tool call it attempted, not a reconstructed or broadened command.
The policy reason comes from the Engine Verdict.

The standard agent-facing text is:

> Operator authorization required: `<reason>`. Request authorization for this
> exact action: `<action>`. If the operator approves, retry this exact tool call
> once. Do not alter or broaden the action.

For a Deny:

> Guardrail denied this action: `<reason>`. It cannot be authorized. Choose a
> safe alternative.

Adapters may add only plane-specific instructions needed to invoke their native
approval interaction; they must preserve these meanings and must not suggest a
manual bypass.

## OpenCode Approval Memory

OpenCode continues to record an Ask and allow one matching retry through its
ten-minute, exact-call approval memory (ADR-0011). The new text is an instruction
to obtain authorization, not a claim that OpenCode can cryptographically verify
that authorization: its existing limitation remains documented. A current Deny
still takes precedence over a pending approval and consumes it.

## Error Handling And Audit

No approval interaction is started for a Deny. If approval is refused, absent,
expired, or the retry differs by session, CWD, tool, arguments, or Ask rule, the
attempt remains an Ask under existing approval-memory rules. Audit behavior and
the `ask-approved-by-retry` record remain unchanged.

## Testing

Tests cover each Adapter's Ask rendering for the authorization instruction,
policy reason, exact action, and exact-retry constraint. They cover Deny
rendering for the non-authorizable safe-alternative instruction. Existing tests
continue to establish that Deny overrides any remembered approval and that
approval is one-shot and exact-call scoped.

## Out of Scope

- Changing any policy classification from Deny to Ask or Allow.
- Allowing an operator to approve an unconditional Deny.
- Replacing OpenCode's approval-memory design with a native plugin-level prompt
  that its extension API cannot create.
- Modifying declarative permission floors except where their presentation must
  use the same terminology.
