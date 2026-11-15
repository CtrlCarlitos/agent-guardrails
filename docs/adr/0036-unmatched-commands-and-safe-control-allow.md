# ADR-0036: Unmatched commands and safe-control tools allow

## Status

Proposed (2026-11-15). This records behavior that has shipped since ADR-0001
and ADR-0012 but was never written down as a decision. It was found by the
#151 fail-open sweep and changes nothing.

## Context

#151 asks for every path where a missing, unparsed or uninvoked component
yields allow to be either justified in an ADR or fixed. The sweep
([#151 comment](https://github.com/CtrlCarlitos/agent-guardrails/issues/151#issuecomment-6892054540))
found two allow paths that are deliberate but have no ADR:

1. **A command that no rule matches allows.** `evaluateVerdict` returns
   `Allow` when no path, shell or overlay rule produced a verdict
   (`internal/engine/evaluate.go`, the `worst == nil` return). Measured:
   `frobnicate --all /` → allow.
2. **`CapabilitySafeControl` tools allow.** The plane contracts classify
   communication and session-control tools as safe control: Claude's
   `AskUserQuestion`, `Sleep`, `BashOutput`, `KillShell`; Codex's
   `update_plan`, `request_user_input`, `wait_agent`; Antigravity's
   `ask_question`, `wait`, `finish`; and read-only MCP introspection such as
   serena's `list_memories`. The engine allows them without further checks.

Both are allow-by-default sites, so the sweep's bar applies to them. The
difference from a fail-open is that each is a classification the Engine
*made*, not one it failed to make.

## Decision

**The Engine is a denylist over input it has parsed and classified.**

- A shell command is tokenized first. A command the tokenizer cannot read
  asks (`tokenize-failed`). A word in a policy-bearing position that cannot
  be resolved statically asks (`P3.unresolved`). A command that is parsed and
  resolved but names nothing a rule covers runs. Naming every safe program
  is not possible, and ADR-0012 already bounds the shapes the analyser
  learns. The guarantee is that whatever runs was *read*, not that it was
  *recognised*.
- A tool a plane contract classifies as safe control runs, because its
  effect stays inside the session: talking to the operator, waiting,
  planning, or reading the session's own state. A tool the contract does
  not classify is unknown, and unknown never allows: it asks, and Codex
  denies (ADR-0014, ADR-0018 as amended by #151).

Both defaults rest on classification being complete, so the controls that
keep it complete are part of this decision:

- `guardrail doctor --coverage <plane>` diffs the installed tool surface
  against the contract and names uncontracted tools. Those tools ask until
  they are classified.
- Adding a tool as safe control is a contract change reviewed like any
  rule. A tool that reaches outside the session is External (ADR-0018),
  never safe control.

## Consequences

- An unrecognised program can run. The defenses against a harmful one are
  the rules on what it touches: P1 destination writes, P4 secret paths,
  P6 egress, and P3's unresolved targets. Its name is not one of them.
- A misclassified safe-control tool would run unchecked. This is why the
  coverage diff and contract review are part of the decision rather than
  tooling around it.
- The #151 sweep table cites this ADR for these two rows.
