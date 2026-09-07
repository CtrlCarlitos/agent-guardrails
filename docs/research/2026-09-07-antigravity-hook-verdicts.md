# NF-15: Antigravity hook verdict mapping

Date: 2026-09-07

## Finding

For a `PreToolUse` command hook, Antigravity requires stdout JSON with a
top-level `decision`:

| Guardrail Policy Verdict | Antigravity `decision` | Native behavior |
|---|---|---|
| `allow` | `allow` | Automatically execute the tool. |
| `ask` | `force_ask` | Always prompt, including when Antigravity has a cached permission. |
| `deny` | `deny` | Hard-block the tool immediately. |

Google's hook documentation distinguishes two native prompt outcomes: `ask`
prompts but respects "Always Allow" settings, whereas `force_ask` always prompts
and ignores cached permissions. Plain `ask` is therefore not generally ignored
or defined as allow. It prompts when no applicable cached grant exists; when one
does exist, Antigravity may proceed without a fresh prompt. `force_ask` is
required to preserve the Guardrail Policy's `ask` as an unconditional
human-approval gate.

This matches the repository's domain contract: a Verdict is plane-agnostic
`allow|ask|deny`, and each Adapter maps it to the plane's richer vocabulary,
explicitly naming Antigravity's `force_ask` as the example (`CONTEXT.md:51-54`).

## Repository mapping

- `DESIGN.md:84-100` defines the Antigravity Adapter boundary and records all
  five native pre-tool decision values.
- `internal/policy/policy.go:7-13` defines the shared policy values, including
  `Ask = "ask"`.
- `cmd/guardrail/hook.go:146-152` passes the Engine Verdict to
  `EmitAntigravity`.
- `internal/adapter/antigravity.go:85-99` maps the plane-agnostic Verdict to the
  Antigravity wire value.

`force_ask` remains an Antigravity wire value rather than a fourth Guardrail
Policy Verdict. No Engine or generated-hook configuration change is required.

## Primary sources

1. [Google Antigravity Hooks, `PreToolUse` output contract](https://antigravity.google/docs/hooks.md#pretooluse)
   defines `allow`, `deny`, `ask`, `force_ask`, and
   `deny_unless_prior_grant`; it states that `ask` respects "Always Allow" and
   `force_ask` ignores cached permissions.
2. [Google Antigravity for IDEs Hooks, `PreToolUse`](https://antigravity.google/docs/ide/hooks.md#pretooluse)
   publishes the IDE command-hook contract with the same `ask` versus
   `force_ask` distinction.
