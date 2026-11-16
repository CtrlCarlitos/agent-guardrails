# Agent access to guardrail commands

What an agent session may run, on each plane, and what happens when it does.
Built from the four live columns recorded on #545 (codex, claude, opencode,
antigravity — each run from a real mediated session); this page is the
synthesis. The exit-code contract itself is
[stability policy](stability-policy.md) — read it alongside.

## The three classes

**Read-only diagnostics** (`version`, `plane status`, `doctor`, `night
status`, `web-research status`, `approvals list`, `explain`, `selftest`)
run from any mediated session on every plane. Their exit codes are states,
not verdicts: `1` means a check said no (night inactive, no daemon to list,
not enough evidence), `2` a usage error. Two selector notes that have bitten
real sessions:

- `explain` takes a **positional** selector (`explain last`, a timestamp, a
  request ID, a session ID); `--last N` is a modifier and needs its N.
  Bare `explain --last` is a usage error (exit 2).
- In zsh, an unquoted variable holding `plane status` passes as **one**
  argument (`unknown subcommand "plane status"`); that is an argv artifact,
  not a guardrail denial.

Read-only status is exact-spelling: `plane status` with no arguments is
exempt from the self-control deny; `plane status claude` is not (it is a
longer argv and a usage error anyway).

**Configuration mutations** (`setup`, `plane enable|disable`, `recover`,
`night on|off`, `web-research on|off`) are operator actions: a mediated
session can *run* the exact canonical command, and the answer is an
approval ceremony, never a silent change. Exit 3 means "waiting on the
operator, nothing changed."

**Protected operator authorization** (`egress grant|revoke`,
`approvals grant`) follows the same boundary — the difference is only in
how each plane can render the ask:

| Plane | An operator action surfaces as | Notes |
|---|---|---|
| **claude** | Default mode: native ask dialog (approval ticket, retry the exact call). Auto/bypass mode: **deny** with terminal guidance — the host would answer the ask itself ([ADR-0035](adr/0035-hosts-that-answer-asks-themselves.md)). Passkey mode: WebAuthn ceremony, independent of the host's permission mode. | |
| **opencode** | Native ask — the host dialog is the approve control ([ADR-0015](adr/0015-opencode-host-owned-approval-evidence.md)), one-shot retry fallback ([ADR-0011](adr/0011-opencode-one-shot-approval-memory.md)). The only plane where the egress-grant ceremony is fully in-band today. | |
| **antigravity** | Native `force_ask` prompt. | No declarative floor — the hook is the boundary ([ADR-0008](adr/0008-antigravity-no-declarative-floor.md)). |
| **codex** | **Deny with terminal guidance** (`operator-action-terminal`): Codex hooks cannot prompt ([ADR-0014](adr/0014-codex-native-hooks-and-blocked-asks.md)). The operator runs the command in their own terminal; the exact-action grant flow ([#349](https://github.com/CtrlCarlitos/agent-guardrails/issues/349)) covers grantable pre-tool asks. | |

## What this page does not promise

Output text, table layout and line order are not stable
([stability policy](stability-policy.md)). The ceremonies above are the
contract; their wording is not. Self-control protection still applies to
every mutating form on every plane — nothing here lets a session
self-authorize.
