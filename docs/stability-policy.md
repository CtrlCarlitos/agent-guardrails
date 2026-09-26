# Stability policy

What a user, script or dotfiles repo may depend on, what may still move, and how
a stable thing is allowed to change. Written for #103.

**Status of this document.** Every release so far carries a `-dev` suffix and no
`v1.0.0` exists. Until one is tagged, this page is the contract the project
holds itself to, not a promise with a version number behind it. The stable list
below was checked against the code on 2026-09-26; each claim names where it
lives so it can be checked again. Where the code and an earlier draft of this
policy disagreed, the policy was corrected to match the code, never the reverse
(see [Known deviations](#known-deviations-from-the-tidy-story)).

## Stable

A change to anything in this section is a breaking change and follows the
[breaking-change process](#breaking-change-process). Adding is not breaking:
a new subcommand, flag, TOML key, JSON field or rule ID may appear in any
release.

### Verdict format

A verdict is one of `allow`, `ask` or `deny`, with a human-readable reason and a
`rule_id` (`internal/policy/policy.go`: `Verdict`, `Decision`; the audit record
in `internal/audit/audit.go`). Stable means:

- The three decisions keep their meaning: `deny` blocks, `ask` puts the call in
  front of a human where the plane can, `allow` proceeds.
- Every non-allow verdict carries a reason and a rule ID. Rule IDs (`P1.rm-rf`,
  `P5.self-config`, ...) are stable names: a rule may be added, and a rule may
  get stricter, but an ID is not renamed or reused for a different meaning
  without the breaking-change process. Overlay `waive` lists and Operator
  grants refer to rule IDs, which is why they must not drift.
- Severity ordering `allow < ask < deny` and "the stricter verdict wins"
  ([ADR-0026](adr/0026-built-in-and-overlay-verdicts-combine-by-severity.md)).

Not covered: the wording of a reason, and the guidance text an adapter wraps
around it. Do not parse them.

### Hook protocol

Each plane's host sends its own JSON payload on stdin to `guardrail hook <plane>`
(`antigravity` takes a phase, `pre` or `post`) and reads the answer from stdout
and the exit code. The contract is that each adapter keeps speaking its host's
protocol (`internal/adapter/`):

| Plane | Deny | Ask | Allow |
|---|---|---|---|
| Claude | exit 2, guidance on stderr | exit 0, `hookSpecificOutput.permissionDecision: "ask"` on stdout | exit 0 |
| opencode | exit 2, `{"decision":"deny","reason":...}` on stdout | exit 0, `{"decision":"ask",...}` | exit 0, `{"decision":"allow",...}` |
| Antigravity | exit 0, `{"decision":"deny",...}` | exit 0, `{"decision":"force_ask",...}` | exit 0, `{"decision":"allow",...}` |
| Codex | blocking exit or structured block per host rules | blocked with guidance (Codex cannot prompt from a hook, [ADR-0014](adr/0014-codex-native-hooks-and-blocked-asks.md)) | exit 0 |

Anything the hook cannot parse or evaluate fails closed (exit 2, or a deny
payload on Antigravity), never open. That fail-closed behaviour is part of the
contract. The exact JSON each host requires is the host's contract; if a host
changes it, the adapter follows and that is an adapter change, not a break of
this one.

### CLI surface

The subcommands and flags printed by `guardrail help` are stable, along with the
operator commands documented in [OPERATIONS.md](OPERATIONS.md) (`allow-baseline`,
`next`, `approvals ...`). `guardrail daemon` is internal: it is spawned on demand
and does not appear in `help`.

**Exit-code contract.** Verified against `cmd/guardrail` (`run.go`, `plane.go`,
`hook.go`) and by running the binary:

| Code | Meaning |
|---|---|
| 0 | The command did what was asked, or there was nothing to do. For `hook`: the call is allowed or asked (an ask is an answer, not a failure). |
| 1 | The command ran and reports a state or check that is not "fine": `night status` while night mode is inactive, `doctor --coverage` with uncontracted tools, `selftest --evidence` without enough evidence, `update` whose post-install `doctor` or `selftest` failed. A state, not a crash. |
| 2 | Usage error or the command could not run: unknown subcommand, missing or bad arguments, unreadable input, no terminal where one is required. For `hook`: deny, or fail-closed. |
| 3 | Operator action pending (`exitOperatorActionPending`, `cmd/guardrail/plane.go`): the change is waiting on the operator's approval or enrollment; nothing was loosened. Not a failure. Returned by `setup`, `plane enable|disable` and `recover`. |

The code is per command family, so read it with the command: `1` means a check
said no, `2` means the command did not run. A script may rely on `0` meaning
success and `3` meaning "come back with the operator"; anything else non-zero is
a failure to be treated as one.

Not stable: output text, table layout, and the order of lines. Only exit codes
and documented machine-readable output are.

### Overlay format (`guardrail.toml`)

The repository's committed policy file (`internal/policy/config.go`,
`LoadOverlay`; example in `guardrail.toml.example`). Stable: the top-level keys
`engine_min_version`, `audit_log`, `unknown_tool_posture`, `waive`; the
`[slots]` keys `safe_roots`, `secret_dirs`, `secret_globs`, `secret_ask_globs`,
`secret_allow`, `egress_allowlist`, `web_hosts`; `[[rules]]` with `id`, `tool`,
`pattern`, `decision`, `reason`, `waive`; and `[recipes.odoo]`. The rule that an
Overlay may tighten or extend but only loosens with an Operator grant is the
core of the contract ([ADR-0003](adr/0003-overlays-may-waive-universal-rules.md),
[ADR-0010](adr/0010-operator-scoped-loosening.md)). An Overlay that parses today
keeps parsing and keeps meaning the same thing.

### Operator config format (`waivers.toml`)

Machine-scoped, outside every repository, at `guardrail/waivers.toml` under the
platform config directory (`internal/policy/operator.go`; layout in
[operator-config.md](operator-config.md)). Stable: tables keyed by absolute
repository path with `waive`, `secret_allow`, `audit_log`, `egress_allowlist`,
`web_hosts` and `[[grant]]` entries, and the global `[web_hosts] global` and
`[web_research] enforcement` tables. The file name `waivers.toml` is kept even
though the concept is "Operator config".

## Not yet stable

These may change in any release without notice or a deprecation period. A
change is still recorded in the [CHANGELOG](../CHANGELOG.md).

- **Internal Go APIs.** Everything under `internal/` (the Go compiler already
  forbids importing it from outside this module) and every package-level
  identifier in `cmd/guardrail`. Guardrail ships as a binary, not a library.
- **Plane-specific adapter behaviour.** How each adapter projects a host tool
  into a capability and paths, which host tools are contracted
  (`internal/planecontract/`), the guidance text, and the generated native
  config (`gen-config` output, hook command spelling). Verdicts for a given
  call may become stricter or more precise as a plane's contract improves.
  Registered handlers are reconciled by `guardrail setup`, so the spelling is
  expected to move.
- **The MCP registry schema.** The table typing MCP families and tools
  (`internal/planecontract/mcp.go`, [ADR-0017](adr/0017-mcp-family-registry-and-projection.md)):
  its fields, family names and per-tool capabilities.
- **The audit log format.** `audit.jsonl` is JSON Lines
  (`internal/audit/audit.go`, `Record`). Additive changes are fine: new fields,
  and new values for existing string fields. **Removing or renaming a field, or
  changing what one means, is a breaking change** and follows the process below.
  Readers must ignore fields they do not know. The path is stable per platform
  (`$XDG_STATE_HOME/guardrail/audit.jsonl` or `~/.local/state/...` on Unix,
  `%LOCALAPPDATA%\guardrail\audit.jsonl` on Windows) unless an Overlay redirect
  is authorised.
- **Doctor, audit and other human-readable output**, and the approval-daemon
  wire protocol.

## Breaking-change process

1. **Announce** in a GitHub issue labeled `breaking-change` before the change
   lands.
2. **Deprecate for at least one minor version.** The old behaviour keeps
   working and warns on use (a warning, not removal).
3. **Remove in the next major version.**
4. **Document the migration** in the CHANGELOG under a **Breaking** note in the
   release that removes it, and in the release that deprecates it.

A change that makes a rule stricter (a new deny for something previously
allowed) is a policy improvement, not a break of the verdict format, and needs
no deprecation. A security fix that cannot wait may skip the deprecation step;
it must still be announced and carry a CHANGELOG **Breaking** note.

Before `v1.0.0` exists, the same steps are followed as practice, but the
project may make a breaking change in a `0.x` release when the alternative is
leaving a hole; it says so in the CHANGELOG.

## Plane support status

Measured facts only. "Enforced" means guardrail's hook is in the path of the
plane's tool calls in a real session and a call it should stop is stopped.
"Registered" means configuration is written; only an audit record from a real
session shows a hook ran ([OPERATIONS.md](OPERATIONS.md)).

| Plane | Windows | Linux / WSL | macOS | Status |
|---|---|---|---|---|
| Claude Code | Enforced | Enforced | CI-tested; no recorded real-session enforcement verification yet | Supported |
| opencode | Enforced | Enforced | CI-tested; no recorded real-session enforcement verification yet | Supported |
| Antigravity | Enforced | Enforced | CI-tested; no recorded real-session enforcement verification yet | Supported |
| Codex | **Registered, unenforced**: Windows `command_execution` does not dispatch `PreToolUse` ([openai/codex#24453](https://github.com/openai/codex/issues/24453)); doctor says so | Registered; hosted tools and `write_stdin` bypass pre-hooks ([ADR-0014](adr/0014-codex-native-hooks-and-blocked-asks.md)); no enforcement claim made here | CI-tested; no recorded real-session enforcement verification | **Experimental** |

Notes:

- macOS is exercised by CI (unit, contract and installer tests on
  `macos-latest`), which is not the same as watching a real macOS agent session
  get blocked. That verification has not been recorded, so this page does not
  claim it.
- A plane's status is re-checked on the machine with `guardrail doctor`,
  `guardrail selftest` and, where offered, `guardrail selftest --evidence
  <plane>` (`claude` and `codex`). See the plane rows in the README.
- Experimental planes follow the "Not yet stable" rules for their adapter
  behaviour; the Stable sections above still hold for the verdict, the CLI and
  the config formats.

## Known deviations from the tidy story

Recorded as found while verifying this policy; the policy above describes the
code, and these are what the code does that a reader might not expect. Some are
candidates for follow-up issues.

- **A fourth internal decision, `complete`.** `policy.Decision` also has
  `Complete`, used when an operator action was brokered. Adapters surface it as
  a `deny` carrying `operator_action` and `request_id` (and `approval_url`) and
  the audit log records `operator_action`. The public verdict vocabulary stays
  `allow | ask | deny`.
- **Antigravity spells ask `force_ask`**, and its deny is exit 0 with a deny
  payload rather than a non-zero exit.
- **A fail-closed deny has no rule ID.** An unparseable payload, an unloadable
  policy or an invalid Overlay produces a deny whose guidance reads `the rule ID
  ()`. "Every deny carries a rule_id" therefore holds for engine verdicts, not
  for these adapter-level failures.
- **Exit codes are per command.** There is no single table that every command
  follows beyond 0 and 3; `1` and `2` are used consistently as described above,
  but a few commands (`egress`, `gen-config`, `sync`, `hook`) never return 1.
- **The Overlay ignores unknown keys** (only unknown `recipes` settings are an
  error), so a mistyped key does not fail loudly. Forward compatibility relies
  on this; typo detection would be a separate change.
- **The Overlay has no schema version.** `engine_min_version` is the only
  compatibility gate.
- **`breaking-change` label.** The process names a label that did not exist in
  the repository when this was written; it needs to be created before the first
  announcement.
