# Stability policy

What a user, script or dotfiles repo may depend on, what may still move, and how
a stable thing is allowed to change. Written for #103.

**Status of this document.** Every release so far carries a `-dev` suffix and no
`v1.0.0` exists. Until one is tagged, this page is the contract the project
holds itself to, not a promise with a version number behind it. The stable list below was re-verified against `main` (`86b62c9`) on both Windows
and Linux on 2026-11-21; each claim names where it lives so it can be checked
again, and `test/docs_stability_test.go` pins schema keys, documented surfaces,
and the compiled binary's exit-code contract in CI. Where the code and an earlier
draft of this policy disagreed, the policy was corrected to match the code, never
the reverse (see [Known deviations](#known-deviations-from-the-tidy-story)).

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
contract. On a host whose permission posture answers asks itself (auto or bypass
mode), an `ask` verdict escalates to a `deny` (`host-auto-ask-escalated`)
naming the operator's terminal ([ADR-0035](adr/0035-hosts-that-answer-asks-themselves.md)).
The exact JSON each host requires is the host's contract; if a host changes it,
the adapter follows and that is an adapter change, not a break of this one.

### CLI surface

The subcommands and flags printed by `guardrail help` are stable, along with the
operator commands documented in [OPERATIONS.md](OPERATIONS.md) (`next`,
`approvals ...`), except what `help` itself marks internal:
`guardrail daemon` (the ADR-0025 resident engine daemon) is listed there as
"internal: not a stable surface". Every subcommand the dispatcher accepts is in
`help` or in the test's hidden list with a reason
(`TestHelpListsEveryDispatchedSubcommand`, #395), so the two cannot drift.

Additive stable CLI surfaces verified on `main`:

- `guardrail explain` (#106): selectors (`last`, a timestamp, a request ID, a
  session ID), flags (`--last N`, `--all`, `--path`), and exit codes (`0`
  explained, `1` nothing matched, `2` usage error or unreadable log).
- `guardrail report` (#124, #585): redacted GitHub issue draft from an audit
  record (`--id`, `--last N`, `--all`, `--path`; same `0`/`1`/`2` exit codes).
- `guardrail status [--json]` (#110): unified per-plane enforcement proof and
  doctor verdict (`0` proven and healthy, `1` unproven or unhealthy, `2` usage
  error; `--json` fields are additive-only).
- `guardrail tail` and `guardrail audit --follow` (#82): live decision stream
  across 20 MB audit rotations (`--format compact|json`, `--plane`, `--verdict`,
  `--lines`/`-n`, `--path`).
- `guardrail night on --scope global|repo|session` (#83): scoped night leases
  (`--until`, `--for`, `--repo`, `--session`).
- `guardrail operator trust [repo-path]` and `guardrail operator untrust [repo-path]`
  (#131): interactive-terminal-only bulk authorization and revocation of a
  repository's Overlay loosening requests.
- `guardrail delivery status|enable|revoke|finish` (#606, #633): bounded
  repository-authorized PR merge and task cleanup.
- `guardrail gen-config` and `guardrail sync` `--major 1|2` (opencode only,
  [ADR-0034](adr/0034-opencode-dual-major-port.md)).

**Exit-code contract.** Verified against `cmd/guardrail` (`run.go`, `plane.go`,
`hook.go`, `status.go`) and by running the binary:

| Code | Meaning |
|---|---|
| 0 | The command did what was asked, or there was nothing to do. For `hook`: the call is allowed or asked (an ask is an answer, not a failure). |
| 1 | The command ran and reports a state or check that is not "fine": `night status` while night mode is inactive, `status` when unproven or unhealthy, `explain`/`report` when nothing matched, `doctor --coverage` with uncontracted tools, `selftest` when any probe fails, `selftest --evidence` without enough evidence, `update` whose post-install `doctor` or `selftest` failed. A state, not a crash. |
| 2 | Usage error or the command could not run: unknown subcommand, missing or bad arguments, unreadable input, no terminal where one is required. For `hook`: deny, or fail-closed. |
| 3 | Operator action pending (`exitOperatorActionPending`, `cmd/guardrail/plane.go`): the change is waiting on the operator's approval (a terminal `[y/N]` or host ask in prompt mode, a passkey in passkey mode) or, in passkey mode, enrollment; nothing was loosened. A declined `[y/N]` for `setup` or `plane` is also 3. Not a failure. Returned by `setup`, `plane enable|disable`, `recover`, `delivery enable`, `approvals grant`, and `operator trust|untrust` (in passkey mode when not enrolled). |

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
`web_hosts`, `[[grant]]` entries, `[<repo>.delivery]` (`DeliveryPolicy`, #606),
and `[<repo>.trust]` (`TrustSnapshot` bulk Overlay snapshots, #131); the global
`[web_hosts] global` and `[web_research] enforcement` tables; and the top-level
`approval = "prompt" | "passkey"` key (missing means `"prompt"`; an unknown
value makes the file unreadable, and an unreadable file means `"passkey"`;
[ADR-0033](adr/0033-operator-approvals-default-to-a-prompt.md)). A binary
older than the `approval` key cannot read a file that sets it and treats
Operator config as empty; remove the key before downgrading. The file name
`waivers.toml` is kept even though the concept is "Operator config".

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
- **Doctor, status, explain, report, audit and other human-readable output**,
  machine-owned state caches (`proof.json`, `selftest-passed`, `night.toml`,
  session/approval stores), and the approval/engine daemon wire protocols. Do
  not parse human-readable CLI output; use documented `--json` flags or
  `audit.jsonl` where machine-readable output is needed.

## Breaking-change process

1. **Announce** in a GitHub issue labeled `breaking-change` before the change
   lands (the label exists in the repository; filter issues by it to see
   every announced break).
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

| Plane | Status |
|---|---|
| Claude Code | Supported |
| opencode | Supported |
| Antigravity | Supported |
| Codex | **Experimental**: on Windows, Codex 0.159+ (re-verified live on `0.170.0`, 2026-11-20) with PowerShell is mediated behind a working-directory check ([#454](https://github.com/CtrlCarlitos/agent-guardrails/issues/454)); other Windows shells fail closed, and earlier Codex did not dispatch ([openai/codex#24453](https://github.com/openai/codex/issues/24453)); hosted tools and `write_stdin` bypass pre-hooks on every OS ([ADR-0014](adr/0014-codex-native-hooks-and-blocked-asks.md)); child delegation remains denied pending upstream pre-effect guarantees ([#587](https://github.com/CtrlCarlitos/agent-guardrails/issues/587)) |

The status is a policy decision. What is actually verified on each OS and
shell, with the evidence for each cell, is in the
[compatibility matrix](compatibility-matrix.md). That page is the single
source for per-OS claims; this one does not repeat them.

- Experimental planes may ship alongside Stable planes in `v1.0.0`: `v1.0.0`
  freezes the Stable sections above (verdict format, hook protocol, CLI,
  Overlay, and Operator config), while an Experimental plane's adapter
  behaviour follows the "Not yet stable" rules until promoted.

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
  for these adapter-level failures. Since #106 they are audited with an empty
  `rule_id` and `audit_kind: hook-fail-closed`, and `guardrail explain` says
  that no rule decided them.
- **Exit codes are per command.** There is no single table that every command
  follows beyond 0 and 3; `1` and `2` are used consistently as described above,
  but a few commands (`egress`, `gen-config`, `sync`, `hook`) never return 1.
- **The Overlay warns on unknown keys but still loads** (only unknown `recipes`
  settings are an error). Forward compatibility relies on the load
  succeeding, so an Overlay written for a newer binary keeps parsing on an
  older one; a mistyped key is a policy warning naming the key and the file
  (`doctor` lists it and counts it toward its verdict line, `sync` prints it,
  the hook passes it on), not a failure (#397).
- **The Overlay has no schema version.** `engine_min_version` is the only
  compatibility gate.
- **`allow-baseline` was removed without a deprecation release** (#531,
  operator ruling, 2026-11-15). It was a stable operator command (#363). The
  hook enforces everything the list could mirror, so the operator retired it
  outright rather than deprecating it for a minor version. The 0.x clause
  above covers removals that close a hole, and this one does not. The removal
  is announced on #531 and carries a CHANGELOG **Breaking** note.
  `guardrail allow-baseline` is now an unknown subcommand (exit 2). The
  operator's own `permissions.allow` list is untouched.
