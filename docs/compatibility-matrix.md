# Compatibility matrix

Which host, OS and shell combinations guardrail is known to protect, and how
we know. This is the one place per-OS support claims live. The
[stability policy](stability-policy.md) says which planes are Supported or
Experimental and links here for the evidence.

A released binary, passing tests, a registered hook and a blocked call in a
real session are four different claims. Each cell below makes only the claim
its evidence supports, and names the evidence.

## States

| State | Meaning |
|---|---|
| **Enforced, observed** | Audit records from real sessions on that OS show the host sent tool calls to the hook and got `ask` and `deny` verdicts back. |
| **Registered only** | Guardrail's hook configuration is written and `doctor` reports it. Nothing on record shows the hook running in a real session. |
| **Unenforced** | A known host gap: the hook is registered but the host does not send the calls to it. `doctor` says so. |
| **CI-tested only** | Unit, contract-fixture and installer tests pass on a CI runner of that OS. No real agent session has been recorded. |
| **Unknown** | No evidence in the repository either way. |

"Observed" is a heuristic, not a coverage proof. It shows the hook ran, not
that every tool call reached it (see `Live-mediation evidence` in
[CONTEXT.md](../CONTEXT.md)).

## Plane × OS

| Plane | Windows native | Linux | WSL | macOS |
|---|---|---|---|---|
| Claude Code | **Enforced, observed** [E1] [E2] | **Enforced, observed** [E15] | Registered only [E9] [E11]; enforcement operator-reported, not recorded [E10] | CI-tested only [E7] |
| opencode | **Enforced, observed** [E2] [E3] | **Enforced, observed** [E16] | Registered only [E11]; enforcement operator-reported, not recorded [E10] | CI-tested only [E7] |
| Antigravity | **Enforced, observed** [E2] [E4] | **Enforced, observed** [E13] | Unknown; operator-reported, not recorded [E10] | CI-tested only [E7] |
| Codex | **Enforced, observed** [E5] on Codex 0.159+ with PowerShell: allowed commands run behind a PowerShell working-directory check proven by the session transcript; other shells fail closed; known bypasses [E6] ([#454](https://github.com/CtrlCarlitos/agent-guardrails/issues/454)). Before 0.159 no dispatch ([openai/codex#24453](https://github.com/openai/codex/issues/24453)) | **Enforced, observed** [E14] on Codex 0.170.0 for local Bash pre-hooks; known bypasses [E6] | Registered only [E11]; enforcement unknown [E12] | CI-tested only [E7] |

Notes on the Codex row:

- Codex cannot prompt from a hook, so an `ask` blocks with guidance on every
  OS ([ADR-0014](adr/0014-codex-native-hooks-and-blocked-asks.md)).
- Hosted tools and `write_stdin` do not pass through pre-hooks on any OS
  ([ADR-0014](adr/0014-codex-native-hooks-and-blocked-asks.md),
  [2026-09-17 mediation probes](research/2026-09-17-codex-mediation-probes.md)).
- The hook payload does not directly identify the effective interpreter or
  per-call execution directory
  ([2026-09-25 execution contract](research/2026-09-25-codex-execution-contract.md)).
  On Windows, the adapter uses the selected session's transcript to prove
  PowerShell and checks the execution directory as described in the row above
  and [ADR-0014](adr/0014-codex-native-hooks-and-blocked-asks.md). An absent or
  unproven shell keeps the refusal; a healthy transport probe is not shell proof.

## Shell

The engine judges the command text a host hands to the hook. Its shared
normalizer uses the POSIX parser (`mvdan.cc/sh`, `internal/engine/tokenize.go`)
with a PowerShell reading when the adapter can prove that dialect. Claude's
native `PowerShell` tool supplies that identity; on Windows, Codex's adapter
sets `ToolCall.Shell` from its session-bound transcript. The PowerShell reading
recognizes `$true`, `$false` and `$null` as constants, including inline switch
values such as `-Confirm:$false` (#495/#498).

PowerShell cmdlet checks (`internal/engine/rules_powershell.go`, #111) and cmd
builtin checks (`internal/engine/rules_cmd.go`, #139) also map recognized command
families onto the shared policy. Observing those checks does not prove the
outer interpreter or full dialect attribution. OpenCode and Antigravity leave
`ToolCall.Shell` unset; PowerShell-looking text can therefore still require
operator review as `P3.unresolved`. The existing unknown-cmdlet denial remains
in force.

| OS | Shell | State | Evidence |
|---|---|---|---|
| Windows | Git Bash (MSYS) | **Enforced, observed** for Claude Code's `Bash` tool | [E1] [E2]; MSYS `/c/...` paths: [ADR-0024](adr/0024-windows-agent-experience-mounts-and-wrappers.md) |
| Windows | PowerShell | **Cmdlet checks observed**, dialect attribution depends on the plane | [E3] [E4] for OpenCode/Antigravity command text; their outer shell is unproven (#501). Claude's native `PowerShell` tool and transcript-proven Windows Codex calls select the PowerShell reading; live-session claims remain as recorded above. |
| Windows | cmd.exe | **Enforced, observed** for `cmd.exe /c ...` text sent by Antigravity | [E4]; a Codex launcher's interpreter does not prove its command interpreter. Windows Codex command rewrites require transcript-proven PowerShell; other shells fail closed ([ADR-0014](adr/0014-codex-native-hooks-and-blocked-asks.md)). |
| Linux, WSL | bash, sh | CI-tested only | [E7]; the engine's own dialect |
| macOS | zsh | Unknown | The parser is bash, not zsh. `zsh -c` options are recognised (`internal/engine/tokenize.go`), but zsh-only syntax has no tests and no session record. |

### OpenCode and Antigravity shell attribution (#501)

The [OpenCode V1/V2 event evidence](https://github.com/CtrlCarlitos/agent-guardrails/issues/501#issuecomment-6898777037)
and [Antigravity CLI/desktop schema evidence](https://github.com/CtrlCarlitos/agent-guardrails/issues/501#issuecomment-6897197733)
show no resolved-shell field at the command guard's existing boundary.
Antigravity's internal `shell_name` does not appear in its PreToolUse envelope
or model arguments. OpenCode's tool execution events expose tool arguments,
not the final interpreter selected by the host.

Reading OpenCode's preferred `shell` config does not establish that final
interpreter. In [V2 2.3.0, commit a6b15d3](https://github.com/anomalyco/opencode/blob/a6b15d33daf6ab7d35569f6d711fdb630b9f04e7/packages/core/src/shell.ts#L880),
shell creation accepts a per-call shell, otherwise resolves a default, then
runs mutable shell lifecycle callbacks before spawning. The
[selector can fall back](https://github.com/anomalyco/opencode/blob/a6b15d33daf6ab7d35569f6d711fdb630b9f04e7/packages/core/src/shell/select.ts#L120)
when a configured executable is unavailable; config also supports reload.
The later [`shell.create.before` event](https://github.com/anomalyco/opencode/blob/a6b15d33daf6ab7d35569f6d711fdb630b9f04e7/packages/plugin/src/effect/shell.ts)
does expose a mutable `shell`, but it lacks the documented failure contract of
the veto-capable [`tool.execute.before` hook](https://github.com/anomalyco/opencode/blob/a6b15d33daf6ab7d35569f6d711fdb630b9f04e7/packages/core/src/plugin/hooks.ts#L23).
It also lacks a typed session/call identity to bind that later event to the
earlier verdict. No absence of overrides is established by the tool-event
types alone.

Guardrail therefore does not infer PowerShell from config, command syntax,
`$SHELL`, installed executables, or the name of a nested `powershell -Command`
invocation. The needed upstream contract is the **resolved outer interpreter
for this command**, bound to a synchronous, veto-capable event and the actual
spawn. Any later interpreter change must invalidate that verdict or repeat
evaluation. Until that exists, both adapters retain the conservative reading;
no permissive fallback is added.

## Install and operator approvals per OS

Operator approvals default to **prompt mode** on every OS
([ADR-0033](adr/0033-operator-approvals-default-to-a-prompt.md)): a terminal
`[y/N]`, or the agent host's own ask for the exact canonical command (Claude
Code `ask`, Antigravity `force_ask`, opencode's dialog where its permission
settings ask; Codex cannot ask from a hook and is told to hand the command to
the operator). State: covered by the Go suite on Windows (this host) and by
CI on Linux and macOS, with sandboxed state roots; no live host-ask session
is on record yet, and the terminal `[y/N]` has been exercised only through
the test seam, not a real console. The WebAuthn column below is **passkey
mode** (`approval = "passkey"`).

| OS | Binary and installer | Operator approvals (passkey mode) | State |
|---|---|---|---|
| Windows | `guardrail_windows_amd64.exe`, `guardrail_windows_arm64.exe`; `install.ps1` under PowerShell 5.1 and 7 | Browser WebAuthn over a per-user named pipe ([ADR-0021](adr/0021-windows-approval-broker.md), [ADR-0025](adr/0025-persistent-daemon-broker-windows.md)) | **Observed** on amd64 [E8]; arm64 CI-built only |
| Linux | `guardrail_linux_amd64`, `guardrail_linux_arm64`; `install.sh` | Browser WebAuthn over a Unix socket | CI-tested only [E7] |
| WSL | the Linux binary and `install.sh` | Same as Linux; the page opens in the Windows browser and names the instance ([operator-approvals.md](operator-approvals.md)) | Bootstrap arming observed; a completed passkey approval is not on record [E11] |
| macOS | `guardrail_darwin_amd64`, `guardrail_darwin_arm64`; `install.sh` | Browser WebAuthn over a Unix socket | CI-tested only [E7] |

A Windows and a WSL instance on one machine are separate: separate binaries,
audit logs, Operator configs and passkeys. A passkey enrolled for one cannot
approve the other ([operator-approvals.md](operator-approvals.md)).

## Evidence

Measured on 2026-09-26 on Windows 11 Pro 10.0.26200 (amd64) with the
installed guardrail v0.23.8-dev, Claude Code 2.1.283, opencode 1.18.31,
Antigravity `agy` 1.2.7 and Codex CLI 0.157.0. Only read-only commands were
run.

- **[E1]** `guardrail selftest --evidence claude` exited 0: `claude: live
  mediation observed (heuristic); the registered hook is running`
  (984 eligible records, 1 qualifying session). `guardrail doctor` reported
  `claude settings: guardrail hook registered` without the `NEVER OBSERVED
  FIRING` caveat.
- **[E2]** The audit log (`%LOCALAPPDATA%\guardrail\audit.jsonl`, two
  segments) holds real-session records from 2026-09-16 to 2026-09-26 with
  `ask` and `deny` verdicts for Claude Code (`Bash`, `Edit`, `Write`, `Read`),
  opencode (`bash`, `edit`, `read`, `apply_patch`) and Antigravity
  (`run_command`, `view_file`, `replace_file_content`). `guardrail selftest`
  exited 0: `claude: probes pass (11)`, `opencode: probes pass (3)`,
  `antigravity: probes pass (7)`, `codex: probes pass (2)`.
- **[E3]** opencode sessions (`ses_…` ids) recorded 329 `ask` and 32 `deny`
  verdicts, including a `deny` for `Remove-Item -Recurse -Force` on
  2026-09-26. Windows spawn latency can make the opencode plugin fail closed
  ([OPERATIONS.md](OPERATIONS.md#windows-engine-unreachable-opencode-spawnsync-etimedout)).
- **[E4]** An Antigravity session on 2026-09-26 recorded 10 `ask` and 1
  `deny` verdicts for `run_command`, with PowerShell (`Test-Path`) and
  `cmd.exe /c` command text.
- **[E5]** Codex 0.159.0 on Windows (operator's machine, pwsh 7,
  v0.23.25-dev, 2026-09-30). `codex exec "…: echo probe"`: Codex ran
  `pwsh.exe -Command '<guardrail precondition>\necho probe'` in the repo and
  printed `probe`. A call with `workdir: C:\Users\carlitos\Documents` ran the
  same rewrite there and exited 1 with `guardrail: Codex workdir differs …`;
  the model then retried with an explicit `Set-Location -LiteralPath …`,
  which guardrail evaluated and allowed. Audit records: `plane: codex`,
  `event: pre`, `decision: allow`, `input_keys: ["command"]`. Before
  v0.23.25-dev every allowed command was refused with `cannot prove the
  Windows command shell` (#454); before Codex 0.159 PreToolUse did not
  dispatch at all (openai/codex#24453).
  `guardrail selftest --evidence codex` exited 1: `codex: live mediation not
  yet observed; approval-proposal gate remains closed`. The same result on
  Codex 0.154.0 is in the
  [2026-09-20 Windows validation](research/2026-09-20-codex-windows-validation.md).
  An observer-only probe on Codex 0.155.1 did see `PreToolUse` for fixed shell
  commands
  ([2026-09-25 execution contract](research/2026-09-25-codex-execution-contract.md));
  that is dispatch, not enforcement, and doctor's claim is unchanged.
- **[E6]** [2026-09-17 plane probes](research/2026-09-17-codex-plane-probes.md):
  Codex CLI 0.154.0 on Linux with a local fixture model sent 16 direct and 14
  code-mode calls to the hook, and the expected verdicts came back. It is a
  harness, not a live session, and the OS was not recorded as native Linux
  or WSL. The [mediation probes](research/2026-09-17-codex-mediation-probes.md)
  show `write_stdin` bypassing the hook.
- **[E7]** CI (`.github/workflows/ci.yml`) runs `go test ./...` on
  `ubuntu-latest` and `macos-latest`, a Windows slice on `windows-latest`, and
  the installer harnesses on all three (`install.ps1` under PowerShell 7 and
  Windows PowerShell 5.1).
- **[E8]** This host's audit log records a `transport: bootstrap` plane
  enable on 2026-09-24 and three `transport: webauthn` plane enables
  (`requested`, then `completed`) on 2026-09-26. `guardrail doctor`
  reports `operator approvals: WebAuthn`.
- **[E9]** [HANDOFF-2026-09-03.md](HANDOFF-2026-09-03.md): on Linux/WSL
  installs `guardrail doctor` showed `guardrail hook registered`.
- **[E10]** The stability policy's first support table marked these cells
  Enforced from the operator's statement, with no run recorded (PR #393
  body). They stay operator-reported until a dated record exists.
- **[E11]** Issue #383 (WSL2 Ubuntu 24.04, installer v0.23.9-dev): the
  ADR-0030 bootstrap armed the planes unattended, and a later re-enable of
  claude, opencode and codex reached the passkey ceremony, which failed in
  the Windows browser. The fix
  shipped; a completed WSL approval after it has not been recorded.
- **[E12]** The 2026-09-25 execution-contract probe ran Codex 0.154.0 inside
  WSL, but its hooks only observe and never call guardrail.
- **[E13]** [Linux Antigravity (`agy 1.5.13`) live acceptance proof](evidence/2026-11-21-linux-antigravity-live-acceptance.md)
  (2026-11-21, `main` at `347c00b`, `linux/amd64`): `test/acceptance/harness.py
  --host antigravity --live` exited 0 (`pass: 11, fail: 0`,
  `live_runtime_session_observed: true`), recording real session
  `16ad5b1e-5d1b-4a3e-9ed9-afebf225658b` denying `read_file` on `.env` as
  `P4.secret-path` and allowing `read_file` on `hello.txt` with zero secret
  sentinel leakage and real home untouched. Hermetic lifecycle stages also
  passed install/update via `install.sh`, `doctor`, `selftest`, prompt-mode
  `host-ask` approval/retry + replay refusal, PTY `[y/N]` disablement, and
  corrupt `hooks.json` recovery.

- **[E14]** [Linux Codex 0.170.0 authenticated live acceptance](evidence/2026-11-21-linux-codex-live-acceptance.md),
  2026-11-21. The authenticated `codex exec` session received the benign
  Bash command's output and a `P4.secret-path` denial on the fake `.env`
  read. Session-specific `selftest --evidence codex` passed. This observation
  covers the tested local shell calls.
- **[E15]** [Linux Claude Code acceptance and real-session verdicts](evidence/2026-11-21-linux-claude-code-acceptance.md),
  2026-11-21. This host's audit log holds three real Claude Code sessions.
  One (2026-11-16) has 10 `ask` verdicts and a `deny`, all for `Bash`
  calls; another has `deny` verdicts for `Bash` and `Edit` calls. `Read`
  and `Write` calls reached the hook and were only ever allowed.
  `guardrail selftest --evidence claude` exited 0 on the two newest
  sessions. The isolated lifecycle run (`test/acceptance/harness.py --host
  claude`) passed. Its nested `claude -p` stage had no login and reported
  `operator_assisted`, so no harness-driven live session is claimed.
- **[E16]** [Linux opencode live acceptance](evidence/2026-11-21-linux-opencode-live-acceptance.md),
  2026-11-21. `test/acceptance/harness.py --host opencode --live` exited 0
  with `live_runtime_session_observed: true`: a real opencode 2.3.2 session
  in an isolated home got its allowed `bash` read back and a
  `P4.secret-path` denial on the fake `.env`. That session has no `ask`.
  The `ask` verdicts, for `Bash` and `Edit` calls, come from four other
  opencode sessions in this host's audit log, which also hold policy
  `deny` verdicts for `Bash` and `webfetch` calls; the log does not record
  their opencode version. The opencode 1 wiring was not exercised on
  Linux.

## Keeping it true

The operator owns this page. Update a cell when one of these happens, and
date the evidence you add:

- a real session on a new OS, host version or shell is checked with
  `guardrail doctor`, `guardrail selftest` and `guardrail selftest --evidence
  <plane>` (`claude` and `codex` are supported), and the audit log shows
  `ask` or `deny` records from it;
- a release changes an adapter, the generated hook config or a doctor line
  this page quotes;
- a host changes its hook contract, or an upstream blocker such as
  openai/codex#24453 closes.

Do not upgrade a cell on a CI result, a registration line or a `selftest`
pass alone. Those are the lower states on purpose.
