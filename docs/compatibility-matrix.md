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
| Claude Code | **Enforced, observed** [E1] [E2] | CI-tested only [E7] | Registered only [E9] [E11]; enforcement operator-reported, not recorded [E10] | CI-tested only [E7] |
| opencode | **Enforced, observed** [E2] [E3] | CI-tested only [E7] | Registered only [E11]; enforcement operator-reported, not recorded [E10] | CI-tested only [E7] |
| Antigravity | **Enforced, observed** [E2] [E4] | CI-tested only [E7] | Unknown; operator-reported, not recorded [E10] | CI-tested only [E7] |
| Codex | **Unenforced** [E5] ([openai/codex#24453](https://github.com/openai/codex/issues/24453)) | Registered only; pre-hooks observed in a fixture harness, known bypasses [E6] | Registered only [E11]; enforcement unknown [E12] | CI-tested only [E7] |

Notes on the Codex row:

- Codex cannot prompt from a hook, so an `ask` blocks with guidance on every
  OS ([ADR-0014](adr/0014-codex-native-hooks-and-blocked-asks.md)).
- Hosted tools and `write_stdin` do not pass through pre-hooks on any OS
  ([ADR-0014](adr/0014-codex-native-hooks-and-blocked-asks.md),
  [2026-09-17 mediation probes](research/2026-09-17-codex-mediation-probes.md)).
- The hook payload does not say which shell runs the command or in which
  directory, on Windows or Linux
  ([2026-09-25 execution contract](research/2026-09-25-codex-execution-contract.md)).
  No enforcement claim is made for Codex until that is resolved.

## Shell

The engine judges the command text a host hands to the hook. It parses every
command with one POSIX (bash) parser (`mvdan.cc/sh`, `internal/engine/tokenize.go`),
then maps PowerShell cmdlets (`internal/engine/rules_powershell.go`, #111) and
cmd builtins (`internal/engine/rules_cmd.go`, #139) onto the same rules. No
host tells the hook which shell will run the command, so the shell is never
an input to the verdict.

| OS | Shell | State | Evidence |
|---|---|---|---|
| Windows | Git Bash (MSYS) | **Enforced, observed** for Claude Code's `Bash` tool | [E1] [E2]; MSYS `/c/...` paths: [ADR-0024](adr/0024-windows-agent-experience-mounts-and-wrappers.md) |
| Windows | PowerShell | **Enforced, observed** for PowerShell command text sent by opencode and Antigravity | [E3] [E4]; Claude Code's separate `PowerShell` tool is mapped to the same analyser (`internal/planecontract/claude.go`) but has no real-session record: Unknown |
| Windows | cmd.exe | **Enforced, observed** for `cmd.exe /c ...` text sent by Antigravity | [E4]; Codex's Windows launcher runs under PowerShell or cmd ([ADR-0031](adr/0031-codex-windows-launcher-returns-structured-blocks.md)) but Codex is Unenforced [E5] |
| Linux, WSL | bash, sh | CI-tested only | [E7]; the engine's own dialect |
| macOS | zsh | Unknown | The parser is bash, not zsh. `zsh -c` options are recognised (`internal/engine/tokenize.go`), but zsh-only syntax has no tests and no session record. |

## Install and operator approvals per OS

| OS | Binary and installer | Operator approvals | State |
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
- **[E5]** `guardrail doctor` and `guardrail plane status` print `codex:
  guardrail hooks registered, unenforced: Windows command_execution
  PreToolUse dispatch not observed (external blocker openai/codex#24453)`.
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
