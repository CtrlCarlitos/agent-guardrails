# Windows PowerShell cmdlet gap and host shell-reporting boundary

## Claim

Initially routing `PowerShell` through the POSIX Bash analyzer left destructive PowerShell cmdlets unclassified; later PowerShell engine rules require proven shell identity, and neither OpenCode nor Antigravity (`agy 1.5.11`) yet reports the resolved shell in hook payloads.

## Context

- Guardrail: `main` as of 2026-09-18 (PR #66) and 2026-11-20 re-check on Windows (`#501`)
- Runtime / plane: Claude Code (`PowerShell` tool), OpenCode (`v2.3.2`), Antigravity (`agy 1.5.11`)
- OS / shell: Windows 11 (`pwsh`)

## Method

1. In PR #66, evaluated `PowerShell` tool payloads containing `Remove-Item -Recurse -Force C:\`, `Get-Content <secret>`, and `Format-Volume` against the Bash analyzer.
2. On 2026-11-20 (#501), inspected the compiled `third_party/jetski/hooks_pb/hooks.proto` (`exa.hooks_pb`) descriptors embedded in `C:\ProgramData\chocolatey\lib\antigravity-cli\tools\agy.exe` (`1.5.11`) for any resolved-shell field on `HookArgsCommon` or `PreRunCommandArgs`.

## Observation

- PR #66 initial finding: `PowerShell` mapped directly to the Bash analyzer, which did not recognize `Remove-Item -Recurse -Force C:\`, `Get-Content <secret>`, or `Format-Volume` and let them pass as unknown commands. The unguarded fixture was removed rather than pinned as expected.
- 2026-11-20 `agy 1.5.11` descriptor inspection (#501): `HookArgsCommon` gained `trajectory_source` since `1.5.9`, but still exposes no resolved-shell field; `PreRunCommandArgs` carries only command/cwd metadata. Upstream OpenCode shell-reporting remains tracked in `anomalyco/opencode#64141`.

## Consequence

- Dedicated PowerShell engine rules were added for explicit PowerShell tools (where the plane proves PowerShell execution, e.g. Claude's `PowerShell` tool and explicit `pwsh`/`powershell` invocations).
- OpenCode and Antigravity adapters stay conservative (ADR-0023 shell-host seam) and do not guess PowerShell readings for generic shell commands until the host explicitly reports its resolved shell (#501).

## Links

- PR: #66 (merged 2026-09-18)
- Issue: #501 (tracked upstream on `anomalyco/opencode#64141` and Antigravity `hooks.proto`)
- ADR: [ADR-0023](../adr/0023-engine-shell-host-seam.md)
