# ADR-0024 — Windows agent experience: MSYS/Git Bash mount resolver, inspectable Codex wrapper hooks, and degraded-allow UX

**Date:** 2026-09-21  
**Status:** Proposed  
**Issues:** Group 3 (Agent experience: Windows-host-specific)  
**Author:** AGY (Antigravity)

---

## Context

Three issues affect agent experience when running on Windows hosts:

### 1. MSYS / Git Bash Drive Mounts (ADR-0023 Extension)

ADR-0023 separated shell-lexical analysis from host-filesystem probing. On Windows, `hostCanProbe` returns `false` for all POSIX-absolute paths (paths beginning with `/`), and `cdDirectoryState` returns `cdDirectoryUnknown` (fail-closed).

This safely resolved #214 (`cd /etc && rm -rf .`), but left an accepted narrowing in §Consequences: Git Bash sessions frequently use POSIX drive paths such as `/c/Users/...` or `/c/repo/...`. Because `/c/...` starts with `/`, the engine treats it as unprobeable on Windows:
- Every `cd /c/...` target returns `cdDirectoryUnknown`, causing the command tail to be evaluated at an unknown working directory.
- Subsequent operations produce conservative `P3.unresolved` asks even for legitimate, in-repo work.
- Path containment checks in `authorizedPath` that compare relative paths against `tc.RepoRoot` (`C:\repo`) resolve `/c/repo` as `C:\c\repo` if passed raw to Win32 `filepath.Abs`.

### 2. Opaque `-EncodedCommand` Hooks in Codex

`internal/genconfig/codex.go` generates hook commands for Codex on Windows:

```text
powershell.exe -NoLogo -NoProfile -NonInteractive -EncodedCommand <Base64> || (echo guardrail: ... 1>&2 & exit /b 2)
```

Base64 UTF-16LE encoding was chosen to prevent `cmd.exe` from interpreting shell metacharacters in arbitrary binary paths while ensuring fail-closed exit code 2. However:
- In `.codex/hooks.json`, long Base64 strings resemble obfuscated payloads and fail human trust reviews during onboarding.
- Security audit logs flag `powershell.exe -EncodedCommand` as a suspicious execution pattern.
- Operators cannot inspect what the hook executes without external decoding (even though `guardrail doctor --codex-hooks` decodes it in diagnostic output).

### 3. OpenCode Degraded-Allow Notice Truncation & Latency Friction

Under ADR-0022, direct human communication and task-tracking tools (`question`, `todowrite`) allow locally in degraded mode when the Engine cannot be spawned within `DEGRADED_PROBE_TIMEOUT_MS` (5000 ms).
- On Windows, NTFS `CreateProcess` overhead and Windows Defender real-time binary scanning intermittently push cold spawns past 5 seconds (~5.1–5.5s).
- Normal tools (`bash`, `read`, `edit`) use `SPAWN_BASE_TIMEOUT_MS` (15000 ms) with 2 retries, completing reliably under Defender scans. But `todowrite` and `question` are killed at exactly 5000 ms (`ETIMEDOUT`).
- When degraded allow triggers, the notice emitted to `stderr` and returned as `reason` is 105 characters:
  ```text
  [guardrail: engine unreachable; degraded allow for <tool> — enforcement is offline for this call]
  ```
- OpenCode's terminal status/alert line truncates this string at ~80 columns, cutting it off mid-word (`...degraded allow for todowrite - enforcement is offline for th`). This alarms the operator, reading as an unhandled exception or crash rather than an intentional non-fatal fallback.

---

## Decision

### Part 1: MSYS / Git Bash Drive Mount Resolver (Pure Lexical + Host `os.Stat`)

Introduce a fast, deterministic, in-process drive mapping seam in `internal/engine`:

#### 1a. Lexical drive translation

```go
// posixDriveToWin32 translates an MSYS2/Git-Bash-style POSIX drive path
// (e.g. "/c", "/c/", "/c/Users/...") into a Win32 path ("C:\", "C:\Users\...").
// It returns ("", false) if p does not match the single-letter drive pattern.
func posixDriveToWin32(p string) (string, bool)
```

- **Pattern:** `^/([a-zA-Z])(?:/(.*))?$` $\to$ `${1}:\$2`.
- **Case preservation:** Drive letter is canonicalized to uppercase (`C:`).
- **Exactness:** Only single-letter drive prefixes match. Non-drive POSIX root paths (`/etc`, `/usr`, `/dev`, `/bin`, `/tmp`) return `false`.

#### 1b. Host probing integration (`probe_windows.go` vs `probe_unix.go`)

On Unix, `hostProbePath` returns the path unchanged and `canProbe=true`.

On Windows, `hostProbePath(p string) (string, bool)`:
1. If `filepath.IsAbs(p)` (e.g. `C:\...`, `\\server\share`): returns `(filepath.Clean(p), true)`.
2. If `winPath, ok := posixDriveToWin32(p); ok`: returns `(filepath.Clean(winPath), true)`.
3. Otherwise (e.g. `/etc`, `/usr/bin`): returns `("", false)`.

`cdDirectoryState(candidate string)` uses `hostProbePath`:
- If `canProbe == false`: returns `cdDirectoryUnknown` (fail-closed, preserving the ADR-0023 fix for `/etc`).
- If `canProbe == true`: probes the host filesystem via `os.Stat(hostPath)`. If the target exists and is a directory, it returns `cdDirectoryAccessible`.

#### 1c. Containment resolution

In `resolvePath(p, cwd)` and `authorizedPath`:
- When running on Windows, if `cwd` or `p` is an MSYS drive path (`/c/...`), it is normalized to its Win32 drive equivalent before lexical and physical ancestor resolution against `RepoRoot` and `SafeRoots`.
- This ensures in-repo operations under Git Bash resolve within `tc.RepoRoot` rather than misaligning as `C:\c\...`.

#### 1d. Non-goals (explicit)
- **No `fstab` parsing**: We do not parse MSYS2/Cygwin mount tables or `/etc/fstab`. Custom non-drive mounts (e.g. `/my-mount/`) remain unmapped and fail closed.
- **No `cygpath` subprocess**: The engine remains a pure in-process function; no subprocesses are spawned during tool-call evaluation.

---

### Part 2: Owned Inspectable Wrapper Files for Codex Windows Hooks

Replace inline `-EncodedCommand` payloads with an owned, transparent batch wrapper script.

#### 2a. Wrapper script generation

When generating or syncing Codex configuration on Windows (`guardrail plane enable codex` or `guardrail sync`):
1. Write an inspectable wrapper script:
   - **Path:** `%LOCALAPPDATA%\guardrail\hooks\codex-hook.cmd`
   - **Content:**
     ```cmd
     @echo off
     @rem Generated by Guardrail - DO NOT EDIT (ADR-0004)
     "%~dp0\..\..\bin\guardrail.exe" hook codex %*
     if errorlevel 1 exit /b %errorlevel%
     ```
   - If the installed binary path is known and absolute, bake the absolute path with appropriate quoting:
     ```cmd
     @echo off
     @rem Generated by Guardrail - DO NOT EDIT (ADR-0004)
     "C:\Users\...\AppData\Local\guardrail\bin\guardrail.exe" hook codex %*
     if errorlevel 1 exit /b %errorlevel%
     ```

2. Set standard private filesystem permissions (`0o700` directory, `0o600` / non-world-writable ACL on Windows).

#### 2b. Hook command format in `.codex/hooks.json`

```json
{
  "type": "command",
  "command": "'/usr/local/bin/guardrail' hook codex || { ... exit 2; }",
  "commandWindows": "\"%LOCALAPPDATA%\\guardrail\\hooks\\codex-hook.cmd\" || (echo guardrail: evaluator unavailable or blocked; continue independent work. 1>&2 & exit /b 2)",
  "timeout": 10
}
```

- Fully readable and inspectable. No Base64 encoding.
- Exit code mapping (failure $\to$ exit 2) is preserved.

#### 2c. Backward compatibility & Doctor diagnostics

`cmd/guardrail/doctor_codex_hooks.go`:
- Retains Base64 decoding fallback so legacy or manually configured `-EncodedCommand` hooks continue to be recognized and diagnosed.
- Adds verification for the owned wrapper script: confirms path existence, owner ACL, and ADR-0004 header.

---

### Part 3: OpenCode Windows Spawn Timeout Parity & Alert Cleanliness

#### 3a. Windows spawn timeout parity for degraded tools
In `internal/genconfig/opencode_plugin.js`:
- Currently, `DEGRADED_PROBE_TIMEOUT_MS` is hardcoded to 5000 ms with zero retries, while normal tools (`bash`, `read`, `edit`) receive 15000 ms (`SPAWN_BASE_TIMEOUT_MS`) with 2 retries.
- On Windows, cold process creation and Windows Defender real-time binary scanning take ~5.1–5.5s, routinely exceeding 5000 ms and prematurely triggering degraded allow on `todowrite` and `question`.
- **Fix:** Set `DEGRADED_PROBE_TIMEOUT_MS` on Windows to parity with `SPAWN_BASE_TIMEOUT_MS` (15000 ms). This gives Defender scans the necessary room to complete, returning clean `allow` without tripping degraded mode.

#### 3b. Degraded allow alert suppression
- If degraded allow does trip as an emergency fallback, avoid polluting the operator's prompt input box with an alarming warning banner.
- Log the event quietly to `plugin-failures.log` and buffer the degraded audit report, but return an unobtrusive reason so OpenCode does not pin a truncated error banner over the prompt typing box.
- Long-term persistent socket/pipe daemon transport is tracked in existing backlog issue #99 (eliminating `spawnSync` and Defender process scanning entirely).

---

## Consequences

### Positive
- **Git Bash usability**: Legitimate in-repo commands executed under Git Bash with `/c/...` paths no longer trigger conservative `P3.unresolved` asks or path mismatches.
- **Security maintained**: Non-drive POSIX targets (`/etc`, `/usr`, `/bin`) remain strictly unmapped and fail closed as `cdDirectoryUnknown`.
- **Zero performance impact**: In-process string translation; no subprocess execution.
- **Trust-review transparency**: Codex hooks in `hooks.json` are clear, inspectable wrapper invocations rather than opaque Base64 `-EncodedCommand` strings.
- **Audit hygiene**: Windows security event logs show transparent execution of `codex-hook.cmd` rather than suspicious PowerShell `-EncodedCommand` invocations.
- **Operator UX clarity**: `todowrite` and `question` no longer prematurely time out under Defender on Windows; no alarming truncated banner is pinned over the prompt box.

### Negative / Trade-offs
- Custom MSYS2 mount aliases (other than standard drive letters) are not resolved. This is an explicit, safe design boundary.
- Enabling Codex on Windows creates one wrapper file in `%LOCALAPPDATA%\guardrail\hooks\`.

---

## Files Touched

| Area | File | Change |
|------|------|--------|
| **Engine** | `internal/engine/probe_windows.go` | Add `posixDriveToWin32` and `hostProbePath` supporting `/[a-zA-Z]/...` |
| **Engine** | `internal/engine/probe_unix.go` | `hostProbePath` identity implementation |
| **Engine** | `internal/engine/probe_test.go` | Test drive translation, non-drive rejection, and host path probing |
| **Engine** | `internal/engine/tokenize.go` | Use `hostProbePath` in `cdDirectoryState` |
| **Engine** | `internal/engine/rules_bash.go` | Normalize MSYS drive paths in `resolvePath` on Windows |
| **Engine** | `internal/engine/rules_bash_test.go` | Add Git Bash in-repo `cd /c/...` allow tests and verify `/etc` stays non-allow |
| **Genconfig** | `internal/genconfig/codex.go` | Generate `codex-hook.cmd` wrapper and update `commandWindows` |
| **Genconfig** | `internal/genconfig/codex_test.go` | Assert wrapper script contents and updated `hooks.json` shape |
| **Genconfig** | `internal/genconfig/opencode_plugin.js` | 15s Windows probe timeout and quiet degraded reason |
| **Genconfig** | `internal/genconfig/opencode_degraded_test.go` | Assert updated degraded timeout and clean reason format |
| **Doctor** | `cmd/guardrail/doctor_codex_hooks.go` | Verify owned wrapper file; preserve Base64 backward compatibility |

---

## TDD Shape (After Operator Sign-off)

1. **Unit tests (Drive mapping)**:
   - `TestPosixDriveToWin32`: verify `/c` $\to$ `C:\`, `/c/repo` $\to$ `C:\repo`, `/C/repo` $\to$ `C:\repo`.
   - Verify non-drives reject: `/etc`, `/usr/bin`, `/dev/null`, `/c1`, `/` $\to$ `("", false)`.
2. **Engine TDD (RED $\to$ GREEN)**:
   - RED on Windows: `cd /c/... && ls` for in-repo path returns `cdDirectoryUnknown` / ask.
   - Apply engine seam: GREEN on Windows for in-repo Git Bash paths.
   - Verify safety: `cd /etc && rm -rf .` remains non-allow on Windows.
3. **Genconfig / Doctor TDD (Codex wrapper & OpenCode UX)**:
   - RED: assert `CodexConfig` generates wrapper command without `-EncodedCommand`.
   - RED: assert OpenCode plugin uses parity timeout (15000 ms) on Windows.
   - Apply `genconfig` changes: GREEN.
   - Verify `doctor --codex-hooks` verifies wrapper file and preserves legacy decode.
