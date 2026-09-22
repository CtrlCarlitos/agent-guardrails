# ADR-0025 — Persistent daemon/broker for Windows: sub-millisecond hook transport and process lifecycle

**Date:** 2026-09-21  
**Status:** Accepted (controller review, 2026-09-21)  
**Issues:** #99 (Daemon mode for hooks), #132 (Windows spawn latency / ETIMEDOUT)  
**Author:** AGY (Antigravity)

---

## Context

### 1. The Per-Call Spawn Bottleneck on Windows (#132, #99)

Every plane adapter (OpenCode plugin, Claude command hook, Codex wrapper) mediates tool calls by invoking the `guardrail` engine binary.

- On Linux, `fork` + `exec` is fast (~2–5 ms).
- On Windows, process creation (`CreateProcessW`) involves NTFS path traversal, PE image loading, and runtime initialization (~30–100 ms on warm idle).
- Crucially, Windows Defender real-time protection (`MsMpEng.exe`) intercepts `CreateProcess` to scan the newly spawned binary image. Under sustained agent workloads (50–100 tool calls in rapid succession) or transient system load, per-call spawn latency spikes to **5,000 ms – 6,500 ms**.
- This creates severe agent experience and reliability failures:
  - In OpenCode, timeouts (`ETIMEDOUT`) trip the ADR-0022 degraded-mode valve on communication tools (`todowrite`, `question`) and fail closed on mutations.
  - In Claude and Codex, hook timeouts cause aborted command streams or session freezes.
  - Operators observe an annoying UX where local policy evaluation feels sluggish despite the core engine logic taking <1 ms.

While ADR-0024 increased timeout parity to 15s to prevent false degraded allows, per-call process creation remains the primary performance bottleneck on Windows.

### 2. Prior Art in ADR-0021

ADR-0021 established the Windows named-pipe transport for the **approval broker** (`internal/approval/daemon_windows.go`):
- Uses `github.com/Microsoft/go-winio` (`winio.ListenPipe`, `winio.DialPipe`).
- Derives a per-user pipe path: `\\.\pipe\guardrail-<UserSID>`.
- Restricts access via an owner-only Security Descriptor Definition Language (SDDL) DACL: `D:P(A;;GA;;;<UserSID>)`.
- Proved that named-pipe round-trip communication in Go and Node.js takes **< 1–2 ms** with zero `CreateProcess` overhead and zero Defender binary scan interception.

---

## Decision

Extend the resident named-pipe daemon to evaluate engine policy directly over IPC, transforming plane adapters into thin, ultra-low-latency clients.

### 1. Architectural Options & Evaluation

We evaluated three design architectures for Windows hook mediation:

| Option | Architecture | Latency | Defender Scan Overhead | Privilege & Complexity | Verdict |
|---|---|---|---|---|---|
| **1. Resident Named-Pipe Daemon (Recommended)** | Single background process listening on a per-user named pipe (`\\.\pipe\guardrail-engine-<UserSID>`). Spawned on demand; idle timeout. | **< 1–2 ms** | **Zero on steady state** (binary scanned only once on initial daemon launch). | User-scoped; runs entirely in user profile; uses proven ADR-0021 transport. | **Accepted** |
| **2. Warm Process Pool** | Adapter or supervisor maintains 1–2 idle standby `guardrail.exe` processes with open stdio pipes. | 5–15 ms | High (every replenishment spawns a process and trips Defender). | High process coordination complexity; high memory footprint in Node.js / wrapper scripts. | **Rejected** |
| **3. Windows SCM Service** | Windows Service managed by the Service Control Manager (SCM) or Task Scheduler. | < 2 ms | Zero on steady state. | Requires Administrator privileges to register/install; runs as `SYSTEM` or service account, breaking per-user DACL and WebAuthn browser ceremonies. | **Rejected** |

### 2. Transport Specification: The Resident Engine Daemon

#### 2a. Pipe Identity, DACL, and Bidirectional Authentication

- **Pipe Path:** `\\.\pipe\guardrail-engine-<UserSID>`
- **Security Descriptor:** `D:P(A;;GA;;;<UserSID>)(A;;GA;;;SY)(A;;GA;;;BA)`
  - Grants Generic All (`GA`) exclusively to the current User SID, `SYSTEM`, and `Administrators` (mirroring `root` access on Unix).
  - Explicitly rejects `Everyone`, `Authenticated Users`, and network callers (`PIPE_REJECT_REMOTE_CLIENTS`).
- **Bidirectional Authentication (New Strong Standard):**
  1. **Server authenticates Client:** On connection accept, the daemon calls `GetNamedPipeClientProcessId` and inspects the client's token to verify that the client process belongs to the same Windows logon session and User SID.
  2. **Client authenticates Server:** Before sending sensitive tool payloads, the client verifies the daemon process's binary path and SHA-256 image hash against the authorized installed `guardrail.exe` image on disk. This prevents pipe squatting or rogue listeners.

#### 2b. Wire Protocol & Audit Provenance

1. Client connects to `\\.\pipe\guardrail-engine-<UserSID>`.
2. Client sends a one-line JSON envelope matching `engine.ToolCall` / plane contract:
   ```json
   {"plane":"opencode","event":"pre","tool":"read","cwd":"C:\\repo","arguments":{"filePath":"C:\\repo\\file.go"}}
   ```
3. Daemon evaluates the merged policy in-process (< 1 ms).
4. **Audit Provenance Tagging (Controller Review Note):**
   - When the daemon logs the evaluation to `%LOCALAPPDATA%\guardrail\audit.jsonl`, it records `transport: "named-pipe-daemon"` (distinct from `transport: "hook"` on cold-spawns).
   - This preserves the ADR-0020 evidence-gate semantics: auditing can strictly verify whether live mediation was performed via resident daemon IPC or cold CLI invocation.
5. Daemon streams back the decision JSON:
   ```json
   {"decision":"allow"}
   ```
6. Client closes the connection (or keeps alive for connection reuse within the same tool call).

#### 2c. Fallback Mechanism (Fail-Closed & Resilience)

If the named pipe cannot be dialed (daemon not running, busy, or starting):
1. **On-demand launch:** If absent, the client attempts to spawn `guardrail.exe daemon --socket` in the background (detached, non-blocking) and retries the pipe dial for 250 ms.
2. **Cold-spawn fallback:** If the pipe still fails to answer within 250 ms, the adapter falls back immediately to cold `spawnSync(GUARDRAIL_BIN, ["hook", plane])`. This guarantees zero regressions and preserves complete fail-closed enforcement even if daemon IPC fails.

---

### 3. The Never-Outlive-a-Release Contract

A long-running daemon holding open a pipe must never evaluate policy using stale rules, outdated binaries, or superseded code. We enforce this through four invariants:

#### 3a. Image Hash Verification on Connect
- When the daemon starts, it records its own executable's SHA-256 digest and file modification time (`info.ModTime()`).
- On every client connection, the daemon stat-checks its binary path on disk (`os.Stat(binaryPath)`).
- If the binary on disk has been replaced (e.g. by `guardrail update` or package manager), the daemon:
  1. Drains in-flight evaluations.
  2. Unlinks the pipe listener.
  3. Exits cleanly (`exit 0`).
  4. The next client connection triggers on-demand launch of the newly installed binary.

#### 3b. Coordinated Update & Teardown
- `guardrail update` and `guardrail daemon stop` send an explicit authenticated shutdown command (`{"action":"shutdown"}`) over the pipe before replacing the binary image on disk.
- If the daemon does not exit within 1,000 ms, the updater terminates the process using its known PID.

#### 3c. Idle Timeout
- The daemon tracks evaluation activity.
- If no tool call is received for **30 minutes** (`idleTimeout = 30 * time.Minute`), the daemon gracefully shuts down and unbinds the pipe. This prevents zombie processes from accumulating on developer workstations.

#### 3d. Crash & Orphan Recovery (Takeover Protocol)
- If a prior daemon crashed while holding the pipe name, `winio.ListenPipe` returns an error (`ERROR_ALREADY_EXISTS` or `ERROR_ACCESS_DENIED`).
- The listener dial-probes the existing pipe. If the pipe is dead/unresponsive, it re-binds using the standard Windows named pipe takeover protocol (`PIPE_ACCESS_DUPLEX`).

---

### 4. Memory, State & Policy Hot-Reload

1. **Isolation per Session:** In-memory tracking (`Trifecta`, rate limits, `session.State`) is strictly scoped by `SessionID`. Evaluating a tool call in session A cannot leak facts or variables into session B.
2. **Hot-Reload on Mtime Change:**
   - The daemon caches the parsed Base policy, Overlay (`guardrail.toml`), and Operator configuration (`%APPDATA%\guardrail\operator.toml`).
   - Before evaluating, the daemon checks the file timestamps (`mtime`).
   - If an operator edits `guardrail.toml` or grants a waiver, the daemon hot-reloads the policy immediately in memory without restarting the process.
   - This provides instantaneous policy updates with zero process downtime.
3. **No Elevation:** The daemon runs with the standard developer token (medium integrity level) and never requests or inherits administrative elevation.

---

## Consequences

### Positive
- **Dramatic latency reduction:** Tool evaluation latency on Windows drops from **~5,000 ms (under Defender) / ~50 ms (idle)** to **< 1.5 ms**.
- **No Defender friction:** Defender scans the binary once when launched; subsequent IPC calls bypass `CreateProcess` and filesystem binary interception entirely.
- **Flawless agent UX:** Eliminates timeouts, UI alert banners, and degraded fallback alerts in OpenCode, Claude, and Codex.
- **Resource amortization:** Overlay parsing, regex compilations, and base policy parsing are performed once and cached in memory across calls.
- **Tighter security boundary:** Bidirectional authentication (client verifies server hash; server verifies client logon session) sets a new security benchmark.
- **Clear audit provenance:** `transport: "named-pipe-daemon"` distinguishes daemon mediation from cold hook invocations for ADR-0020 evidence verification.
- **Seamless lifecycle:** Automatic image-hash verification guarantees the daemon never outlives an update.

### Negative / Trade-offs
- Adds a long-running user background process (~15–25 MB RAM idle).
- Requires named-pipe client dialing logic in the OpenCode plugin (`node:net`) and command-hook adapters.
- Cold first-call latency still takes ~500 ms while the daemon initializes.

---

## Implementation Seams & Phasing

1. **Seam 1 (`internal/daemon/listener_windows.go`, `internal/daemon/listener_unix.go`):**
   - Extract and generalize the pipe transport into an engine-serving RPC listener.
   - Implement `ImageHashCheck`, bidirectional process verification, takeover protocol, and 30-minute idle termination.
2. **Seam 2 (`cmd/guardrail/daemon.go`, `internal/audit`):**
   - Add `guardrail daemon [start|stop|status]` subcommands.
   - Wire `transport: "named-pipe-daemon"` into audit records.
   - Implement graceful drain and shutdown on update.
3. **Seam 3 (`internal/genconfig/opencode_plugin.js`):**
   - In OpenCode plugin, add `net.connect` to `\\.\pipe\guardrail-engine-<UserSID>`.
   - Stream serialized envelope, parse verdict, and fall back to `spawnSync` on connection error.
4. **Seam 4 (`cmd/guardrail/hook.go`):**
   - In command hooks (Claude, Codex), add pipe-dialing fast path before falling through to direct in-process evaluation.

---

## References

- **ADR-0021 §1:** Windows approval broker named-pipe transport (`internal/approval/daemon_windows.go`).
- **Issue #99:** [backlog] Daemon mode for hooks (amortize fork+exec).
- **Issue #132:** Windows pre-hook: ETIMEDOUT fail-closes on legitimate tool calls.
- **Issue #146:** Defender exclusion scoping and binary replacement safety.
- **ADR-0020:** Codex live-mediation evidence gate and transport verification.
