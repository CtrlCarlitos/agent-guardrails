# ADR-0021: Windows approval broker — named-pipe transport, browser WebAuthn, and the seams to lift

## Status

Proposed (design only; implementation lands seam by seam, each validated on CI's `windows-latest`)

## Context

Windows is a first-class **release** artifact (`guardrail update` fetches `…-windows-amd64.exe`, CI builds and vets on `windows-latest`) but a fail-closed **operator** platform. Every path that needs the approval broker is gated:

| Gate | Where | Today |
|---|---|---|
| Private listener / dialer | `internal/approval/daemon_windows.go` | `persistentApprovalError()` — no daemon |
| Enrollment lock | `internal/operatorauth/lock_windows.go` | error |
| Allowance owner check | `cmd/guardrail/allowance_transaction_windows.go` | error |
| Private-file checks (`0o077` mode bits) | `operatorauth.validateRegularFile`, allowance journal | POSIX semantics; Go synthesises `0666`/`0777` on Windows, so a literal port would reject or accept everything |
| Operator CLI, plane lifecycle, recover, action audit | `operator.go:28`, `plane.go:228`, `recover.go:89`, `action_audit.go:26` | `unavailable on Windows` |
| doctor | `operatorApprovalStatus(windows=true)` | `operator approvals: disabled (Windows fail-closed)` |

What the Unix design actually relies on, so the Windows design preserves it rather than imitates it:

1. **Peer authenticity by the OS, not by a secret.** The broker socket lives in a `0700` directory; only the owning user can connect. No token is minted, stored, or rotated.
2. **A daemon that cannot outlive a release.** Spawned on demand (`SubmitOnDemand` re-execs `approvals daemon`), shut down by every `update`; a stale socket is detected by dialing and removed.
3. **One approval ceremony, in the browser.** The daemon opens `http://localhost:<port>` (loopback TCP, `127.0.0.1:0`); the page runs WebAuthn with `RPID: localhost`, the exact port origin, and `UserVerification: required` against the operator's enrolled credential (`internal/operatorauth/webauthn.go`). The CLI never talks to an authenticator.
4. **Exclusive locks** for enrollment (`flock`) and allowance journals (`gofrs/flock`, already cross-platform).
5. **Operator-terminal semantics** (`term.IsTerminal` on stdin) for `night`, `plane`, `egress`, `operator`.

Points 3 and 5 already work on Windows unchanged: `golang.org/x/term` supports Windows consoles (ConPTY, Windows Terminal), and every mainstream browser on Windows 10+ exposes the **Windows Hello platform authenticator** to WebAuthn on a `localhost` origin, which is a secure context. Points 1, 2 and 4 are what the design below provides.

## Decision

### 1. Transport: a per-user named pipe, not loopback TCP

`daemon_windows.go` implements the existing seams — `listenPrivate(string) (net.Listener, error)` and `dialPrivate(string) (net.Conn, error)` — over a **named pipe** using `github.com/Microsoft/go-winio` (`winio.ListenPipe`, `winio.DialPipe`). `daemon.go`, the JSON-per-connection protocol (`send`, `daemonMessage`/`daemonReply`), the broker, and the browser transport are untouched.

- **Name**: `\\.\pipe\guardrail-broker-<sha256(stateRoot)[:16]>` where `stateRoot` is the `LOCALAPPDATA`-based state directory the Unix path already hashes for its long-path fallback. `DefaultSocketPath()` returns this name on Windows; the value is opaque to callers already (they pass it back to `listenPrivate`/`dialPrivate`).
- **Access control**: the pipe is created with a security descriptor granting `GENERIC_ALL` to the **current user's SID only** (`winio.PipeConfig{SecurityDescriptor: "D:P(A;;GA;;;<SID>)"}`; SID from `windows.OpenCurrentProcessToken().GetTokenUser()`). This is the named-pipe equivalent of the `0700` socket directory: the OS authenticates the peer. Other users, including other interactive sessions on the same machine, get `ERROR_ACCESS_DENIED`.
- **Liveness**: "already running" is `DialPipe` succeeding within one second; "not running" is `ERROR_FILE_NOT_FOUND`. Named pipes vanish with their process, so the stale-socket removal branch of the Unix listener has no Windows counterpart — a simplification, not a gap.
- **Message framing** stays one JSON request and one JSON reply per connection; `winio` pipes are byte streams, so `json.Encoder`/`Decoder` over the `net.Conn` work unchanged. Pipe mode is `PIPE_TYPE_BYTE` (winio default).

**Rejected — loopback TCP with a token file.** TCP has no peer identity on Windows: any local process of any user can connect, so a bearer token in the state directory would have to stand in for the OS — a new secret to mint, protect and rotate, and a Windows Defender Firewall prompt on first listen. The named pipe gives the property the Unix socket already has, with no new secret.

**Rejected — a Windows service.** Requires elevation and a lifecycle Guardrail does not otherwise have (ADR-0002: one user-level binary; the daemon is spawned on demand and dies with `update`).

### 2. Locks: `LockFileEx`

`lock_windows.go` implements `acquireEnrollmentLock(dir)` with `windows.LockFileEx(handle, LOCKFILE_EXCLUSIVE_LOCK, …)` on `.enrollment.lock`, released by `UnlockFileEx` and `CloseHandle`. Same signature, same exclusivity contract as `flock(LOCK_EX)`. The allowance journal lock (`gofrs/flock`) already uses `LockFileEx` on Windows; nothing to do there.

### 3. Private files: owner SID + DACL, not mode bits

The `0o077` checks encode "only this user can read or write this file". On Windows that is an ACL question, answered in two places behind existing seams:

- **Creation**: `writePrivateFile` and the credential-store writers pass `SecurityAttributes` with the same owner-only SDDL as the pipe (`D:P(A;;FA;;;<SID>)`), instead of relying on `0o600`.
- **Validation**: `validateRegularFile` (operatorauth) and `validateAllowanceOwner` (cmd) get `_windows.go` counterparts that read the file's security info (`windows.GetNamedSecurityInfo` with `OWNER_SECURITY_INFORMATION|DACL_SECURITY_INFORMATION`) and require: owner SID == current user SID; no ACE grants access to `Everyone`, `Users`, or `Authenticated Users`; regular file, not a reparse point.

`Administrators` and `SYSTEM` retain access, as `root` does on Unix. That is the accepted equivalence, stated here so nobody expects more.

### 4. State roots

Unchanged: audit, sessions, allowance journals and the coverage cache already resolve to `%LOCALAPPDATA%\guardrail\…`; operator config to `%APPDATA%\guardrail\…`. The pipe name is derived from the `LOCALAPPDATA` state root so two Windows user profiles never share a broker.

### 5. Approval ceremony: unchanged by design

The browser page, the `http://localhost:<port>` origin, `RPID: localhost`, `UserVerification: required` and the `AssertionStore` all stay exactly as on Unix. `openURL` is today `printOperatorURL` — it prints the approval URL for the operator to open (`approvals.go`), it does not launch a browser — and that stays platform-neutral. Windows Hello (PIN or biometric) satisfies UV once the operator opens the page in any mainstream browser. **Rejected — native `webauthn.dll`**: it would be a second ceremony code path to keep equivalent to the browser one, for no security gain; the browser path is the one every operator already enrolled through.

### 6. Lifting the gates, in order

Each step is one PR, each keeps the `GOOS == "windows"` fail-closed behaviour for everything after it, and each ships with tests that run on `windows-latest`:

| Step | Seam | CI test on `windows-latest` |
|---|---|---|
| a | `daemon_windows.go`: pipe `listenPrivate`/`dialPrivate`, pipe-name `DefaultSocketPath` | listen → dial → JSON echo round trip; second `listenPrivate` on a live pipe → "already running"; dial with no listener → not-running error; pipe security descriptor's owner and single ACE SID == current user (`GetSecurityInfo` on the pipe handle) |
| b | `lock_windows.go`: `LockFileEx` | two handles: second acquire blocks until first release (goroutine + timeout) |
| c | `validateRegularFile_windows.go`, `validateAllowanceOwner` (Windows), `SecurityAttributes` on creation | file we create passes; a file granted to `Everyone` (via `windows.SetNamedSecurityInfo` in the test) fails; a reparse point fails |
| d | remove the `GOOS` gates in `operator.go`, `action_audit.go`, `plane.go`, `recover.go`, `allowance_transaction.go:277`; `operatorApprovalStatus` reports enrolment state on Windows; `doctor`/`selftest` unchanged | `go test ./internal/approval/... ./internal/operatorauth/... ./cmd/guardrail/ -run 'Approval|Operator|Plane|Recover'` on Windows |

CI change: keep the engine suite ubuntu-only (its POSIX-shell semantics are by design, see `ci.yml`), and add a Windows step that runs the packages above. No new runner, no secrets, no authenticator hardware — the WebAuthn verifier is already unit-tested with synthetic assertions, and the browser ceremony is exercised by the existing `browser_e2e_test.go` shape on both OSes.

### 7. Explicit non-goals

- No elevation, no service, no scheduled task.
- No TCP listener for the broker; loopback TCP remains only for the short-lived browser page, as on Unix.
- No native WebAuthn API.
- WSL is unchanged: it runs the Linux binary and the Unix design.

## Consequences

- Windows operators get the same approval model as Unix — OS-authenticated peer, browser ceremony, on-demand daemon that dies with `update` — with one new dependency (`github.com/Microsoft/go-winio`, MIT, Microsoft-maintained) and no new secret material.
- Until step (d) lands, Windows stays fail-closed exactly as today; steps (a)–(c) are inert on Windows behind their gates and no-ops on Unix.
- The private-file invariant on Windows is "owner-only DACL", documented as equivalent to `0600`/`0700` with the `Administrators`/`root` caveat.
- `docs/OPERATIONS.md` gains a Windows column when (d) lands: pipe name under `\\.\pipe\`, state under `%LOCALAPPDATA%\guardrail`, operator config under `%APPDATA%\guardrail`.
