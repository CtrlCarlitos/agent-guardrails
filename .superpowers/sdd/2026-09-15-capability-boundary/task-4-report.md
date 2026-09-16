# Task 4 Report

## Status

Implemented the trusted approval broker, loopback browser and TTY transports,
and broker-executed canonical night actions.

## Verification

`/usr/local/go/bin/go test ./...`

All packages, including `test/adversarial`, pass.

## Security Properties

- Broker records use the existing locked, hashed, atomic session store.
- Free-form session and reason values are persisted only as SHA-256 digests.
- Approval requests are expiring, bounded, exact-scope, and single-use.
- The browser binds only to `127.0.0.1` and requires an unguessable request token.
- Only exact `guardrail night off` and `guardrail night on --until HH:MM`
  commands reach the broker; all other self-configuration invocations retain
  the existing deny behavior.
- Approved night changes execute internally rather than replaying the guarded
  shell command.

## Concerns

## Fix Round 1

- Canonical broker actions now emit the structured `complete` verdict. Adapters
  block the originating native call and return pending action metadata instead
  of an Ask/force_ask retry path.
- Added adapter and adversarial coverage for the non-retry completion contract.
- Verification: `/usr/local/go/bin/go test ./...`.

## Remaining Concerns

- Persistent web-host grant/revoke actions and a retained browser lifecycle are
  not implemented by this round and require a follow-up before Task 4 can be
  considered fully complete against the expanded review scope.

## Fix Round 1 Blocker

Implementation is blocked before adding persistent web-host actions. The
binding design requires registered persistent host grant/revoke actions but
does not define their canonical agent-visible command grammar or a bound
parameter representation. The existing recognizer deliberately accepts only
the exact night commands. Inventing a host mutation syntax would expand the
agent-controlled self-configuration surface and violate the required
canonical-only, fail-closed boundary.

Required decision: specify the exact canonical request forms and parameters
for repository/global web-host grant and revoke, including how an agent may
request an Allow once choice without selecting a persistent scope.

## Fix Round 1 Browser Lifecycle Blocker

The canonical persistent-host grammar is now specified, but the required
browser lifecycle remains undefined by the current process architecture.
`cmdHook` creates a request then exits; the existing loopback server is an
in-process goroutine and is terminated with that hook process. A durable
browser transport therefore requires one of: a persistent broker daemon, a
parent process that owns the loopback server, or an explicitly specified
operator command that serves the request. Starting an unmanaged background
server would make action completion and crash recovery ambiguous, violating
the review requirement.

## Daemon Authentication Blocker

The revised plan requires an "authenticated user-level daemon" reached through
an "authenticated local socket", but it does not specify an authentication
proof or peer-credential validation protocol. Socket filesystem permissions
control who can connect but do not authenticate the peer. Unix peer credential
APIs are platform-specific and unavailable on Windows, while a random token
requires a specified secure bootstrap, storage, rotation, and client protocol.

Implementing either an unauthenticated socket or an invented cross-platform
authentication scheme would violate the explicit fail-closed requirement.
Required decision: define the daemon socket authentication protocol, including
platform support, token/credential source, permissions, validation, and daemon
restart behavior.

## Final Review Follow-up

- Preserved the canonical requested `repo` or `global` scope and host through
  hook submission and durable broker recovery for web-host actions.
- Browser-launch failure now closes only the failed transport and retains the
  pending request for a TTY client.
- Focused verification: `go test ./internal/approval ./cmd/guardrail`.

Remaining final-review items still require implementation: recoverable action
execution and idle accounting, atomic repository Overlay/Operator mutation,
safe live-versus-stale socket ownership, and separate mutation audit records.

## Completion

- Implemented the on-demand broker daemon over a mode-0700 Unix socket
  directory. Hooks submit requests to the daemon and return a completion
  verdict; the operator TTY is a daemon client.
- The daemon owns the loopback browser, passes its 256-bit single-use token
  only to the OS browser launcher, and never persists, audits, or returns it
  through the broker protocol. It exits after ten minutes without activity and
  pending requests keep it alive.
- Added exact canonical recognition and broker-executed repository/global
  persistent-host grant and revoke actions. Repository grants update both the
  Overlay and matching Operator authorization; global grants update only the
  Operator config. Replays, malformed actions, and scope changes deny.
- Verification: `/usr/local/go/bin/go test ./...`.

## Task 4 Finalization

- `guardrail approvals daemon` now dispatches before the operator-terminal
  check, allowing an on-demand hook re-exec to create the broker socket.
- The TTY approval command now looks up, approves, and denies only through
  the daemon socket; it cannot bypass an unavailable daemon via the session
  store.
- Unix, WSL, and macOS retain the private mode-0700 socket directory. Long
  state-root paths use a deterministic short private socket path to remain
  within Unix-domain socket limits.
- Windows persistent/operator approvals fail closed with: `persistent
  approvals are unavailable on Windows; use Unix, WSL, or macOS`. Windows is
  not supported for persistent approvals.
- Added a production-binary adversarial test that starts `approvals daemon`,
  verifies private socket creation, and submits a canonical night request.
- Verification: `/usr/local/go/bin/go test ./...`; `GOOS=windows
  GOARCH=amd64 /usr/local/go/bin/go build -o /tmp/guardrail-windows-test.exe
  ./cmd/guardrail`.
