# WebAuthn Operator Approval Design

**Date:** 2026-09-16
**Status:** Approved for planning

## Purpose

Replace the same-user approval broker's unsafe IPC and TTY completion paths
with a local WebAuthn ceremony. A coding plane may request an operator action,
but only an enrolled human authenticator may authorize its execution.

This is not an OS sandbox. It prevents routine self-approval in a correctly
deployed, fully intercepted plane; it cannot defend against an agent that gains
an unguarded same-user OS-level bypass or modifies the enforcement deployment.

## Scope

The first implementation supports the existing Unix/WSL and macOS broker.
Windows operator actions remain fail-closed until its native broker transport is
implemented and validated on Windows.

Supported authenticators use the vendor-neutral WebAuthn/FIDO2 standard:
platform passkeys, password-manager passkeys, and physical FIDO2 security keys.
Guardrail depends on no external service, account, or private hosted verifier.

## Trust Model

There is no default approver. Operator actions fail closed until the operator
enrolls a first authenticator from a trusted local terminal before starting
coding agents. This initial enrollment is trust-on-first-use; it cannot
cryptographically distinguish a human from a same-UID agent, so it is an
operator deployment responsibility.

After initial enrollment, adding or removing an authenticator requires a valid
assertion from an enrolled authenticator. Losing every enrolled authenticator
requires an explicit local recovery reset that disables approvals until trusted
first enrollment is repeated.

Each machine stores protected public credential records only: credential ID,
public key, algorithm, and permitted transport metadata. It never stores an
authenticator private key, a shared OTP seed, browser approval token, or raw
assertion. Public records may be copied to another machine safely. A physical
security key offers predictable one-credential, many-computer operation;
synced passkeys may work across devices where their browser/platform supports
cross-device WebAuthn, but are optional convenience rather than a guarantee.

## Enrollment Operations

`guardrail operator enroll` performs the initial ceremony only when no
credential exists. It opens a loopback WebAuthn registration page and records
the verified public credential. It is never callable through the approval
broker and is not invoked automatically by installation.

`guardrail operator add-authenticator` and
`guardrail operator remove-authenticator` create a pending, authenticator-gated
management request. The active credential list must never become empty through
removal. `guardrail operator recover-reset` clears local public credential
records and disables all operator actions; it is intentionally a documented
local recovery procedure, not an agent-accessible broker operation.

The dotfiles package will guide the operator through initial enrollment after
this capability ships. It must not trigger enrollment or register credentials
automatically.

## Approval Flow

1. A guarded action creates a pending canonical request with request ID,
   action, repository, scope, exact host when applicable, issued time, and
   expiry.
2. The daemon constructs a single-use WebAuthn challenge binding a digest of
   every authorization-relevant request field. The page is served only from a
   loopback origin using the `localhost` relying-party identity.
3. The browser asks the enrolled authenticator for user verification. The
   authenticator requires its own biometric, PIN, or physical touch.
4. The daemon verifies origin, relying-party ID, challenge, credential ID,
   signature, user-verification flag, request digest, expiry, and single-use
   state. It then executes exactly the stored canonical action and records a
   privacy-safe credential fingerprint and transport in the completion audit.
5. Every verification failure, browser/authenticator failure, expiry, replay,
   or state mismatch denies the action and leaves no partial mutation.

Browser automation may open the page but cannot create a valid authenticator
assertion without the operator's physical/biometric interaction.

## IPC Boundary

The broker's Unix socket accepts request submission and non-sensitive status
only. It must not offer approve, deny, registration, token, approval URL, raw
request details, or any operation that performs a persistent mutation.

The TTY approval command is removed. A terminal/PTY and Unix peer credentials
cannot distinguish a same-UID human from an agent process. The local browser
WebAuthn ceremony is the sole completion path.

## Request Presentation And Audit

The browser page prominently presents the canonical action, repository path,
scope, exact egress host, request ID prefix, and expiry before invoking the
authenticator. It must not render agent-controlled strings as HTML.

Audit records retain the request and completion events and add only a stable,
privacy-safe credential fingerprint plus `webauthn` transport attribution. Raw
credential IDs, challenges, assertions, tokens, URLs, and authenticator labels
are never logged.

## Security Properties

- An agent that knows a request ID cannot approve, deny, or retrieve a browser
  capability over IPC.
- An assertion authorizes one exact, unexpired request once; it cannot authorize
  another request, another repository, another host, or a replay.
- No private authentication material exists on a Guardrail host for an agent to
  copy or generate OTPs from.
- Persistent mutation remains broker-executed and crash-safe under the existing
  journaled allowance transaction rules.

## Limits

This design does not prevent a same-user agent with an unguarded OS capability
from modifying Guardrail's binary/configuration, starting an unguarded plane,
killing the daemon, exploiting an adapter bug, or misleading an operator into
approving a request. Guardrail must continue protecting its deployment files and
plane integrations, and the approval page must show exact canonical intent.

## Verification

Automated tests must cover registration, assertion verification, user
verification required, wrong origin/RP ID/challenge/digest, expiry, replay,
credential add/remove/recovery invariants, socket denial of every completion
operation, redacted audit records, and no partial mutation on failures.

End-to-end browser tests use `agent-browser` against the loopback page for
presentation and failure paths. A physical authenticator is required for a
manual smoke test of successful registration and approval on each supported
browser/platform pair.

## Sources

- W3C, [Web Authentication: An API for accessing Public Key Credentials](https://www.w3.org/TR/webauthn-3/)
- FIDO Alliance, [WebAuthn](https://fidoalliance.org/specifications/)
