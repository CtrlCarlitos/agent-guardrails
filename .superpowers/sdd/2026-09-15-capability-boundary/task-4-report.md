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
