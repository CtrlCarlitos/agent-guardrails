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

No unresolved concerns.
