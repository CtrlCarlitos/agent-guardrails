# Task 5 Report: Authenticator Management, Audit, And Deployment Gates

## Delivered

- Added operator enrollment, management, recovery, WebAuthn completion
  attribution, Doctor state, documentation, and a raw-socket egress regression.
- Added `Store.ClearForRecovery` as a dedicated fail-closed operation. It
  validates and syncs deletion, then clears in-memory ceremonies and grants.
- Recovery requires `RESET`, writes an audit event, and disables approvals.
- Completion records retain only `transport: "webauthn"` and a stable credential
  fingerprint; raw WebAuthn material is neither audited nor persisted.

## TDD Evidence

1. Recovery-store and Doctor status tests failed before their APIs existed.
2. Operator terminal/confirmation tests failed before `cmdOperatorInput`.
3. Audit attribution assertions failed before the request and audit fields.

## Verification

Passed:

```text
/usr/local/go/bin/go test ./cmd/guardrail ./test/adversarial -run 'Test(InitialEnrollment|CredentialManagement|AdversarialSocketApproval|OperatorCommands|RecoverReset)' -count=1
/usr/local/go/bin/go test ./test -count=1
/usr/local/go/bin/go test ./test/adversarial -count=1
make check
/usr/local/go/bin/go test ./... -count=1
/usr/local/go/bin/go vet ./...
GOOS=windows GOARCH=amd64 /usr/local/go/bin/go build -o /tmp/guardrail-windows-test.exe ./cmd/guardrail
```

## Manual Smoke Test

Not run: successful enrollment and approval require a physical FIDO2 key or
platform passkey on each supported browser/platform pair. The procedure is in
`docs/operator-approvals.md`.

## Fix Round 1

- Initial registration now records whether a ceremony is initial enrollment.
  After WebAuthn verification, it acquires a private exclusive creation lock,
  rereads the credential store while holding that lock, and atomically persists
  the first public credential only when the store remains empty. A stale second
  ceremony cannot replace the first enrollment.
- Recovery now writes a durable `requested` audit event before credential
  removal and a `completed` event after. Failure to write the request event
  leaves the credential store unchanged.
- `add-authenticator` rejects an unenrolled store before it can start a browser
  ceremony. `remove-authenticator` rejects the final credential before browser
  launch; its underlying removal invariant remains in force after assertion.
- Doctor's status formatting is factored into a platform predicate, with direct
  Windows fail-closed coverage.

### Fix-Round TDD Evidence

The focused RED command failed with missing command test seams and status
predicate, no initial-registration persistence, and two successful stale
registration ceremonies:

```text
/usr/local/go/bin/go test ./internal/operatorauth ./cmd/guardrail -run 'Test(StaleInitialRegistration|RegistrationIsInitial|RecoveryDoesNot|RecoverReset|CredentialManagement|OperatorApprovalStatus)' -count=1
```

The same focused command passed after the implementation.

## Fix Round 2

- Replaced the persistent `O_EXCL` enrollment-lock sentinel with a private
  Unix advisory file lock. The lock file can persist safely after a process
  exits because the kernel releases the held lock with the owning descriptor.
  Privacy and regular-file validation still run before locking, and the lock
  remains held through the credential reread and atomic persistence.
- Added a build-tagged Windows implementation that returns a fail-closed error
  until the native Windows broker/locking work is implemented and validated.
- Added a subprocess-exit regression: a helper acquires the lock and exits
  without unlocking; the parent then acquires the same lock. The stale
  concurrent-ceremony enrollment regression remains covered.

### Fix-Round Verification

The new subprocess regression first failed against the persistent sentinel:

```text
lock remained held after holder exit: enrollment creation lock unavailable
```

It passes with the advisory lock. The full Task 5 gates also passed:

```text
/usr/local/go/bin/go test ./test -count=1
/usr/local/go/bin/go test ./test/adversarial -count=1
make check
/usr/local/go/bin/go test ./... -count=1
/usr/local/go/bin/go vet ./...
GOOS=windows GOARCH=amd64 /usr/local/go/bin/go build -o /tmp/guardrail-windows-test.exe ./cmd/guardrail
```
