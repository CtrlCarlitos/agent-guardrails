# Operator Approvals

Guardrail completes persistent operator actions only after a local WebAuthn
ceremony. The browser page shows the canonical action, repository path, scope,
exact egress host when applicable, request ID prefix, and expiry. Verify those
fields before satisfying the authenticator prompt.

## Enrollment

Initial enrollment is explicit trust-on-first-use. Before launching coding
planes, from a trusted local terminal run:

```
guardrail operator enroll
```

This opens a loopback `localhost` page and requires WebAuthn user verification.
Guardrail supports platform passkeys, password-manager passkeys, and physical
FIDO2 security keys. A physical key is the predictable choice when using one
credential on several computers; synced passkeys depend on browser and platform
cross-device support.

`guardrail operator add-authenticator` requires a verified enrolled
authenticator before it opens a registration ceremony. `guardrail operator
remove-authenticator <fingerprint>` requires a verified enrolled authenticator
and refuses to remove the final credential. Credential fingerprints are
privacy-safe audit identifiers, not credential IDs or authenticator labels.

If every authenticator is lost, run `guardrail operator recover-reset` from a
trusted local terminal and type `RESET`. It removes only public credential
records, writes a recovery audit record, and disables approvals until a new
initial enrollment. Recovery is never available through the broker socket.

## Limits And Validation

Unix, WSL, and macOS use the local loopback ceremony. Windows operator actions
are fail-closed pending a native validated broker transport. Browser automation
can open the page but cannot satisfy a physical or biometric user-verification
prompt. Guardrail is not an OS sandbox: a same-user process with an unguarded
OS bypass can still modify its deployment or deceive an operator.

Perform a manual smoke test for every supported browser/platform pair: enroll a
physical FIDO2 key or platform passkey, submit one night-mode action and one
exact-host grant, check the displayed canonical fields, complete user
verification, confirm one WebAuthn-attributed audit completion per action, and
confirm replayed or expired pages fail. Dotfiles integration may later guide
this enrollment; it must never initiate enrollment automatically.
