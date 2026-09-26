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

The command prints a loopback `localhost` page URL and waits for WebAuthn user
verification. Open that URL yourself in the browser you trust; Guardrail never
launches a browser automatically. Guardrail supports platform passkeys,
password-manager passkeys, and physical FIDO2 security keys. A physical key is
the predictable choice when using one credential on several computers; synced
passkeys depend on browser and platform cross-device support.

For a remote SSH session, forward the printed port from a second local terminal,
then open the same URL locally. For example, if Guardrail prints port `39169`:

```
ssh -L 39169:127.0.0.1:39169 user@remote-host
```

The browser remains on your local machine while the SSH tunnel reaches the
remote loopback-only listener. No external service is involved.

`guardrail operator add-authenticator` requires a verified enrolled
authenticator before it opens a registration ceremony. `guardrail operator
remove-authenticator <fingerprint>` requires a verified enrolled authenticator
and refuses to remove the final credential. Credential fingerprints are
privacy-safe audit identifiers, not credential IDs or authenticator labels.

Until a credential is enrolled there is nothing to approve against, so the
first install arms the planes without a ceremony (ADR-0030): `guardrail
setup` and `guardrail plane enable` register the hooks and the permissions
floor, audit it with `transport: bootstrap`, and print this instruction. That
path can only tighten: `setup --state disabled`, `plane disable` and
`recover` stop with exit 3 until you enroll. `guardrail doctor` reports
`operator approvals: disabled (no authenticator enrolled; planes armed by
bootstrap; run guardrail operator enroll)` until then. A mediated session
cannot run any of these lifecycle commands itself (`P5.self-config`).

If every authenticator is lost, run `guardrail operator recover-reset` from a
trusted local terminal and type `RESET`. It removes only public credential
records, writes a recovery audit record, and disables approvals until a new
initial enrollment. Recovery is never available through the broker socket.

## Windows plus WSL, and why a phone cannot approve

A machine can run two guardrail instances: one on Windows and one inside WSL.
Each has its **own** credential store (`%LOCALAPPDATA%` on Windows,
`~/.local/state/guardrail` in WSL), and both ceremonies use the WebAuthn rpId
`localhost` on a loopback port. The approval page opens in the browser on the
Windows host, so a WSL approval is a Windows browser talking to a daemon inside
WSL. What that means for you:

- **A credential is only usable where it lives.** A passkey enrolled for the WSL
  instance can approve the WSL instance, from the browser or passkey provider that
  holds it. It cannot approve the Windows instance, and the reverse. The approval
  page names the instance that is asking (`Guardrail instance: WSL Ubuntu-24.04 on
  <host>`), so you can tell which one you are authenticating for.
- **A phone cannot approve with a passkey it does not hold.** The browser's system
  dialog may offer "iPhone, iPad or Android device" (a QR code). Scanning it links
  the phone, and the phone then looks for the exact credential the page asked for.
  Passkeys for `localhost` are created where you enrolled, so unless you enrolled
  this instance's authenticator on that phone, it answers "No passkeys available".
  Choose this device (Windows Hello or your passkey provider), not the phone.
- **Synced passkeys follow their provider, not the machine.** `guardrail doctor`
  prints `operator authenticators: N authenticators: X synced (backup-eligible, held
  by a passkey provider), Y device-bound; transports recorded for Z of N`. Synced
  means the passkey lives in a provider such as your browser's password manager and
  only offers itself where that provider is signed in. Device-bound means it lives
  in the machine's authenticator (Windows Hello, a security key).
- **Transports are recorded at enrollment.** An authenticator enrolled before this
  was fixed has no recorded transports, so the browser cannot narrow its prompt and
  offers every option. To get a narrower prompt, add a new authenticator with
  `guardrail operator add-authenticator` while one still works, or run
  `guardrail operator recover-reset` and enroll again, choosing this device when
  the system dialog asks.

If the approval page ends with "No enrolled authenticator responded", the
authenticator you used is not the one enrolled for this instance. Use the browser
and authenticator you enrolled it with. If that authenticator is gone, from this
instance's own terminal run `guardrail operator recover-reset`, then `guardrail
operator enroll`, and choose this device.

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

## Plane Lifecycle Actions

`guardrail plane enable|disable <plane>` (claude, opencode, or antigravity)
manages Guardrail's integration in that plane's global config through broker
approval: the command requires an interactive local terminal, submits a
`plane-enable`/`plane-disable` request bound to the exact plane, and applies
only after a WebAuthn approval. Enable regenerates and merges the Guardrail
floor (hooks, permissions, plugin); disable removes only Guardrail-owned
entries, preserving unrelated configuration. Both take `--all`, which acts on
detected supported planes, reports undetected planes, and always reports codex
as unsupported. `guardrail plane status` is read-only and needs no approval;
`guardrail doctor` prints the same per-plane state. The Guardrail binary stays
installed while planes are disabled, so re-enabling is local and verified.
Applied actions write `operator-action` audit records; a replayed approved
request completes idempotently without a second mutation.

## Recovery Repairs

`guardrail recover <repair>` (claude-settings, opencode-config,
antigravity-hooks) repairs Guardrail-protected machinery through the broker:
interactive terminal required, WebAuthn approval bound to the exact named
repair, audit-journaled, idempotent. Every repair takes a timestamped backup
first (`<path>.guardrail-recover-<utc>`); an unparseable file is reset and
the Guardrail integration re-registered (original bytes preserved in the
backup), while a parseable file is repaired in place with user configuration
untouched. Repairs are predefined code — an agent can never supply repair
content, only be told to ask the operator for a named repair.
