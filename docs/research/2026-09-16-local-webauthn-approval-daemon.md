# Local WebAuthn Approval Daemon: Feasibility and Constraints

Date: 2026-09-16

> Status note (2026-09-24): this is the feasibility research that preceded the
> WebAuthn operator-approval broker (`internal/operatorauth`, `internal/approval`;
> ADR-0021, ADR-0025). Recovered from the `feat/capability-boundary` worktree
> and committed as written. The "Go implementation boundary" section describes
> the repository as it was then; the project is now on Go 1.26 with
> `go-webauthn/webauthn` pinned in `go.mod`.

## Conclusion

A Go approval daemon that serves a browser UI on loopback and uses WebAuthn as
its local authorization ceremony is feasible on Linux, macOS, and WSL. It does
not need an identity provider, cloud RP, or password service: the daemon is the
Relying Party (RP), stores credential public keys locally, and verifies signed
assertions locally.

`http://localhost` is a potentially trustworthy origin, so it can be a secure
context without local TLS. Use one canonical origin and RP ID,
`http://localhost:<fixed-port>` and `localhost`, respectively; bind the HTTP
listener only to `127.0.0.1` and `::1`. Do not substitute a LAN address or a
machine name: the browser origin and RP ID must pass WebAuthn's RP-ID binding.
[MDN Secure Contexts](https://developer.mozilla.org/en-US/docs/Web/Security/Defenses/Secure_Contexts)
states that localhost, loopback addresses, and `.localhost` are potentially
trustworthy; WebAuthn itself is secure-context-only.
[MDN WebAuthn](https://developer.mozilla.org/en-US/docs/Web/API/Web_Authentication_API)

There are two materially different product promises:

| Promise | Feasibility | Constraint |
| --- | --- | --- |
| Local approval using the browser's platform authenticator or a directly attached security key | Supported design | No external provider is required. Support remains browser/OS/authenticator dependent. |
| Approve using a phone selected as an external/cross-device authenticator | Optional, not a guaranteed baseline | The browser and platform, not the daemon, implement authenticator discovery and transport. It may use platform passkey synchronization or browser-mediated hybrid/cross-device mechanisms; therefore it cannot promise operation without a third-party platform service, network access, Bluetooth, or a supported browser pairing flow. Test each target combination. |

The W3C specification explicitly presents the phone-as-external-authenticator
flow but qualifies feature availability as implementation-dependent.
[W3C WebAuthn, multi-device credentials](https://www.w3.org/TR/webauthn-3/#sctn-usecase-consumer-mdc)
Apple says an iPhone can sign in to websites on non-Apple devices, and that
iCloud Keychain syncs passkeys; Chrome documents Google Password Manager
synchronization across desktop, Android, Linux, Windows, and macOS.
[Apple Passkeys](https://developer.apple.com/passkeys/)
[Chrome, Google Password Manager synchronization](https://developer.chrome.com/blog/passkeys-gpm-desktop/)
These are useful interoperability paths, but they are external providers under
a strict reading of "no external provider."

## Recommended local design

The daemon owns one local RP and one local operator account. Its HTTP UI is
only a ceremony client; the security authority stays in the daemon.

1. Bind a fixed loopback port. Reject non-loopback `Host` values and requests
   whose `Origin` is not the canonical origin. Serve a top-level document, not
   an iframe. Do not add CORS access for other origins.
2. During enrollment, create a new credential with `rp.id = "localhost"`, a
   stable opaque user handle, `userVerification: "required"`, and an explicit
   approved algorithm list. Persist the returned credential record only after
   verification succeeds.
3. For every approval, construct a fresh, cryptographically random challenge
   and persist a short-lived, one-use pending-approval record before returning
   request options. Bind that record to the exact approval payload: action,
   normalized command/request digest, repository, plane, session/process
   identity, expiry, and a monotonically unique approval ID.
4. Authenticate with `allowCredentials` containing only enrolled credentials
   and `userVerification: "required"`. On receipt, verify the assertion,
   exact challenge, `type == "webauthn.get"`, expected origin, RP-ID hash,
   user-presence and user-verification flags, credential ID, and signature
   using the stored public key. Atomically consume the pending record before
   returning approval.
5. Make approval single-use and short lived. The WebAuthn signature proves an
   approval ceremony, not the semantics shown to the human, so the daemon must
   bind and display the exact action itself. A signed challenge not tied to the
   action would be replayable as authorization for a different action.

The specification requires RP verification of `clientDataJSON` type,
challenge, origin, RP-ID hash, user-presence and (when required)
user-verification flags, credential public key, and signature.
[W3C WebAuthn, verifying an assertion](https://www.w3.org/TR/webauthn-3/#sctn-verifying-assertion)
It further requires challenges to be generated randomly by the RP and used to
defend against replay.
[W3C WebAuthn, cryptographic challenges](https://www.w3.org/TR/webauthn-3/#sctn-cryptographic-challenges)

### User verification

Set `userVerification: "required"` for enrollment and approval. User presence
alone can be a touch; it does not establish that the operator passed a device
PIN, biometric, or equivalent user-verifying gesture. A device without a
suitable UV path must fail rather than downgrade approval. The CTAP definition
distinguishes user presence from built-in user verification and identifies
fingerprint and secure PIN UI as UV examples.
[FIDO CTAP 2.1, terminology](https://fidoalliance.org/specs/fido-v2.1-rd-20210309/fido-client-to-authenticator-protocol-v2.1-rd-20210309.html#sctn-terminology)

This validates a local authenticator ceremony, not the identity of a particular
human in a multi-user OS account. The daemon's security boundary is therefore
the local user account plus the authenticator's UV policy. A host already
controlled by the same OS user can invoke the loopback UI; WebAuthn should be
treated as a deliberate operator-presence gate, not as a sandbox against a
fully compromised local account.

## Credential, transport, and attestation policy

Store one row per credential, scoped by RP ID: credential ID, public key/COSE
key, sign counter, backup-eligible and backup-state flags, user-verification
initialization/flags, authenticator attachment, reported transports, AAGUID,
creation and last-used timestamps, friendly label, and status (active or
revoked). Store the opaque user handle once per local operator, not as a
human-readable identifier. Update mutable authenticator fields after every
successful assertion. Credential IDs are identifiers, not secrets; private
keys remain in authenticators.

The W3C credential record defines the credential ID, public key, sign count,
transports, UV and backup state as RP record data.
[W3C WebAuthn, credential record](https://www.w3.org/TR/webauthn-3/#credential-record)
The selected Go library documents the same durable state, requires RP-ID
partitioning, and says challenge/session data must be integrity protected and
anchored to the user agent.
[go-webauthn package documentation](https://pkg.go.dev/github.com/go-webauthn/webauthn/webauthn#hdr-Storage)

Reported transports (`usb`, `nfc`, `ble`, `internal`, and browser-supported
hybrid paths) are hints for browser UX and diagnostics, not an authorization
decision. CTAP defines USB, NFC, and BLE bindings for roaming authenticators.
[FIDO CTAP 2.1, transport-specific bindings](https://fidoalliance.org/specs/fido-v2.1-rd-20210309/fido-client-to-authenticator-protocol-v2.1-rd-20210309.html#transport-specific-bindings)

Request `attestation: "none"` initially. The approval use case needs a valid
credential and UV, not a hardware-model allowlist. Attestation can identify
authenticator provenance but has privacy and operational costs; only introduce
verified attestation and a FIDO Metadata Service dependency if policy requires
specific hardware. Google similarly recommends RPs not maintain authenticator
allowlists.
[Chrome WebAuthn guidance](https://developer.chrome.com/docs/identity/webauthn)
If a strict device-bound-key policy is required, design it as a separate policy
mode: synced credentials may not provide usable attestation. Microsoft
documents that synced passkeys do not support attestation.
[Microsoft passkey documentation](https://learn.microsoft.com/en-us/entra/identity/authentication/how-to-enable-passkey-fido2)

## Enrollment, removal, and recovery

- **First enrollment:** bootstrap only from a locally trusted installation or
  explicit local CLI ceremony. Do not leave an unauthenticated HTTP enrollment
  endpoint active after the first credential exists.
- **Add credential:** require a successful assertion from an existing active
  UV credential, then run a separate registration ceremony. Require the new
  credential to have UV as well. Keep the existing credential until the new
  one is confirmed.
- **Remove credential:** require fresh UV and forbid removing the final active
  credential except through a recovery ceremony. Mark revoked locally
  immediately; best-effort browser authenticator synchronization signals do
  not replace server-side revocation.
- **Recovery:** WebAuthn cannot recover an unexportable private key. Offer a
  second enrolled authenticator as the primary recovery path. If all
  credentials are lost, require a local, operator-controlled reset that stops
  the daemon, removes the local credential store, and produces an auditable
  re-enrollment event. Treat that reset as equivalent to taking ownership of
  the local approval boundary.

The W3C specification discusses credential loss and key mobility as RP security
considerations.
[W3C WebAuthn, credential loss and key mobility](https://www.w3.org/TR/webauthn-3/#sctn-credential-loss-key-mobility)
It also defines RP-to-client signals for unknown and accepted credentials, but
those signals are not a substitute for local credential revocation.
[W3C WebAuthn credential signals](https://www.w3.org/TR/webauthn-3/#sctn-signal-methods)

## Go implementation boundary

`github.com/go-webauthn/webauthn` is an appropriate server-side library
candidate. Its documented ceremony API creates options and `SessionData` with
`BeginRegistration`/`BeginLogin`, and verifies responses with
`FinishRegistration`/`FinishLogin`; it validates configured origin and RP
binding. Its `SessionData` must be persisted server-side between start and
finish and must not be client-modifiable.
[go-webauthn package overview](https://pkg.go.dev/github.com/go-webauthn/webauthn/webauthn)

The project currently uses Go 1.23 and has no WebAuthn dependency. The
library's repository says it is still major version zero and may make breaking
changes, so pin an exact version and exercise upgrade/credential-store
migration tests before adoption.
[go-webauthn repository](https://github.com/go-webauthn/webauthn)

The library verifies the WebAuthn ceremony, not the daemon's approval semantics.
The daemon must own pending-approval persistence, challenge-to-action binding,
one-time consumption, credential lifecycle, local file permissions, and audit
records.

## Platform constraints

| Host | Supported baseline | Constraint to test before support claim |
| --- | --- | --- |
| Linux | Browser running on the same Linux host, loopback daemon, platform authenticator if available or USB/NFC/BLE security key | Desktop browser and authenticator availability vary by distribution, browser, hardware, and sandboxing. Include a supported USB security key path. |
| macOS | Safari/Chrome browser, loopback daemon, Touch ID/passkey platform UI or security key | Keep `localhost` stable. Apple documents iCloud Keychain synchronization and iPhone use on non-Apple devices, but these are optional provider-mediated paths. |
| WSL | Browser on Windows accesses the daemon through `http://localhost:<port>`; Windows-host authenticator UI is expected to service the browser | Run the daemon only in WSL loopback and do not expose it to LAN. Microsoft documents that Windows applications can access a WSL networking application via localhost; remote IP use is LAN exposure. |

Microsoft's WSL networking documentation confirms that Windows applications,
including browsers, can access a WSL networking application through localhost,
while remote-address configurations are LAN connections and require wider
binding. [Microsoft WSL networking](https://learn.microsoft.com/en-us/windows/wsl/networking)

## Acceptance matrix

Before declaring support, manually test registration, approval, timeout,
cancellation, one-time challenge replay, delete/revoke, and recovery on:

1. Linux browser plus USB FIDO2 security key.
2. macOS Safari and Chrome plus platform authenticator, and one security key.
3. Windows browser accessing the WSL daemon over localhost plus Windows Hello
   and one security key.
4. Each intended phone/browser cross-device combination, both with and without
   the phone's passkey sync provider available. Record whether it needs
   Bluetooth, network connectivity, browser sign-in, or a provider account.

Only add phone cross-device approval to the supported matrix after these tests.
It is not a capability the daemon can implement or force through WebAuthn
request options.

## Sources

1. W3C: [Web Authentication Level 3](https://www.w3.org/TR/webauthn-3/), especially [RP operations](https://www.w3.org/TR/webauthn-3/#sctn-rp-operations), [RP ID](https://www.w3.org/TR/webauthn-3/#relying-party-identifier), [security considerations](https://www.w3.org/TR/webauthn-3/#sctn-security-considerations-rp), and [credential record](https://www.w3.org/TR/webauthn-3/#credential-record).
2. MDN: [Secure contexts](https://developer.mozilla.org/en-US/docs/Web/Security/Defenses/Secure_Contexts) and [Web Authentication API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Authentication_API).
3. FIDO Alliance: [CTAP 2.1](https://fidoalliance.org/specs/fido-v2.1-rd-20210309/fido-client-to-authenticator-protocol-v2.1-rd-20210309.html) and [FIDO2 overview](https://fidoalliance.org/specifications/).
4. go-webauthn: [package documentation](https://pkg.go.dev/github.com/go-webauthn/webauthn/webauthn) and [source repository](https://github.com/go-webauthn/webauthn).
5. Apple: [Passkeys overview](https://developer.apple.com/passkeys/).
6. Google: [Chrome WebAuthn guidance](https://developer.chrome.com/docs/identity/webauthn) and [Google Password Manager passkey synchronization](https://developer.chrome.com/blog/passkeys-gpm-desktop/).
7. Microsoft: [WSL networking](https://learn.microsoft.com/en-us/windows/wsl/networking) and [passkey (FIDO2) documentation](https://learn.microsoft.com/en-us/entra/identity/authentication/how-to-enable-passkey-fido2).
