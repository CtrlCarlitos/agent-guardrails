# Operator Approvals

Guardrail completes persistent operator actions (`setup`, `plane
enable|disable`, `recover`, `web-research on|off`, `night on|off`, `egress
grant|revoke`) only after the operator approves them. How they approve is the
**approval mode**, one top-level key in Operator config
([ADR-0033](adr/0033-operator-approvals-default-to-a-prompt.md)):

```toml
approval = "prompt"   # the default: a host ask or a terminal [y/N]
approval = "passkey"  # a WebAuthn ceremony through the approval broker
```

Only Operator config sets it; a repository's `guardrail.toml` cannot. If the
file cannot be read or parsed, guardrail uses `passkey`, the stronger mode.
`guardrail doctor` prints `approval mode: prompt …` or `approval mode: passkey …`.

## Prompt mode (default)

**From a terminal**, the command asks and waits:

```
Approve remove guardrail from planes: claude? [y/N]
```

`y` or `yes` approves; anything else, including a bare Enter, declines and
changes nothing (exit 3 for `setup` and `plane`, 1 for `recover` and
`web-research`). `night` and `egress` apply directly from a terminal, as they
always have. With no terminal and no host approval the command refuses as
before (exit 3, or 2 for `recover`, `web-research`, `night`, `egress`), except
the first-install bootstrap of ADR-0030, which can only tighten.

**From an agent**, the exact canonical command is intercepted by the hook and
becomes the host's own permission prompt, naming the action:

| Plane | What the operator sees |
|---|---|
| Claude Code | its permission prompt (`ask`) |
| Antigravity | its permission prompt (`force_ask`) |
| opencode | its dialog, where its permission settings ask for the command; otherwise the agent is told to have you run it in a terminal |
| Codex | nothing: Codex cannot ask from a hook, so the call is denied and the agent names the command for you to run in a terminal |

When you approve, the host runs the command without a terminal, so the hook
leaves an **approval ticket** that the command claims as its proof. A ticket
binds the exact command and working directory, lives ten minutes, is spent by
the first run that claims it, and is voided by the session's next tool call,
so a refused ask leaves nothing usable behind. Tickets live under the state
root in `guardrail/approval-tickets/`, which agents cannot write (P5).
Anything other than the exact command (a different spelling, a chained
command, a pty wrapper such as `script`, `expect`, `unbuffer` or `winpty`,
an interpreter naming guardrail) stays denied as `P5.self-config`, and a
session cannot run `guardrail hook` itself.

The audit log records how each action was approved: `transport: host-ask`,
`terminal-prompt`, `bootstrap` or, in passkey mode, the WebAuthn transport.

**Accepted trade-off.** A host that approves everything by itself answers the
ask for you: Claude Code's `bypassPermissions` mode or an allow rule matching
these commands, Codex full-auto. An agent in such a session can change
guardrail's own settings unseen. Agents cannot switch their host into that mode
(host settings are P5), but prompt mode trusts the host's prompt. Prompt mode
also stops at the engine's static boundary: a script file or a background job
the engine cannot see into can run the CLI, and only a passkey's user
verification cannot be scripted. If either matters to you, use passkey mode.

## Passkey mode

With `approval = "passkey"`, guardrail completes persistent operator actions
only after a local WebAuthn ceremony, exactly as before ADR-0033. The browser
page shows the canonical action, repository path, scope, exact egress host
when applicable, request ID prefix, and expiry. Verify those fields before
satisfying the authenticator prompt. The rest of this page describes passkey
mode.

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
Each has its **own** credential store (`%USERPROFILE%\.local\state\guardrail`
on Windows, `~/.local/state/guardrail` in WSL; unlike the audit log and
sessions, the credential store is not under `%LOCALAPPDATA%`), and both
ceremonies use the WebAuthn rpId
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

Unix, WSL, and macOS use the local loopback ceremony. Windows uses the same
browser ceremony; the CLI reaches the daemon over a per-user named pipe
([ADR-0021](adr/0021-windows-approval-broker.md),
[ADR-0025](adr/0025-persistent-daemon-broker-windows.md)). Which OS has a
completed approval on record is in the
[compatibility matrix](compatibility-matrix.md). Browser automation
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
manages Guardrail's integration in that plane's global config through an
operator approval of a `plane-enable`/`plane-disable` request bound to the
exact planes: in prompt mode a terminal `[y/N]` or a host ask; in passkey mode
an interactive local terminal, a broker request and a WebAuthn approval. Enable regenerates and merges the Guardrail
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
antigravity-hooks) repairs Guardrail-protected machinery after an operator approval bound to the
exact named repair (a terminal `[y/N]` or host ask in prompt mode; the broker
and WebAuthn in passkey mode), audit-journaled, idempotent. Every repair takes a timestamped backup
first (`<path>.guardrail-recover-<utc>`); an unparseable file is reset and
the Guardrail integration re-registered (original bytes preserved in the
backup), while a parseable file is repaired in place with user configuration
untouched. Repairs are predefined code — an agent can never supply repair
content, only be told to ask the operator for a named repair.
