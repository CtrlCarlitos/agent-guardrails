# ADR-0030: A first install arms the planes without an approval; the approval-less path can only tighten

## Status

Accepted (operator, 2026-09-24). Design:
`docs/superpowers/specs/2026-09-24-first-install-bootstrap-design.md`.
Closes #326. Amends ADR-0029 ("`setup` needs an interactive terminal and an
enrolled operator"): that holds once an operator is enrolled, and for every
loosening action always.

## Context

Registering a plane is an operator action (ADR-0021): it needs a WebAuthn
approval, and an approval needs an enrolled passkey. On a fresh machine that
made the first install fail — first as a misleading "approval daemon
unavailable", then, after #327, as an honest exit 3 — and left the machine
unguarded until the operator found the three-step workaround (`--no-setup`,
`operator enroll`, `setup`). Dotfiles-driven installs could not complete at
all.

The approval requirement exists so the guarded planes cannot loosen their own
posture. Making the planes *guarded* in the first place is the opposite
direction.

## Decision

1. When no operator authenticator is enrolled, `guardrail setup` (state
   `enabled`) and `guardrail plane enable` register the planes and their
   permissions floor **without an approval**, run the coverage gate and
   `selftest`, write an `operator-action` audit record with
   `transport: bootstrap`, print the one-time enrollment instruction, and
   exit 0. `guardrail doctor` reports `planes armed by bootstrap` until a
   credential is enrolled.
2. **The approval-less path can only tighten.** Disable, unregister,
   recover, grants, waivers, night mode and credential management keep
   exit 3 and the enrollment instruction on an unenrolled machine. This is
   what keeps a deleted `authenticators.json` worthless: it unlocks more
   guarding and nothing else.
3. There is no bootstrap marker and no elevation check. The rule is "not
   enrolled, and the action is enable". A marker could be deleted by the
   same hand that deleted the credentials, and an elevated shell is not
   evidence of operator intent.
4. The bootstrap enable path skips the interactive-terminal gate: there is
   no ceremony to host, and this lets an unattended first `chezmoi apply`
   arm a fresh machine.
5. To keep (4) from handing agents a way to register a different binary's
   hooks, the engine's `P5.self-config` self-control rule — which already
   denies `guardrail night on|off` from a mediated session, directly and
   through opaque interpreters — extends to `guardrail setup`,
   `plane enable|disable`, `operator …` and `recover …`. Read-only
   subcommands (`plane status`, `doctor`, `selftest`, `audit`, `version`,
   `night status`) stay allowed.

## Consequences

- A first install is one command on every OS: the installer arms the
  machine and tells the operator to enroll. `--no-setup` remains for CI
  and for operators who want to run `setup` themselves.
- Once enrolled, nothing changes: every later plane change goes through
  WebAuthn, including re-enables after drift. There is no bootstrap state
  to retire, so `operator recover-reset` needs no new logic either.
- `guardrail audit` shows bootstrap registrations as operator actions with
  `transport: bootstrap` and no credential fingerprint, distinguishable
  from approved ones.
- Mediated agents can no longer invoke the lifecycle subcommands at all;
  the operator runs them from a real terminal, which is what every runbook
  line already says.
- ADR-0029's first-install narrative (`--no-setup`, then enroll, then
  setup) becomes optional rather than required.
