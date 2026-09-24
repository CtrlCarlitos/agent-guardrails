# First-install bootstrap: arm the planes before the operator enrolls

**Status:** design, approved by the operator 2026-09-24 (direction and the
terminal-gate question, in chat). Companion plan:
`docs/superpowers/plans/2026-09-24-first-install-bootstrap.md`. ADR:
`docs/adr/0030-first-install-bootstrap-arms-without-approval.md`.
Issue: #326 part B. Builds on #327 (part A: exit 3 and the unmasked daemon
reason).

## Problem

On a machine with no enrolled operator, `guardrail setup` cannot register
any plane: registration is an operator action, operator actions need a
WebAuthn approval, and no approval ceremony can begin without a passkey.
After #327 the failure is at least honest (`exit 3`, "run `guardrail
operator enroll`"), but the outcome is still that a fresh machine ends its
first install **unguarded**. The documented workaround is `--no-setup`,
then `operator enroll`, then `setup` — three steps the operator has to know
about, and a dotfiles run (`chezmoi apply`) cannot perform any of them.

The order is backwards. Enrollment exists to stop the guarded planes from
loosening their own posture; it was never meant to stop the planes from
being guarded in the first place.

## Decision

When no operator authenticator is enrolled, `guardrail setup` and
`guardrail plane enable` **arm the planes without an approval**: they
register the hooks and the permissions floor for every detected plane,
record the action in the audit log with `transport: bootstrap`, run the
coverage gate and `selftest`, print the one-time enrollment instruction,
and exit 0. Nothing else changes: every loosening action stays
approval-only, and the moment a credential is enrolled every plane change
— including a re-enable — goes back through WebAuthn.

### The invariant

> **The approval-less path can only tighten.** It can register and enable.
> It can never disable, unregister, grant, waive, reset, or change night
> mode.

This is what makes a deleted `authenticators.json` useless to an attacker:
the only thing the bootstrap state unlocks is *more* guarding. Every
loosening command on an unenrolled machine keeps #327's behaviour (exit 3
and the enrollment instruction).

### No marker, no elevation check

Two shapes were considered and rejected:

- **A bootstrap marker under `operator-auth/`** that the first real
  enrollment retires. Its job would be to tell "never enrolled" from
  "authenticators.json was deleted". But anyone who can delete that file
  can delete the marker, and can already edit `settings.json` directly.
  The marker adds a state to reason about and protects nothing the
  invariant does not already protect.
- **Elevated / root install as the bootstrap authority.** It does nothing
  for an ordinary user-level install, needs per-platform detection, and an
  elevated shell is not evidence of operator intent.

The rule is therefore just: *not enrolled, and the action is enable*.

### The terminal gate

`setup` and `plane enable` refuse to run without an interactive terminal
because the approval ceremony needs one and because agents must not run
them. On the bootstrap path there is no ceremony, so `setup --state
enabled` and `plane enable` **skip the terminal gate when no operator is
enrolled**. A first `chezmoi apply` on a fresh machine then fully arms it
unattended, which also settles the first-install half of #324.

That removes one of the two things standing between an agent and
`guardrail setup` on an unenrolled machine (the other, enrollment, is by
definition absent). An agent that can run a **different** guardrail binary's
`setup` would register hooks pointing at that binary — not a tightening. The
engine already denies agent invocations of `guardrail night on|off`
(`P5.self-config`, ADR-0012 for opaque interpreter input); this design
extends that rule to `guardrail setup`, `plane enable|disable`,
`operator …` and `recover …`, direct and opaque, so an armed plane cannot
re-arm, disarm or re-enrol itself. `plane status`, `doctor`, `selftest`,
`audit`, `version` and every other read-only subcommand stay allowed.
Before any plane is armed the agent is unmediated anyway; this closes the
window that opens the moment the first plane is registered.

`setup --state disabled` and `plane disable` keep the terminal gate: they
are loosening actions and always go through an approval.

### What the operator sees

A fresh machine, `sh install.sh --version vX` (or `chezmoi apply`):

```
setup: registering /home/u/.local/bin/guardrail
claude: not registered; enabling
codex: not registered; enabling
opencode: not detected
antigravity: not detected
claude enabled (bootstrap: no operator enrolled)
codex enabled (bootstrap: no operator enrolled)
… selftest output …
setup: plane status
claude: registered
codex: registered
…
setup: planes armed without an approval because no operator authenticator is enrolled.
setup: run 'guardrail operator enroll' from a real terminal to take control; every later plane change needs your passkey.
setup: for Codex, run /hooks inside Codex to review and trust the generated hooks; restart the agents you wired.
```

`guardrail doctor` on that machine, until enrollment:

```
operator approvals: disabled (no authenticator enrolled; planes armed by bootstrap; run guardrail operator enroll)
```

The audit log carries one `operator-action` record per bootstrap run:
`operator_action: plane-enable`, `decision: completed`, `transport:
bootstrap`, `reason: bootstrap: no operator enrolled; planes claude,codex`,
no request id and no credential fingerprint. `guardrail audit` lists it
with the other operator actions.

After `guardrail operator enroll`, nothing special happens: the next
`setup`, `update` or `plane enable` that finds drift opens the WebAuthn
ceremony as today. There is no state to retire.

### Exit codes after this change

| Situation | `setup` | `setup --state disabled` | `plane enable` | `plane disable` | `recover` |
|---|---|---|---|---|---|
| Enrolled, terminal, approved | 0 | 0 | 0 | 0 | 0 |
| Enrolled, terminal, denied/expired | 1 | 1 | 1 | 1 | 1 |
| Enrolled, no terminal | 2 | 2 | 2 | 2 | 2 |
| Not enrolled, something to do | **0, armed by bootstrap** | 3 | **0, armed by bootstrap** | 3 | 3 |
| Not enrolled, no terminal, something to do | **0, armed by bootstrap** | 2 | **0, armed by bootstrap** | 2 | 2 |
| Nothing to do (any enrollment state) | 0 | 0 | 0 | 0 | n/a |

`recover` rewrites a plane's config file (backup, then overwrite) before
re-enabling; it stays approval-only even though its direction is
tightening, because it destroys operator-owned content on the way.

## Components

**`cmd/guardrail/setup.go`** — `setupEnable` gains the bootstrap branch:
when the batch is non-empty and `operatorEnrolled()` is false, call
`bootstrapPlanes(batch, stdout)` instead of `requireOperatorEnrolled` +
`planesViaApproval`, then continue into the convergence check, the gates
and the status block, and end with the enrollment instruction.
`cmdSetup` evaluates the terminal gate after argument parsing and only
when the run is not a bootstrap enable.

**`cmd/guardrail/plane.go`** — `bootstrapPlanes(planes, stdout) error`:
`enablePlaneIntegration` per plane, then one audit record with
`transport: bootstrap`. `cmdPlaneLifecycle` takes the same branch for
`plane-enable` and skips the terminal gate in that case.
`operatorEnrolled` and `requireOperatorEnrolled` are unchanged from #327.

**`cmd/guardrail/action_audit.go`** — `writeBootstrapAudit(planes)`
builds the record above and writes it through `writeActionAudit` (the
existing test seam).

**`cmd/guardrail/doctor.go`** — `operatorApprovalStatus(enrolled, armed
bool)`: the `armed` argument is "any supported plane is registered", and
selects the bootstrap wording.

**`internal/engine/rules_bash.go`** — `checkNightControlInvocation`
generalises to `checkSelfControlInvocation`: the direct match accepts
`night on|off`, `setup`, `plane enable|disable`, `operator <anything>`,
`recover <anything>`; the opaque match looks for the executable plus any of
`night`, `setup`, `plane`, `operator`, `recover`. Read-only forms stay
allowed exactly as `night status` does today: `plane status`, and every
subcommand not listed. Reasons name the subcommand.

**Installers** — the handoff already exits with `setup`'s code, which is
now 0 on a fresh machine. One real change: both scripts probe whether the
binary has `setup` by running it with stdin piped and reading the exit-2
refusal. A bare piped `setup` would now *bootstrap* on an unenrolled
machine, so the probe becomes `setup --state disabled`, which keeps the
terminal gate in every enrollment state and touches nothing. A capability
probe must never have side effects. The `install.ps1` harness case that
relied on the old refusal places the binary with `-NoSetup` first, then
runs `-State disabled` without a console.

## Error handling

- `enablePlaneIntegration` failing for one plane: print
  `guardrail: setup: <plane>: <err>` and exit 1, exactly as the approval
  path's convergence check does. Planes already enabled in the same batch
  stay enabled (each merge is idempotent and independently correct).
- Audit write failing: the planes are already registered; print a warning
  line `guardrail: setup: bootstrap audit record not written: <err>` and
  continue with exit 0. The registration is the safety-relevant outcome;
  a missing log line must not leave the machine unguarded.
- Store inspection error (`Enrolled()` returns an error): treated as
  enrolled (unchanged from #327), so the run goes to the daemon and gets
  the daemon's reason. Bootstrap never triggers on a store that might hold
  credentials.

## Testing

Behavioural, hermetic (`testenv`), with the existing seams. Named in the
plan; the important ones:

- setup, not enrolled, unregistered plane → exit 0, plane registered on
  disk, `enabled (bootstrap: no operator enrolled)` line, gates ran once,
  no `submitPlaneRequest` call, one audit record with `transport:
  bootstrap`, the enrollment instruction printed last.
- setup, not enrolled, **no terminal** → same outcome (the gate is
  skipped).
- setup, enrolled, no terminal → exit 2 (unchanged).
- setup `--state disabled`, not enrolled → exit 3, nothing removed
  (unchanged from #327); no terminal → exit 2.
- plane enable, not enrolled → bootstrap; plane disable, not enrolled →
  exit 3; recover, not enrolled → exit 3.
- steady state, not enrolled → exit 0, no audit record.
- doctor: registered plane + not enrolled → the bootstrap wording; not
  registered + not enrolled → #327's wording; enrolled → `WebAuthn`.
- engine: `guardrail setup`, `guardrail plane enable claude`,
  `guardrail plane disable --all`, `guardrail operator enroll`,
  `guardrail recover claude-settings`, a `python3 -c` that mentions any of
  them, and the `.exe` / absolute-path spellings → deny `P5.self-config`;
  `guardrail plane status`, `guardrail doctor`, `guardrail selftest`,
  `guardrail audit` → allow.
- installer harnesses: `install_sh_test.sh` unchanged (its handoff case
  uses a fake `guardrail` that decides the code); `install_ps1_test.ps1`'s
  `handoff-propagates-setup-exit-code` installs with `-NoSetup`, then runs
  `-State disabled` without a console and expects exit 2. Both harnesses
  and shellcheck green locally (Windows pwsh, WSL) and in CI.

## Out of scope

- #324's `--state disabled` non-interactive contract (a loosening action;
  still needs a person).
- Re-arming after `operator recover-reset`: the store is empty again, so a
  later `setup` bootstraps if a plane drifted. That is the invariant
  working as designed, not a special case.
- Distinguishing "bootstrapped" from "approved" anywhere other than the
  audit log and the doctor line.
