# Containment posture — the phase after the parser freeze

**Status:** design note, 2026-09-08. Candidate ADR-0013. Not scheduled; nothing
in this document is required to declare the remediation done.

## Why this is the next phase

ADR-0012 froze the Engine's shell semantics. The audit log settled what a
static command guard can and cannot do: it stops the *accident* class — a
model reaching for `rm -rf`, a secret path, `git push --force`, `git config
core.hooksPath` in the flow of work — and makes every dangerous action visible.
It cannot stop *intent*: a model that treats a block as a puzzle expresses the
same outcome in another shape (`rm a; rm b; rmdir d` after `rm -r d` is
denied). That limit has been in ADR-0010 from the start.

What stops intent is the blast radius. An agent whose workspace holds nothing it
cannot afford to lose, and whose environment holds no secrets, cannot do harm
that matters — whatever shape it uses. That is containment, and it is an
operations change, not Engine code.

## The problem this must solve

Containment and the guard have opposite instincts about autonomy. The guard's
`ask` Verdict exists to stop and fetch a human; a contained agent is supposed to
run unattended, often for hours. A guard that asks inside a container either
halts the run until someone notices, or gets switched off. Both are failures.

Today the question is moot: the chezmoi installer is gated on `$interactive`,
which is false in devcontainers, so containers receive **no guard at all** — no
prompts, but also no tripwire and no audit trail.

## Decision (proposed)

1. **Two postures, set by the operator, never inferred.**
   - **host** (today's behaviour): `allow` / `ask` / `deny` as designed. Used
     wherever the agent shares a filesystem with the operator's secrets and
     data — including every worktree on the host. A host worktree isolates
     *code*, not blast radius; it is not containment.
   - **contained**: every `ask` becomes `allow` and is written to the audit log
     as `ask-allowed-by-posture` with the originating rule ID. `deny` is kept
     only for the shapes that are catastrophic even inside a box: the `rm -rf
     /`, `~`, `.`, `..` literals, secret-directory reads, self-config and
     git-metadata writes, download-pipe-to-shell. P3's unresolved-word backstop
     downgrades to allow-and-audit like any other ask.
   The posture is a field in the Operator config (`posture = "contained"`) or
   an environment marker the installer sets when it detects a container. It is
   not a Waiver and not an Overlay slot; a repository cannot set it.

2. **The container is what makes `contained` safe, and the installer checks
   it.** `guardrail doctor` refuses to report a contained posture as healthy
   unless: no secret directory from `secret_dirs` is present or mounted; the
   workspace is the only writable bind mount; `HOME` is inside the container.
   A contained posture on a host is a WARNING in the SessionStart posture and in
   `doctor`, and the Engine falls back to **host** posture — silently
   weakening on a misconfiguration is the one thing this design must not do.

3. **The installer installs the guard in containers**, in contained posture,
   regardless of `$interactive`. The value inside a box is the audit trail and
   the catastrophic denies; the cost is zero prompts. This is the one chezmoi
   change: lift the `$interactive` gate for `install_agent_guardrails` only,
   and pass the posture.

4. **Nothing else changes.** No new parser semantics (ADR-0012). No new plane
   code beyond reading the posture. The ask-tier rules stay as they are; only
   their rendering changes under `contained`.

## What the operator does

- Run unattended agents in a container: workspace bind-mounted, nothing else
  writable, no `~/.ssh`, `~/.aws`, `~/.claude` mounted; credentials injected
  as short-lived tokens through the environment where a task needs them.
- Run attended agents on the host with the host posture; accept the occasional
  ask as the price of shared secrets.
- Read the audit log for the contained runs the way this project read it this
  week: by rule, by session, by shape. The tripwire still fires; it just does
  not wait.

## Explicitly out of scope

- Making the guard un-bypassable. Not possible for a static analyser; not the
  goal.
- Detecting containment from inside the Engine. The operator declares it; the
  installer and `doctor` verify the declaration's preconditions.
- Any change to H-10, H-6, NF-17/18/19. Those remain parked behind ADR-0012's
  threshold.

## Effort

Small: one Operator config field, one verdict-rendering branch per Adapter,
`doctor` preconditions, one installer gate change, tests and goldens. One SOL
task with the usual gate, after `v0.16.0-dev`. It should be the last piece of
work in this repository for a while.
