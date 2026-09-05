# Phase 3 Whole-Review Hardening Design

## Status

Approved in conversation on 2026-09-05. This design resolves the findings from
the whole-phase review of `aa66b99...3d884e7` before `v0.11.0-dev` is published.

## Trust Boundary

The Guardrail Policy evaluates operations visible through a plane's tool-call
boundary. It is not an operating-system sandbox: arbitrary same-user code can
construct effects that are absent from the command text and therefore cannot be
proven safe by static inspection. The Engine must fail closed when a protected
target is visible, including through a filesystem symlink or as a literal in an
opaque interpreter command. Dynamically concealed writes remain an explicit
hardening limitation; Phase 2 remains outstanding and the installer pin must not
move to this development version.

## Operator-Scoped Egress

An Overlay egress entry permits traffic that the Base policy otherwise denies,
so it is a loosening and requires Operator config authorization.

`RepoGrant` gains an optional `egress_allowlist = [...]`. An Overlay egress entry
takes effect only when the exact string appears in the grant for the exact
cleaned absolute repository path. Exact matching is deliberately fail closed:
equivalent spellings do not inherit authorization. `*` and `**` remain forbidden
even when listed by the operator; disabling P6 requires an explicit P6 Waiver.
Every rejected entry produces a deterministic warning.

This preserves project-specific egress configuration as a two-file handshake:
the Overlay requests destinations and the machine-scoped Operator config grants
only the named entries.

## Plane Failure Semantics

After the plane and phase are known, all hook setup failures use one fail-closed
boundary. Claude and OpenCode retain sanitized stderr plus exit status 2.
Antigravity pre-hooks emit sanitized deny JSON and exit 0 because the plane
ignores process status and has no Declarative floor. Antigravity post-hooks emit
`{}` and exit 0 because a completed operation cannot be blocked retroactively.
Parse, Base-load, Overlay-load, and Merge failures follow these semantics.

## Operator Config Self-Protection

Path checks resolve existing symlinks for candidates both inside and outside the
repository. A resolved target is re-evaluated against secret and self-config
protections. This closes H-5 (`/tmp/innocent` resolving to a secret) and denies
writes through aliases to Operator config.

Opaque interpreters (`python`, `node`, and equivalent established executors)
receive a conservative P5 denial when their visible literal code references an
Operator config path. Direct read tools remain readable as previously specified.
This catches visible same-user scripting attempts without claiming to detect a
path assembled dynamically at runtime.

## Declarative Floor Ordering

OpenCode uses the last matching permission rule. Generated JSON must therefore
order permission rules monotonically by Verdict strength: `allow`, then `ask`,
then `deny`, with deterministic lexical order within each group. Existing and
generated entries participate in the same ordering, and exact-key collisions
retain the stricter Verdict. A retained broad `allow` can no longer override a
generated `ask` or `deny`; retained `ask`/`deny` rules can still tighten the
floor. Claude generation remains unchanged.

## Safe Roots And Display Output

Accepted relative `safe_roots` are stored as cleaned absolute paths relative to
the actual repository root. Validation continues to resolve existing ancestors
to reject symlink escapes; warnings retain the requested spelling.

`guardrail sync` applies the uncapped terminal display sanitizer to every dynamic
path, warning, and error, preserving complete dispositions while preventing
control-character line forgery.

## Repository Hygiene And Documentation

Accidentally tracked `.superpowers/sdd/` task reports are removed. Canonical
terminology replaces prohibited uses of "exception" and "waiver file" in
Phase 3 documentation. Review annotations are corrected after H-5 is covered;
Phase 2 and the arbitrary same-user-code limitation remain explicit.

## Verification

Each correction starts with a focused regression test. Required integration
coverage includes:

- an ungranted exact egress host remains denied and an exact Operator grant
  permits only that entry;
- malformed, oversized, and invalid-merge Antigravity pre-hooks emit deny JSON;
- outside-repository symlink aliases to secrets and Operator config are denied;
- visible opaque-interpreter Operator-config writes are denied;
- OpenCode broad retained allows lose to generated floor denies;
- relative safe roots are normalized to absolute repository paths;
- hostile sync output cannot forge lines;
- the adversarial corpus only gains deny expectations.

Final publication requires focused reviews, a fresh whole-phase review,
`make check`, an uncached `go test ./...`, a clean worktree, then pushing `main`
and the `v0.11.0-dev` tag. The chezmoi installer pin is not changed.
