# Anything that loosens policy requires operator opt-in

ADR-0003 decided a repo's `guardrail.toml` could `waive` a named rule, on the
reasoning that a visible, audited Waiver beats people disabling the whole
guard. The 2026-09-04 adversarial review found that neither half held:

- `waive` accepted arbitrary ids with no Operator config authorization and no
  cap, including
  `tokenize-failed`, `panic-recovered`, and `P3.unresolved` — the three
  fail-closed backstops.
  A repo-local file turned `rm -rf /etc`, `sudo`, `mkfs`, and `curl | bash`
  into exit-0 allows.
- Slot widening reached *globally*: `secret_allow = ["**"]` made
  `~/.ssh/id_rsa` readable, a path nowhere near the repo.
- `audit_log` silenced the trail and gave an append-anything primitive.
- "Logged" meant stderr on an **exit-0** hook, which Claude Code never
  surfaces. The mitigation ADR-0003 relied on did not exist in practice.

The failure mode is structural, not a bug: a repo the agent is *working in*
was trusted to describe the policy governing that agent. A cloned repo is
untrusted input.

Decision: **a repository Overlay may tighten, never loosen.** It may add rules,
make existing rules stricter, and fill parameterized slots in a repo-scoped way.
Anything that would make the guard permit something it would otherwise block —
a Waiver, a `secret_allow` entry, an `egress_allowlist` entry, or an `audit_log`
redirect — takes effect only when the **operator** has authorized it in
`~/.config/guardrail/waivers.toml`, a machine-scoped file outside any repo and
itself protected from the agent.
`safe_roots` entries are repository-scoped only; entries that resolve outside
the repo are always dropped and cannot be authorized by the operator.

Egress authorization is per entry: the exact Overlay string must appear in the
grant for that exact cleaned absolute repository path. Equivalent spellings do
not inherit authorization. Total wildcards `*` and `**` are always dropped,
even if an Operator config lists them. Disabling the whole P6 gate instead
requires an explicit P6 Waiver.

Authorization is **per repo, by absolute path**, not a global list of waivable
rules: a waiver you granted your own project must not transfer to a repository
you clone. `tokenize-failed`, `panic-recovered`, and `P3.unresolved` are never
waivable, by anyone.

Unauthorized loosening is **dropped with a warning**, not a fatal error — a
hostile repo must not be able to deny service. Warnings surface in the
Claude SessionStart posture and `guardrail doctor`, because the review proved
stderr on an exit-0 hook is invisible. OpenCode and Antigravity have no
SessionStart posture; Doctor is their operator-facing warning view.

This protects targets the Engine can see at the tool-call boundary. Existing
symlinks are resolved before secret and Operator config checks, and visible
Operator config paths in known opaque interpreters are denied. The Engine is
not an operating-system sandbox: same-user code that constructs and writes a
protected path without exposing it in the attempted tool call remains outside
this static boundary.

## Consequences

- Granting any loosening request is now a two-file operation: the repo asks,
  the operator authorizes. That friction is the point.
- Existing `guardrail.toml` files with waivers keep parsing but their waivers
  stop taking effect until authorized — surfaced, not silent.
- ADR-0003 is superseded on the authorization question; its reasoning about
  *why* an escape hatch should exist at all still stands.
