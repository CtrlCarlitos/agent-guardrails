# Anything that loosens policy requires operator opt-in

ADR-0003 decided a repo's `guardrail.toml` could `waive` a named rule, on the
reasoning that a visible, logged exception beats people disabling the whole
guard. The 2026-09-04 adversarial review found that neither half held:

- `waive` accepted arbitrary ids with no allowlist and no cap, including
  `tokenize-failed` and `panic-recovered` — the two fail-closed backstops.
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

Decision: **a repo overlay may tighten, never loosen.** It may add rules, make
existing rules stricter, and fill parameterized slots in a repo-scoped way.
Anything that would make the guard permit something it would otherwise block —
a waiver, a `secret_allow` entry, a non-repo-scoped `safe_roots`, an
`audit_log` redirect — takes effect only when the **operator** has authorized
it in `~/.config/guardrail/waivers.toml`, a machine-scoped file outside any
repo and itself protected from the agent.

Authorization is **per repo, by absolute path**, not a global list of waivable
rules: a waiver you granted your own project must not transfer to a repository
you clone. `tokenize-failed`, `panic-recovered`, and `P3.unresolved` are never
waivable, by anyone.

Unauthorized loosening is **dropped with a warning**, not a fatal error — a
hostile repo must not be able to deny service. Warnings surface in the
SessionStart banner and `guardrail doctor`, because the review proved stderr
on an exit-0 hook is invisible.

## Consequences

- Granting a waiver is now a two-file operation: the repo asks, the operator
  authorizes. That friction is the point.
- Existing `guardrail.toml` files with waivers keep parsing but their waivers
  stop taking effect until authorized — surfaced, not silent.
- ADR-0003 is superseded on the authorization question; its reasoning about
  *why* an escape hatch should exist at all still stands.
