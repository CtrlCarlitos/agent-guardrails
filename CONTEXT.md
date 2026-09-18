# Agent Guardrails

One Guardrail Policy enforced across any number of AI coding-agent hosts
("planes"). A shared Engine plus generated native config where a plane supports
it; thin, idiomatic Adapters. Ships universally via dotfiles; each project layers
its own rules.

## Language

**Plane**:
An AI coding-agent host that can run the guardrails through its own extension
mechanism. Today: Claude Code, opencode, Antigravity, Codex.
_Avoid_: harness, runner, agent, tool

**Guardrail Policy**:
The plane-agnostic ruleset the guard enforces, comprising the **Base policy**
(universal, shipped by the dotfiles package) and an **Overlay** (a project's own).
Its secret tiers classify protected paths according to their certainty and scope.
_Avoid_: SOP, ruleset, config

**Directory secret**:
A path inside a sensitive directory. It always Denies and cannot be waived or
overridden by a Secret allowance.

**File secret**:
A path matching a definitive secret-file pattern. It Denies unless an authorized
Waiver or Secret allowance applies.

**Ambiguous secret**:
A path matching a potentially sensitive file pattern. It Asks inside the
repository and Denies outside it.

**Secret allowance**:
An Overlay `secret_allow` request authorized by Operator config. It can allow a
matching file name but never overrides a Directory secret.

**Base policy**:
The universal Guardrail Policy shipped with the dotfiles package. The floor every
plane gets. An Overlay may tighten, extend, or `waive` it, never silently loosen it.
_Avoid_: default policy, global rules

**Overlay**:
A project's committed `guardrail.toml`. Adds rules; extends safe roots, secret
tiers, Secret allowances, and the egress allowlist; and may request permission to
`waive` named Base rules. Its audit-log request is a top-level setting.
_Avoid_: project config, local policy, override file

**Operator config**:
Machine-scoped authorization outside any repository. Grants the repository at a
named absolute path permission to make specific loosening requests. An Overlay
may request; only the Operator config may grant. Authorization remains attached
to that path until the operator removes it.
_Avoid_: waiver file, global config, allowlist

**Engine**:
The single `guardrail` binary (Go) that holds all decision logic: normalize an
attempted tool call, evaluate it against the merged policy, return a Verdict. Also
generates each plane's Declarative floor.
_Avoid_: core, validator, checker

**Adapter**:
The per-plane integration between a plane's native hook/permission mechanism and the
Engine. A subcommand of the Engine binary for command-hook planes (`guardrail hook
claude`); a thin plugin that spawns the Engine for opencode.
_Avoid_: shim, plugin, hook (as a name for the whole integration)

**Verdict**:
The outcome of evaluating an attempted tool call: `allow`, `ask`, or `deny`. Planes
map these onto their own richer vocabularies (e.g. Antigravity's `force_ask`).
_Avoid_: decision, result, outcome

**Declarative floor**:
The subset of the Policy expressed as a plane's native permission config: Claude
`settings.json` permissions and OpenCode `opencode.json` permission. It remains
enforced when the Engine is unavailable; Codex has a limited native command-escalation floor, and
Antigravity has no Declarative floor.
_Avoid_: static rules, fallback policy

**Recipe**:
A per-language definition of the P8 per-edit format-and-lint commands. The Base
policy ships Go, Python, JavaScript/TypeScript, and Rust Recipes; session-completion,
Elixir, and Odoo Recipes remain follow-ups.
_Avoid_: linter config, toolchain, profile

**Waiver**:
An entry in an Overlay's `waive = [...]` that switches a named Base rule off for that
project when authorized by the Operator config. Written to the audit log on every hit
and printed in Claude's SessionStart posture — never silent.
_Avoid_: exception, exclusion, ignore

**System temp root**:
A platform-provided temporary-directory root. Only strict descendants are
authorized at designated write seams; the root itself and escapes remain protected.

**Plane-owned writable root**:
A narrowly shaped out-of-repository directory owned by one plane for its working
state. Authorization applies only to the named plane and designated write surfaces.

**Operator authorization request**:
A durable, exact request for an operator-controlled approval. It binds the
plane, repository, action or domains, scope, expiry, and one-shot consumption.
Only a host-owned Approve result or WebAuthn assertion can authorize it.

**Egress authorization**:
An operator's permission for an exact set of web-host domains. Repository scope
persists through a matching Overlay request and Operator config grant; Global
scope persists only in Operator config. It never authorizes a host wildcard or
an unrelated domain.

**Plane lifecycle**:
The operator-controlled enabled or disabled state of Guardrail integration for a
plane. The Guardrail binary remains installed while a plane is disabled, so an
audited enable command can restore only Guardrail-owned configuration.

**Delegation inheritance**:
A plane property: every tool call, subagents included, is mediated by that
plane's Guardrail adapter. On such planes (OpenCode, Claude) delegation is
allowed because each child call is still evaluated; other planes deny
delegation with proceed-inline guidance. See ADR-0013.

**Recovery request**:
A terminal-only Operator authorization request for a predefined repair of
Guardrail-protected machinery. It shows the normalized repair, requires
WebAuthn, and cannot execute arbitrary shell text supplied by a plane.

**Autonomy posture**:
Claude's SessionStart advisory describing the active operating posture, Waivers,
and warnings. It is model-facing context, not a Verdict mode.

**Containment posture**:
A proposed operator-selected `host` or `contained` enforcement posture described
by candidate ADR-0014. It is not implemented.
