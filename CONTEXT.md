# Agent Guardrails

One guardrail policy ("SOP") enforced across any number of AI coding-agent hosts
("planes"). A shared decision engine plus generated per-plane native config; thin,
idiomatic adapters. Ships universally via dotfiles; each project layers its own rules.

## Language

**Plane**:
An AI coding-agent host that can run the guardrails through its own extension
mechanism. Today: Claude Code, opencode, Antigravity. Planned: Codex.
_Avoid_: harness, runner, agent, tool

**Guardrail Policy**:
The plane-agnostic ruleset the guard enforces. Split into the **Base policy**
(universal, shipped by the dotfiles package) and an **Overlay** (a project's own).
_Avoid_: SOP, ruleset, config

**Base policy**:
The universal Guardrail Policy shipped with the dotfiles package. The floor every
plane gets. An Overlay may tighten, extend, or `waive` it, never silently loosen it.
_Avoid_: default policy, global rules

**Overlay**:
A project's committed `guardrail.toml`. Adds rules, fills the Base's parameterized
slots (safe roots, egress allowlist, ephemeral-DB pattern, container-naming scheme,
formatter tiers), and may request permission to `waive` named Base rules.
_Avoid_: project config, local policy, override file

**Operator config**:
Machine-scoped authorization outside any repository. Grants a named repository
permission to loosen specific rules. A repository's Overlay may request; only the
Operator config may grant.
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
The subset of the Policy expressed as a plane's *native* permission config (Claude
`settings.json` permissions, `opencode.json` permission, Antigravity `hooks.json`).
Enforced by the plane itself even when the Engine is unavailable.
_Avoid_: static rules, fallback policy

**Recipe**:
A per-language definition of the P8 format-and-lint commands, split into a per-edit
tier (sub-2s, single file) and a session-completion tier. Base ships Go, Python,
JavaScript/TypeScript, Rust, Elixir, Odoo.
_Avoid_: linter config, toolchain, profile

**Waiver**:
An entry in an Overlay's `waive = [...]` that switches a named Base rule off for that
project when authorized by the Operator config. Written to the audit log on every hit
and printed in the session-start banner — never silent.
_Avoid_: exception, exclusion, ignore
