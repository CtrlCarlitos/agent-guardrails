# ADR-0015: Codex has a limited native escalation floor

Codex supports Starlark `prefix_rule` files under `rules/` beside each active
config layer. Generate `rules/guardrail.rules` with a curated set of `forbidden`
command prefixes independently of the hook process. `gen-config codex --floor`
prints this floor; `gen-config codex --merge <hooks.json>`, `sync --planes codex`,
and plane enable install it alongside the hooks. Only the generated file is
owned; a user-created file with the same name is not overwritten. Disabling the
plane removes its hooks and retains the floor, matching Claude's retained native
permissions. Restart Codex after changing native rules.

This floor controls escalation outside the sandbox. It does not translate the
full Guardrail Policy, deny reads of secret paths, or govern hosted tools.
We deliberately do not rewrite the operator's `config.toml` sandbox or approval
preferences: those are separate native containment settings, not equivalent
translations of Guardrail rules. Runtime hook coverage limitations remain visible
in ADR-0014. No-floor would misdescribe an available, useful native mechanism;
claiming a complete permissions floor would overstate it.

Evidence: [official Codex rules documentation](https://learn.chatgpt.com/docs/agent-configuration/rules),
reviewed 2026-09-17. `codex execpolicy check --rules <generated.rules> -- rm -rf /`
on CLI 0.154.0 reports `forbidden` without executing the command.
