# agent-guardrails

One guardrail policy, enforced across every AI coding-agent host ("plane") — Claude
Code, opencode, Antigravity (Codex planned). A shared Go decision engine
(`guardrail`) plus a generated native-config floor per plane; thin idiomatic adapters.
Installed globally via dotfiles; each project layers its own rules in a committed
`guardrail.toml`.

- **Terminology**: [CONTEXT.md](./CONTEXT.md)
- **Full design**: [DESIGN.md](./DESIGN.md)
- **Key decisions**: [docs/adr/](./docs/adr/)

## Status

Plan 1 (engine core + Claude adapter) implemented: `guardrail hook claude` enforces
P1 (destructive commands) and P4 (secret paths) with audit logging and per-repo
`guardrail.toml` overlays. Plans 2–6 (declarative-floor generation, installer,
remaining policies, opencode/antigravity adapters, recipes) are pending — see
`docs/superpowers/plans/`.

## Layout

```
cmd/guardrail/        Engine entrypoint; `guardrail hook <plane>`, `guardrail sync`, `guardrail gen-config`
internal/policy/      Policy model, guardrail.toml parsing, Base+Overlay merge
internal/engine/      Tokenizer (mvdan.cc/sh), evaluation, verdicts, lethal-trifecta gate
internal/adapter/     Per-plane payload normalization + response emission
adapters/opencode/    The ~30-line opencode JS plugin that spawns `guardrail hook opencode`
recipes/              Per-language P8 format+lint recipes (Go, Python, JS/TS, Rust, Elixir, Odoo)
test/fixtures/        Recorded per-plane payloads → expected verdict (contract tests)
docs/adr/             Architecture decision records
```
