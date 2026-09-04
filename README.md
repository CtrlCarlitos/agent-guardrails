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

Plans 1–2 implemented. `guardrail hook claude` enforces P1 (destructive commands)
and P4 (secret paths) with audit logging and per-repo `guardrail.toml` overlays;
`guardrail gen-config claude` emits/merges the Claude declarative floor (`hooks`
registration + a coarse `permissions` deny/ask set); `guardrail doctor` reports
resolved state. Pending: CI release workflow + dotfiles installer + smoke test
(Plan 3), remaining policy modules P2/P5/P6/P7/P10 (Plan 4), opencode adapter
(Plan 5), Antigravity adapter (Plan 6), recipes + `guardrail sync` (Plan 7).

## Layout

```
cmd/guardrail/        Engine entrypoint; `guardrail hook <plane>`, `gen-config <plane>`, `doctor` (`sync` is planned, Plan 7)
internal/genconfig/   Translate the policy into each plane's native declarative floor + idempotent merge
internal/policy/      Policy model, guardrail.toml parsing, Base+Overlay merge
internal/engine/      Tokenizer (mvdan.cc/sh), evaluation, verdicts, lethal-trifecta gate
internal/adapter/     Per-plane payload normalization + response emission
adapters/opencode/    The ~30-line opencode JS plugin that spawns `guardrail hook opencode`
recipes/              Per-language P8 format+lint recipes (Go, Python, JS/TS, Rust, Elixir, Odoo)
test/fixtures/        Recorded per-plane payloads → expected verdict (contract tests)
docs/adr/             Architecture decision records
```
