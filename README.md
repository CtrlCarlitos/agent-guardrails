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

Plans 1–4 implemented. `guardrail hook claude` enforces P1 (destructive commands),
P2 (git-safety), P4 (secret paths), P5 (filesystem-scope + CI/infra/lockfile),
P6 (network-egress + supply-chain), with audit logging and per-repo `guardrail.toml`
overlays. `guardrail gen-config claude` / `doctor` cover Claude installation and
diagnostics. CI + a real `v0.3.1` release ship the binary; the chezmoi installer wires
it globally (Plan 3b). Pending: P7 (injection hygiene + lethal-trifecta) + P10
(autonomy posture) — Plan 4b, needs new session-state and SessionStart infrastructure;
opencode adapter (Plan 5); Antigravity adapter (Plan 6); recipes + `guardrail sync`
(Plan 7).

`make smoke` runs a best-effort end-to-end check against a real `claude` session
(needs a login, spends tokens, not in CI) — see `test/smoke/README.md`.

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
