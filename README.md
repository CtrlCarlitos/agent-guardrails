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

Plans 1–3 implemented. `guardrail hook claude` enforces P1/P4 with audit logging and
per-repo `guardrail.toml` overlays; `guardrail gen-config claude` emits/merges the
Claude declarative floor with marker-based owned-entry replacement (safe to re-run
and to rebind `--binary`); `guardrail doctor` reports resolved state. CI runs the
full build/vet/test/gofmt suite on ubuntu and builds+vets on windows on push; `v*`
tags publish checksummed cross-platform binaries to GitHub Releases (`v0.3.0` is
the first). Pending: chezmoi installer + real-Claude smoke test (Plan 3b), policy
modules P2/P5/P6/P7/P10 (Plan 4), opencode adapter (Plan 5), Antigravity adapter
(Plan 6), recipes + `guardrail sync` (Plan 7).

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
