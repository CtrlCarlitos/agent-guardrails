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

Plans 1–4 + the git -C/-c hotfix (v0.4.1) + Plan 4b implemented. `guardrail hook
claude` enforces P1/P2/P4/P5/P6, escalates via a two-signal P7 trifecta heuristic
(session-scoped, ask-only, waivable), and answers SessionStart with an autonomy
posture message + active-waiver banner (P10). `gen-config`/`doctor` cover Claude
installation and diagnostics. CI + real releases ship the binary; the chezmoi
installer wires it globally, currently pinned to v0.4.1. Pending: opencode adapter
(Plan 5), Antigravity adapter (Plan 6), recipes + `guardrail sync` (Plan 7). Known
parked gaps: `git -C <path>` target-repo validation (a different concern from the
v0.4.1 parsing fix), `docker … | xargs`, backslash-escaped words, `bash -lc`,
Windows-path engine semantics, macOS `sha256sum` fallback.

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
