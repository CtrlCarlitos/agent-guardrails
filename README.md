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

The [2026-09-04 adversarial security review](./docs/reviews/2026-09-04-adversarial-review.md)
identified the current remediation roadmap. Phase 1 is published at `v0.9.0-dev`.
Phase 3 and its whole-review hardening are published at `v0.11.0-dev`. Phase 2
is complete on `main`; `v0.12.0-dev` is planned but has not been created or
pushed. Only Phase 4 remains outstanding in this repository. The installer pin
remains at `v0.7.0-dev`. The M-9 installer fix and Task 10b tooling remain on the
separate chezmoi branch `guardrail-remediation-phase1`, which is unmerged,
unapplied, and unpushed.

Every Overlay egress entry is a loosening request and needs an exact per-entry
grant for that repository in Operator config. Total wildcards `*` and `**` are
always forbidden. See [Operator config](./docs/operator-config.md).

The original plan series is complete: Plans 1–6 + the git -C/-c hotfix (v0.4.1) +
the deployment plan, and Plan 7 (P8 recipes + `guardrail sync`) finished it off.
`guardrail hook claude` enforces P1/P2/P4/P5/P6, escalates via a two-signal P7
trifecta heuristic (session-scoped, ask-only, waivable), runs per-edit P8 recipe
format+lint checks on edited files (Go, Python, JS/TS, Rust — lenient when a
tool is absent, deny on real lint failure, allow-only escalation; Odoo/Elixir
recipes and the session-completion tier are follow-ups per
[ADR-0009](./docs/adr/0009-recipe-scope.md)) — P8 denial surfaces on Claude
today (opencode needs a `tool.execute.after` plugin hook; antigravity post
responses are always `{}` per ADR-0008, so post denials there are audit-only) —
and answers Claude-only SessionStart with
an autonomy posture message + active-waiver banner (P10). `guardrail hook
opencode` runs the same shared pipeline (audit, trifecta, waivers) through a JS
plugin — ask/deny throw, allow passes through — which `gen-config opencode`
deploys alongside the generated `opencode.json` permission floor. `guardrail
hook antigravity <pre|post>` runs the same shared pipeline on Antigravity's
PreToolUse/PostToolUse events and is the whole boundary: Antigravity has no
declarative floor ([ADR-0008](./docs/adr/0008-antigravity-no-declarative-floor.md)),
so `gen-config antigravity` emits only the hooks.json registration; `gen-config`
covers Claude + opencode + Antigravity installation; `doctor` covers Claude
installation and diagnostics. `guardrail sync` regenerates a project's plane
configs from Base+Overlay in one shot (per-plane warn-and-continue). CI + real
releases ship the binary; the chezmoi installer wires it globally. Known parked
gaps include `git -C <path>` target-repo validation (a different concern from the
v0.4.1 parsing fix), `docker … | xargs`, backslash-escaped words, `bash -lc`,
Windows-path engine semantics, and the macOS `sha256sum` fallback. H-5's
outside-repository symlink laundering is fixed by resolved-target checks. The
Engine also denies visible opaque-interpreter references to Operator config, but
it is a static tool-call guard, not an operating-system sandbox: dynamically
concealed same-user writes remain outside its boundary. Phase 2's original
findings are fixed and locked in the 190-case adversarial corpus; the remaining
repository findings are assigned to Phase 4.

`make smoke` runs a best-effort end-to-end check against a real `claude` session
(needs a login, spends tokens, not in CI) — see `test/smoke/README.md`.

## Layout

```
cmd/guardrail/        Engine entrypoint; `guardrail hook <plane>`, `gen-config <plane>`, `sync`, `doctor`
cmd/guardrail/sync.go  `guardrail sync` — regenerate a project's plane configs from Base+Overlay
internal/recipe/      Per-language P8 recipe registry + per-edit format/lint execution (Go, Python, JS/TS, Rust)
internal/genconfig/   Translate the policy into each plane's native declarative floor + idempotent merge
internal/genconfig/opencode.go  opencode declarative floor (`permission.bash/read/edit` from the policy's glob lists)
internal/genconfig/opencode_plugin.js  Embedded JS plugin source, deployed by `gen-config opencode`; spawns `guardrail hook opencode`
internal/genconfig/antigravity.go  Antigravity hooks.json fragment — named-wrapper hook registration, no permissions key (ADR-0008)
internal/policy/      Policy model, guardrail.toml parsing, Base+Overlay merge
internal/engine/      Tokenizer (mvdan.cc/sh), evaluation, verdicts, lethal-trifecta gate
internal/adapter/     Per-plane payload normalization + response emission
internal/adapter/antigravity.go  Antigravity parse/emit for `hook antigravity <pre|post>` (`conversationId`, `toolCall.name`)
recipes/              Per-language P8 recipes (Go, Python, JS/TS, Rust; Odoo/Elixir per ADR-0009 follow-ups)
test/fixtures/        Recorded per-plane payloads → expected verdict (contract tests)
docs/adr/             Architecture decision records
```
