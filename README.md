# agent-guardrails

One guardrail policy, enforced across every AI coding-agent host ("plane") — Claude
Code, opencode, Antigravity (Codex planned). A shared Go decision engine
(`guardrail`) plus a generated native-config floor where the plane supports one;
thin idiomatic adapters.
Installed globally via dotfiles; each project layers its own rules in a committed
`guardrail.toml`.

- **Terminology**: [CONTEXT.md](./CONTEXT.md)
- **Full design**: [DESIGN.md](./DESIGN.md)
- **Key decisions**: [docs/adr/](./docs/adr/)

## Status

The current source and release boundary is `v0.17.0-dev` at `e1ab965`. The
[2026-09-04 adversarial security review](./docs/reviews/2026-09-04-adversarial-review.md)
and its Phase 1 through Phase 5 remediation are reconciled in the
[response ledger](./docs/reviews/2026-09-05-remediation-response.md). H-6, H-10,
NF-3, NF-11, NF-12, and candidate ADR-0013 containment are parked under
[ADR-0012](./docs/adr/0012-static-analysis-boundary-and-shape-threshold.md) and
operator direction.

Every Overlay egress entry is a loosening request and needs an exact per-entry
grant for that repository in Operator config. Total wildcards `*` and `**` are
always forbidden. See [Operator config](./docs/operator-config.md).

Secret paths have three tiers: directory secrets always Deny; file secrets Deny
but may be waived with Operator authorization; ambiguous secrets Ask inside the
repository and Deny outside it. A `secret_allow` entry cannot override a
directory secret.

Operator actions use a local, browser-mediated WebAuthn ceremony. Before
starting a coding plane, enroll an authenticator with `guardrail operator
enroll`; see [Operator approvals](./docs/operator-approvals.md). Unix, WSL,
and macOS are supported. Windows operator actions remain fail-closed.

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
releases ship the binary; the chezmoi installer wires it globally. The Engine is
a static tool-call guard, not an operating-system sandbox: dynamically concealed
same-user writes remain outside its boundary. Fixed behavior through Phase 5 is
locked in the 321-case adversarial corpus.

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

## Codex

Codex CLI 0.154.0 integration uses native synchronous hooks:

```sh
guardrail gen-config codex --merge "$HOME/.codex/hooks.json"
# In Codex, review and trust the generated definitions with /hooks, then restart.
guardrail plane status
```

`plane enable codex` and `plane disable codex` use the existing operator approval
flow. `CODEX_HOME` overrides the global Codex directory. Project installation is
`guardrail sync --planes codex`; Codex must trust that project config layer.
Disable removes Guardrail hooks and retains its native escalation rules.

`gen-config codex --floor` prints the native command-escalation floor. Merge and
enable also install it as `rules/guardrail.rules` beside `hooks.json`.

Codex Asks block with guidance because native PreToolUse cannot request approval.
Delegation is denied pending child enforcement evidence. Hosted tools and
continued `write_stdin` input have runtime hook gaps; registration is not proof
of hook trust or complete containment. See [ADR-0014](docs/adr/0014-codex-native-hooks-and-blocked-asks.md)
and [ADR-0016](docs/adr/0016-codex-native-escalation-floor.md).
