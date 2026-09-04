# Recipe scope: four languages, per-edit tier only

Two deliberate cuts from DESIGN.md's full P8 vision.

**Odoo and Elixir are not in the registry.** Odoo's Python files use the
`.py` extension — identical to the generic Python recipe's claim. A recipe
registry keyed purely by extension can't express "this .py file additionally
gets pylint-odoo" without either exclusive-claim conflicts or an
additive-composition model (multiple recipes contributing commands for one
extension, gated by an explicit per-project opt-in — DESIGN.md's Q9 always
intended Odoo/Elixir to be off-by-default, opt-in). Building that
composition model well is its own design work. Elixir's `.ex`/`.exs` don't
collide with anything, but is cut alongside Odoo for the same reason: both
were envisioned as opt-in from the start, and opt-in needs the overlay
`[recipes]` schema this plan didn't build.

**Only the per-edit tier ships.** No `Stop` hook, no `go vet`/`go build`/
`pytest`/`mix test`/`cargo test`/full-project lint runs. Claude Code
supports a `Stop` event (confirmed by this project's own hooks research)
that could carry this, but wiring a new hook event, deciding what "block
session end" means for opencode/Antigravity (neither of which has an
obviously analogous event), and running potentially-slow full-suite
commands from inside a tool-use hook is real additional scope.

## Consequences

- A Go/Python/JS-TS/Rust project gets real, working format+lint enforcement
  today. An Odoo or Elixir project gets nothing recipe-related until a
  follow-up builds the opt-in composition model.
- Nothing here blocks catching a *syntax-breaking* edit at commit/CI time —
  the per-edit formatter often surfaces that anyway (e.g. `gofmt` fails
  loudly on unparseable Go). The session-completion tier's value is deeper
  checks (type errors, failing tests), not just "is broken code possible."
