# Recipe composition and trigger scope

P8 Recipes have two independent trigger tiers. The per-edit tier runs after a
supported write tool changes a matching file. The session-completion tier runs
only when the host reports that the session or subagent is stopping. A Recipe
may implement either or both tiers.

## Project configuration and composition

Go, Python, JavaScript/TypeScript, Rust, and Elixir Recipes match their file
extensions automatically. Odoo is an explicit, additive opt-in because its
Python and JavaScript files also belong to the generic Recipes. An Overlay opts
in with all three project values:

```toml
[recipes.odoo]
module = "sale_guardrail"
test_database = "guardrail_test"
relax_ng = "schema/import_xml.rng"
```

`module` and `test_database` are literal command arguments. `relax_ng` is a
literal repository-relative file path. Missing, dynamic, absolute, escaping,
or unknown Recipe values fail while loading the Overlay. Commands receive these
values directly as argument-vector entries; Recipes do not expand a shell or
infer them from environment variables. This preserves the P3 rule that an
unresolved value cannot silently become authorization.

Odoo contributes checks in addition to the automatic Recipe for the edited
file. Opting in never suppresses Python or JavaScript/TypeScript checks.

## Plane support

Per-edit Recipes continue to run at the Engine's post-write seam on supported
planes. Session completion is exposed only through Claude's `Stop` and
`SubagentStop` events. OpenCode, Antigravity, and Codex do not currently expose
an equivalent Guardrail trigger and are reported by `guardrail doctor` as
unsupported; registration or per-edit coverage must not be described as
session-completion coverage.

Doctor derives installed Recipe names from the Recipe registry and separately
reports configuration, execution availability, and unsupported planes. Schema
and doctor visibility ship together so an accepted Recipe configuration cannot
be invisible to the operator.

## Delivery sequence

The schema and doctor contract land first. Session completion, Elixir, and Odoo
execution then land as separate milestones, each adding its behavior to the
same registry-backed diagnostic surface.
