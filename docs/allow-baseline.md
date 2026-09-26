# Allow baseline for Claude Code

Claude Code prompts before running a shell command unless a rule in the
`permissions.allow` list of your settings file covers it. That list is yours:
ADR-0028 says settings files belong to the operator, and guardrail does not
write to it. Guardrail's Engine blocks what it blocks and stays silent about the
rest; it never approves anything, and an allow rule you add does not turn a
guardrail denial into an allow.

This page is a list you can review and paste. `guardrail allow-baseline` prints
it with the reason for each rule, `guardrail allow-baseline --check` compares it
with your file, and `guardrail doctor` carries one summary line.

## What "safe" means here

The definition is one you have already accepted. The recipe registry
(`internal/recipe`) lists the verification commands guardrail itself runs for you
at session end: `go build|test`, `ruff check`, `mypy`, `pytest`, `tsc`, `eslint`,
`npm test`, `cargo test`, `mix test`. Those are the baseline, derived from the
registry so the two cannot disagree. A test run executes the repo's own code, and
that trust is already extended at session end.

Added to it: read-only package queries (`pip list`, `pip show`, `npm ls`) and
graft's read-only, local subcommands.

## What is deliberately not in it

- **Any install or add** (`pip install`, `npm install`, `uv sync`, `poetry
  install`, `go install`, ...): they fetch from a registry.
- **Remote launchers** (`npx`, `bunx`, `uvx`, `pipx`, `dlx`, `exec`): they download
  and run a package that may not be local.
- **Arbitrary code** (`node <file>`, `node -e`, `python <file>`, `python -c`,
  `python -m`, `npm run <anything>`, `go run`, `cargo run`).
- **graft's mutating subcommands.** `graft init` writes agent instruction files,
  MCP config and Claude hooks; `upgrade` runs `npm install -g`; `uninstall`
  removes them; `build --deep` sends code to an LLM provider with an API key;
  `viz` and `telemetry` are not queries. graft is allowed **by subcommand**, and
  `graft build` only as an exact rule. A blanket `Bash(graft:*)`,
  `Bash(graft-dev:*)` or `Bash(npx graft:*)` also covers all of those.

A rule is a prefix, so it cannot exclude a flag (`Bash(graft build:*)` would also
match `graft build --deep`). That is why a few entries are exact, and why the
Engine, not the pattern, is the thing that asks for the dangerous variants.

## Your own narrow entries

Keep them. A rule that names one script, such as `Bash(node dist/cli.js:*)`, is
narrow and is not flagged. `guardrail allow-baseline --check` only reports rules
that also match something the baseline leaves out, with the reason.

## The list

Merge this into `permissions.allow` of `~/.claude/settings.json` if you want it.
It is generated: `guardrail allow-baseline --json` prints exactly this block, and
a test fails if this page and the code disagree.

```json
{
  "permissions": {
    "allow": [
      "Bash(go build:*)",
      "Bash(go test:*)",
      "Bash(golangci-lint run:*)",
      "Bash(govulncheck:*)",
      "Bash(ruff check:*)",
      "Bash(mypy:*)",
      "Bash(pytest:*)",
      "Bash(tsc:*)",
      "Bash(eslint:*)",
      "Bash(npm test:*)",
      "Bash(cargo fmt --all -- --check)",
      "Bash(cargo clippy:*)",
      "Bash(cargo test:*)",
      "Bash(mix compile:*)",
      "Bash(mix test:*)",
      "Bash(go vet:*)",
      "Bash(ruff format --check:*)",
      "Bash(prettier --check:*)",
      "Bash(npm run lint:*)",
      "Bash(npm run build:*)",
      "Bash(pip list:*)",
      "Bash(pip show:*)",
      "Bash(npm ls:*)",
      "Bash(graft ask:*)",
      "Bash(graft grep:*)",
      "Bash(graft skeleton:*)",
      "Bash(graft callers:*)",
      "Bash(graft map:*)",
      "Bash(graft blast:*)",
      "Bash(graft check:*)",
      "Bash(graft stats:*)",
      "Bash(graft version:*)",
      "Bash(graft build)",
      "Bash(graft-dev ask:*)",
      "Bash(graft-dev grep:*)",
      "Bash(graft-dev skeleton:*)",
      "Bash(graft-dev callers:*)",
      "Bash(graft-dev map:*)",
      "Bash(graft-dev blast:*)",
      "Bash(graft-dev check:*)",
      "Bash(graft-dev stats:*)",
      "Bash(graft-dev version:*)",
      "Bash(graft-dev build)"
    ]
  }
}
```

## Related

- `#381`: the Engine asks about `pip install` and `npm install` but not yet about
  every other spelling of an install or a remote launch. Until that lands, the
  absence of such a rule from your allow list is the only thing that makes Claude
  Code prompt for them.
- ADR-0028: settings files are user-owned.
