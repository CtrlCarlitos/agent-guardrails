# agent-guardrails

**One guardrail policy across every AI coding agent you use.**

You work with multiple AI coding agents — Claude Code, OpenCode, Antigravity,
Codex. Each has its own permission system, its own config format, its own
way of asking "are you sure?" And each one, left unconfigured, will happily
read your SSH keys, pipe curl into sh, or push --force to main.

agent-guardrails is a single binary that enforces one security policy across
all of them. It intercepts tool calls before they execute, evaluates them
against a policy you control, and returns a verdict: **allow**, **ask**, or
**deny** — with instructions telling the agent what to do instead of just
blocking it.

## What it looks like

When an agent tries something destructive, it doesn't get a wall. It gets
direction:

```
Guardrail denied this action: rm -rf /
Destructive operation: do not retry it. Use a scoped, reversible
alternative, or ask the operator to run it manually; then continue the task.
```

When it tries to read a secret:

```
Guardrail denied this action: access to a credential/secret path: ~/.ssh/id_ed25519
This is a secret-tier path: it is denied here. Exclude this path and
continue the rest of the task.
```

When it needs permission for something reasonable:

```
Operator authorization required: edit of a CI lockfile — this code runs
later with more privilege. Request authorization for this exact action.
```

The agent keeps working. The operator stays in control. Nothing dead-ends.

## Quick start

### Standalone (no dotfiles required)

```bash
# Download the pinned release (checksum-verified)
curl -fLo guardrail https://github.com/CtrlCarlitos/agent-guardrails/releases/download/v0.21.0-dev/guardrail_linux_amd64
curl -fLo SHA256SUMS https://github.com/CtrlCarlitos/agent-guardrails/releases/download/v0.21.0-dev/SHA256SUMS
grep " guardrail_linux_amd64$" SHA256SUMS | sha256sum -c -
chmod +x guardrail && mv guardrail ~/.local/bin/

# Wire into your agent (pick the ones you use)
guardrail gen-config claude --merge ~/.claude/settings.json --binary ~/.local/bin/guardrail
guardrail gen-config opencode --merge ~/.config/opencode/opencode.json --binary ~/.local/bin/guardrail
guardrail gen-config antigravity --merge ~/.gemini/config/hooks.json --binary ~/.local/bin/guardrail

# Verify
guardrail doctor
guardrail selftest
```

### With CtrlCarlitos dotfiles

If you use the [chezmoi dotfiles](https://github.com/CtrlCarlitos/dotfiles),
guardrail is installed and reconciled automatically. Set the flag:

```toml
[data.packages]
guardrail = true    # enable enforcement
guardrail = false   # disable enforcement (binary stays installed)
```

Then `chezmoi apply` handles everything — install, plane wiring, drift
detection, and verification.

## What it guards

| Plane | Status | What's protected |
|---|---|---|
| Claude Code | ✅ | Hooks + permissions floor, delegation, MCP tools, artifacts |
| OpenCode | ✅ | Plugin + permission floor, typed capabilities, MCP registry, host-dialog approvals |
| Antigravity | ✅ | Hooks (no declarative floor — ADR-0008), typed paths, MCP registry, timers |
| Codex | ✅ | Hooks + escalation floor, fail-closed posture, live-mediation gate |

### The policy model

- **Deny** — destructive commands, secret files, protected machinery, egress
  to unauthorized hosts. Every deny carries a concrete next step so the agent
  continues working safely.
- **Ask** — CI lockfile edits, out-of-repo writes, unknown MCP tools,
  scheduled tasks. The operator decides per call.
- **Allow** — everything else. The guard stays silent.

### What it never does

- Never silently relaxes a rule (night mode relaxes *asks*, never *denies*)
- Never lets an agent edit its own configuration
- Never dead-ends an agent without telling it what to do instead

## Verification

The system verifies itself:

```bash
guardrail selftest           # 19 behavioral probes across all planes
guardrail doctor             # wiring, drift, coverage, posture
guardrail doctor --coverage claude    # scan the installed Claude Code bundle
guardrail audit              # summarize the decision log
```

Every invariant is pinned by a test: delegation inheritance, MCP path
projection, night-mode preservation, meta-dispatch denial. If any of them
regress, `selftest` catches it in milliseconds.

## Extending

- **Per-project rules**: commit a `guardrail.toml` (Overlay) to tighten,
  extend, or request waivers for the base policy
- **Machine-level authorization**: the Operator config grants specific
  loosening requests per repository path — nothing is loosened silently
- **MCP tools**: known server families (serena, graft) are typed with real
  path evaluation; unknown MCP tools ask rather than silently allowing
- **New planes**: add a contract in `internal/planecontract/`, an adapter,
  and the lifecycle + diagnostics come along

## Documentation

- [Operations runbook](docs/OPERATIONS.md) — what to do when something looks wrong
- [Architecture decisions](docs/adr/) — 21 ADRs covering every design choice
- [Domain glossary](CONTEXT.md) — the vocabulary the codebase uses
- [Windows handover](docs/windows-handover.md) — the next platform

## Development

```bash
go build ./cmd/guardrail
go test ./...
go vet ./...
```

CI runs the full suite on Linux, macOS, and Windows. All release binaries
are checksum-verified against SHA256SUMS.

## License

[MIT](LICENSE)
