# agent-guardrails

[![CI Status](https://github.com/CtrlCarlitos/agent-guardrails/actions/workflows/ci.yml/badge.svg)](https://github.com/CtrlCarlitos/agent-guardrails/actions)
[![Release](https://img.shields.io/github/v/release/CtrlCarlitos/agent-guardrails?include_prereleases)](https://github.com/CtrlCarlitos/agent-guardrails/releases)
[![Go Version](https://img.shields.io/github/go-mod/go-version/CtrlCarlitos/agent-guardrails)](https://golang.org)
[![Planes](https://img.shields.io/badge/planes-claude%20%7C%20opencode%20%7C%20antigravity%20%7C%20codex-blue)](https://github.com/CtrlCarlitos/agent-guardrails)
[![License](https://img.shields.io/badge/license-MIT-green)](https://github.com/CtrlCarlitos/agent-guardrails)

> **Universal pre-execution security guardrails for autonomous AI coding agents.**  
> Protect your machine, your repositories, and your secrets across Claude Code, OpenCode, Antigravity, and Codex.

---

## What It Is

When you give an AI coding agent a terminal and filesystem tools, you hand it the keys to your workstation. A single hallucinated command (`rm -rf /`), an accidental credential dump (`.env`, `~/.ssh/id_rsa`), an uninspected force push, or an opaque MCP meta-tool can corrupt your repository or compromise private tokens in milliseconds. 

**`guardrail`** is a single, lightning-fast Go binary that intercepts every tool invocation *before* it runs on your system. It evaluates attempted actions against a unified, deterministic security policy—letting safe operations proceed with sub-millisecond overhead, asking for human confirmation on high-impact operations, and strictly denying dangerous actions with **actionable guidance** so the agent can self-correct without dead-ending your session.

---

## The Four Planes Guarded Today

Different AI agents expose different hook systems. Guardrail bridges them into a single, unified security perimeter:

| Agent Plane | Integration Mechanism | Hook Lifecycle | Delegation Handling |
| :--- | :--- | :--- | :--- |
| **Claude Code** | Native CLI command hooks (`settings.json`) | `PreToolUse` & `PostToolUse` | In-process inheritance (subagents mediated) |
| **OpenCode** | Embedded JavaScript plugin (`opencode.json`) | Synchronous plugin interception | Non-blocking host dialogs & approval memory |
| **Antigravity** | Native command hooks (`hooks.json`) | PreToolUse & PostToolUse (`*` matcher) | In-process inheritance ([ADR-0013](./docs/adr/0013-delegation-inherits-enforcement-in-process.md)) |
| **Codex** | Native synchronous hooks (`hooks.json`) | PreToolUse command interception | Direct hook verification + audit evidence |

---

## The Verdict Model: Allow, Ask, Deny

Guardrail evaluates every attempted command, path access, and network query into one of three verdicts:

```
                  ┌──────────────────────────────┐
                  │ Attempted Agent Tool Call    │
                  └──────────────┬───────────────┘
                                 │
                     ┌───────────▼────────────┐
                     │ Guardrail Policy Engine│
                     └─────┬────────────┬─────┘
          allow            │            │            deny
      ┌────────────────────┘    ask     └───────────────────┐
      │                          │                          │
┌─────▼───────────────┐ ┌────────▼───────────┐ ┌────────────▼────────────────┐
│ Zero-Overhead Pass  │ │ Human Confirmation │ │ Hard Denial + Guidance      │
│ • Benign edits      │ │ • Web searches     │ │ • Secret paths (.env, .ssh) │
│ • Non-secret reads  │ │ • Cron schedules   │ │ • Destructive bash (rm, git)│
│ • Local formatting  │ │ • External reach   │ │ • Opaque meta-dispatch      │
└─────────────────────┘ └────────────────────┘ └─────────────────────────────┘
```

- **`allow`**: Safe operations run unimpeded. Formatting, unit tests, repository reads, and safe control primitives execute with sub-millisecond latency.
- **`ask`**: High-impact or outward-reaching operations require operator approval. In **Night Mode** (`guardrail night on`), routine in-session asks relax to allow unattended overnight work, while outward-reach asks (schedulers, unknown MCP servers, web access) remain strictly preserved ([ADR-0018](./docs/adr/0018-external-tier-never-relaxed-by-night-mode.md)).
- **`deny`**: Hard-stop rejections for invariant violations. Denials are **never silent rejections**—Guardrail emits concrete, model-facing guidance that explains *why* the action was blocked and redirects the agent to safe alternatives.

### Show, Don't Tell: How Denials Guide the Agent

#### Example 1: Preventing Credential Access
When an agent tries to inspect a protected secret file:

```json
// Agent Tool Call
{"name": "view_file", "args": {"AbsolutePath": "/project/.env"}}
```

```json
// Guardrail Intercept Response
{
  "decision": "deny",
  "reason": "Guardrail denied this action: '.env' matches protected File Secret tier (P4). Do not read or output secrets. Inspect '.env.example' or mock credentials instead."
}
```

**What the agent does next**: Instead of crashing or repeatedly retrying, the agent parses the guidance, understands that `.env` is off-limits, and immediately redirects to `.env.example`:
> *"I cannot view `.env` as it contains private credentials. Let me check `.env.example` instead to see the required environment keys."*

#### Example 2: Blocking Irreversible Git History Loss
When an agent attempts a destructive reset:

```json
// Agent Tool Call
{"name": "run_command", "args": {"CommandLine": "git reset --hard HEAD~1"}}
```

```json
// Guardrail Intercept Response
{
  "decision": "deny",
  "reason": "Guardrail denied this action: 'git reset --hard/--keep' discards the working tree and index irrecoverably. Use non-destructive alternatives like 'git stash' or 'git revert'."
}
```

**What the agent does next**: The agent adapts and stashes its changes cleanly.

---

## Installation & Setup

### Standalone (Direct Install)

1. **Install the binary**:
   ```bash
   # Download the latest release binary:
   curl -fsSL https://raw.githubusercontent.com/CtrlCarlitos/agent-guardrails/main/scripts/install.sh | bash

   # Or compile directly with Go (1.24+):
   go install github.com/CtrlCarlitos/agent-guardrails/cmd/guardrail@latest
   ```

2. **Register your coding planes**:
   ```bash
   # Enable all detected planes with operator passkey verification:
   guardrail plane enable --all

   # Or enable an individual plane:
   guardrail plane enable claude
   guardrail plane enable antigravity
   ```

3. **Verify the installation**:
   ```bash
   guardrail doctor
   ```

### With CtrlCarlitos Dotfiles

If you use the `CtrlCarlitos` dotfiles ecosystem, Guardrail is wired globally via Chezmoi:
- The binary is deployed to `~/.local/bin/guardrail`.
- Base policy and global hooks are managed declaratively.
- Releases and updates sync automatically with dotfile management.

---

## Quick Verification

Guardrail provides two built-in commands to prove everything is working:

### 1. `guardrail selftest` — Behavioral Verification
Runs **16 embedded behavioral probes** across all four planes directly through the installed binary's evaluation path:

```bash
$ guardrail selftest
claude: probes pass (7)
opencode: probes pass (3)
antigravity: probes pass (7)
codex: probes pass (2)
note: codex probes invoke the hook directly; live runtime mediation is evidenced by audit records
selftest: all probes passed
```
*Validates that destructive commands are blocked, secret reads fail closed, MCP arguments project properly, and ADR-0019 meta-dispatch invariants hold.*

### 2. `guardrail doctor` — Structural & Inventory Auditing
Checks policy configuration, active waivers, operator WebAuthn state, and installed hook registrations:

```bash
$ guardrail doctor
guardrail v0.20.27-dev
cwd: /home/user/projects/my-app
GUARDRAIL_CONFIG: (unset)
overlay: none
policy warnings: none
waivers: none
audit log: ~/.local/state/guardrail/audit.jsonl
operator approvals: WebAuthn
claude settings: guardrail hook registered
opencode settings: guardrail integration registered
codex settings: guardrail hooks registered
antigravity settings: guardrail integration registered
```

You can also run tool coverage audits to verify your plane has zero uncontracted tools:
```bash
guardrail doctor --coverage antigravity
guardrail doctor --coverage claude
```

---

## Extending Guardrail

### 1. Repository Overlays (`guardrail.toml`)
Layer project-specific rules in your repository root:
```toml
# guardrail.toml (committed to your repo)
[paths]
safe_roots = ["docs/", "tests/fixtures/"]
custom_secrets = ["config/private_keys.json"]

# Request permission to waive a base rule (requires operator authorization)
waive = ["P8.format-lint"]
```

### 2. Operator Authorization (`operator.toml`)
Machine-level authority outside of any repository. Authorizes specific repository loosening requests or network egress domains using WebAuthn passkeys:
```bash
# Authorize outbound network access for guardrail fetch
guardrail egress grant --scope repo --host api.github.com,registry.npmjs.org
```

### 3. Model Context Protocol (MCP) Registry
Guardrail includes a central MCP family registry ([ADR-0017](./docs/adr/0017-mcp-family-registry-and-projection.md)). Known servers (e.g. `serena`, `graft`) have their path arguments projected into Engine policies automatically—ensuring that an MCP tool attempting to write to `.env` is blocked just like a native edit.

Generic meta-dispatchers (`call_mcp_tool`, `tool_caller`, `write_stdin`) fail closed by contract ([ADR-0019](./docs/adr/0019-static-boundary-verification-vs-dynamic-meta-dispatch.md)) to prevent argument concealment.

---

## Documentation & Architecture

- **[CONTEXT.md](./CONTEXT.md)**: Ubiquitous language, core domain entities, and glossary.
- **[docs/OPERATIONS.md](./docs/OPERATIONS.md)**: Operator runbook — symptom-to-command table, debugging, and incident response.
- **[docs/adr/](./docs/adr/)**: Architectural Decision Records documenting all design choices:
  - `ADR-0001`: Hybrid enforcement model
  - `ADR-0008`: Antigravity hook architecture & no declarative floor
  - `ADR-0013`: Delegation inheritance in-process
  - `ADR-0017`: Central MCP family registry & argument projection
  - `ADR-0018`: External tier never relaxed by night mode
  - `ADR-0019`: Static boundary verification vs dynamic meta-dispatch

---

## License

MIT © [Carlitos Melgar](https://github.com/CtrlCarlitos)
