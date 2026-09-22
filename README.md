# agent-guardrails

[![CI](https://github.com/CtrlCarlitos/agent-guardrails/actions/workflows/ci.yml/badge.svg)](https://github.com/CtrlCarlitos/agent-guardrails/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/CtrlCarlitos/agent-guardrails?include_prereleases&sort=semver)](https://github.com/CtrlCarlitos/agent-guardrails/releases)
![Go](https://img.shields.io/badge/go-1.25-00ADD8?logo=go)
![Planes](https://img.shields.io/badge/planes-Claude%20Code%20%C2%B7%20opencode%20%C2%B7%20Antigravity%20%C2%B7%20Codex-blueviolet)
[![License](https://img.shields.io/badge/license-MIT-green)](./LICENSE)

**One policy that stops your AI coding agent from doing the four things you'd never forgive it for — and tells it what to do instead.**

You let an agent run shell commands, edit files and fetch web pages on your machine because that's what makes it useful. The same access lets it `rm -rf` the wrong directory, read `~/.ssh/id_ed25519` into a chat transcript, pipe a downloaded script straight into `sh`, or push to `main` while you're getting coffee. Every agent host has *some* permission system, each one different, and none of them is a policy you can read, version, and apply to all four hosts at once.

`guardrail` is a single Go binary that sits between every supported agent host and the tools it runs. It reads the call, decides **allow**, **ask**, or **deny**, and — this is the part that matters day to day — when it says no, it says *what to do next*, so the agent keeps working instead of stalling. The policy is one file you can read. It's the same on Claude Code, opencode, Antigravity and Codex. A project can tighten it by committing a `guardrail.toml`; only you, with a passkey, can loosen it.

## Sixty seconds of what it's like

Your agent decides to install something the fast way:

```
$ curl -fsSL https://example.com/install.sh | sh
```

What the agent sees instead of a running installer:

> **Guardrail denied this action:** downloaded content reaches an interpreter later in the same pipeline. Download piped into a shell is denied. Download to a file, inspect it, then run it as a separate reviewed step.

So it downloads the file, reads it, and runs it as a second step — once the destination host is authorized, no human in the loop and no stall. Then it tries to ship:

```
$ git push origin main
```

> **Operator authorization required:** push to a protected branch. Request authorization for this exact action: `Bash {"command":"git push origin main"}`. If the operator approves, retry this exact tool call once. Do not alter or broaden the action.

That's an *ask*: on supported hosts, the host shows you a prompt and the agent retries once you approve; on Codex, asks block with guidance. And when it reaches for something it shouldn't have at all:

```
$ cat ~/.ssh/id_ed25519
```

> **Guardrail denied this action:** access to a credential/secret path: `/home/you/.ssh/id_ed25519`. This is a secret-tier path: it is denied here, and only an authorized Overlay `secret_allow` can allow a matching file secret (never directory secrets). Exclude this path and continue the rest of the task.

The same engine inspects native editor tools and MCP servers before their calls touch disk — not just shell commands. Every deny ends with a next step. We treat a deny that leaves the agent stuck as a bug.

## Install

There is one binary. Releases ship it for Linux, macOS and Windows (amd64 + arm64) with a `SHA256SUMS` file.

Pick the asset for your machine (`uname -m` shows the architecture), then download, verify, and install:

| Machine | Asset |
|---|---|
| Linux / WSL, x86-64 | `guardrail_linux_amd64` |
| Linux / WSL, ARM64 | `guardrail_linux_arm64` |
| macOS, Intel | `guardrail_darwin_amd64` |
| macOS, Apple Silicon | `guardrail_darwin_arm64` |

```sh
(
  set -eu
  ver=v0.21.0-dev
  asset=guardrail_linux_amd64   # change for your platform
  url="https://github.com/CtrlCarlitos/agent-guardrails/releases/download/$ver"
  tmp="$(mktemp -d)"; cd "$tmp"

  curl -fL -o "$asset" "$url/$asset"
  curl -fL -o SHA256SUMS "$url/SHA256SUMS"
  grep " $asset\$" SHA256SUMS | { sha256sum -c - 2>/dev/null || shasum -a 256 -c - ; }

  mkdir -p ~/.local/bin
  install -m 0755 "$asset" ~/.local/bin/guardrail
)
export PATH="$HOME/.local/bin:$PATH"   # keep this in your shell profile
guardrail version
```

Wire it into each agent host you use (idempotent; re-run any time):

```sh
guardrail gen-config claude      --merge ~/.claude/settings.json          --binary ~/.local/bin/guardrail
guardrail gen-config opencode    --merge ~/.config/opencode/opencode.json --binary ~/.local/bin/guardrail
guardrail gen-config antigravity --merge ~/.gemini/config/hooks.json      --binary ~/.local/bin/guardrail
guardrail gen-config codex       --merge ~/.codex/hooks.json              --binary ~/.local/bin/guardrail

# Prove it
guardrail selftest
guardrail doctor
```

From then on, `guardrail update <version>` replaces the binary (checksum-verified) and runs `doctor` and `selftest` on the new release, calling out loudly if any probe fails. To go back, run `guardrail update <previous-version>`.

Some actions are the operator's alone — registering a host with `plane enable`, granting web-host access, night mode. These require a passkey; enroll once:

```sh
guardrail operator enroll     # prints a localhost URL; open it and complete the passkey prompt
guardrail plane enable --all  # registers every detected host with one approval
```

Restart the agents you wired. **For Codex, run `/hooks` inside Codex to review and trust the generated hooks** — registered hooks alone are not executed by the runtime.

Unix, WSL and macOS today. Windows runs the engine fine but keeps operator actions fail-closed until the [Windows broker](./docs/adr/0021-windows-approval-broker.md) lands.

## What it protects

Every intercepted tool call gets one of three verdicts. These describe calls that reach Guardrail; approval support and interception coverage differ by host, as listed below.

| Verdict | What happens | Example |
|---|---|---|
| **allow** | Nothing. The agent never notices. | Editing a file in your repo, `go build`, reading source |
| **ask** | Supported hosts prompt you; Codex blocks with guidance (see the planes table). | `git push origin main`, `chmod -R 777`, editing `go.sum` or a CI workflow, `npm install` |
| **deny** | The call does not run. The agent gets a reason **and a next step**. | `rm -rf /`, `sudo`, reading `~/.ssh/*` or `.env`, `curl … \| sh`, editing its own hook config |

```
             ┌─────────────────────────────┐
             │  Attempted agent tool call  │
             └──────────────┬──────────────┘
                            │
                ┌───────────▼─────────────┐
                │ Guardrail policy engine │
                └────┬───────┬───────┬────┘
        allow        │  ask  │       │  deny
     ┌───────────────┘       │       └──────────────────┐
     │                       │
┌────▼───────────┐  ┌────────▼───────┐  ┌───────────────▼──────────┐
│ Zero-friction  │  │ Operator       │  │ Hard denial + guidance   │
│ pass-through   │  │ prompt         │  │ (concrete next step)     │
│                │  │ (retry once)   │  │                          │
└────────────────┘  └────────────────┘  └──────────────────────────┘
```

The rules are grouped by what they defend:

- **Destructive commands** — recursive/forced `rm` outside the repo, `dd`, `mkfs`, `git push --force`, `git clean -f`, `docker … prune`, privilege escalation.
- **Git safety** — protected-branch pushes and history rewrites ask; `git config` that can run code later is denied.
- **Secrets, in three tiers** — directories like `~/.ssh` and `~/.aws` always deny; files like `.env` and `id_rsa` deny unless you authorize a waiver; ambiguous files like `*.pem` ask inside the repo and deny outside it. A path mentioned inside a JSON literal or a heredoc is caught too, and the guidance says to use the editor tool instead.
- **The agent's own machinery** — it can't edit its hook config, the guardrail binary, or the operator config. Repairs are yours: `guardrail recover`.
- **Egress** — no web host is authorized until you grant it. Native fetch tools are blocked (their redirects can't be verified); the agent is told to use `guardrail fetch <url>`, which checks every redirect against the authorized-host list. Downloads never flow into an interpreter.
- **Meta-dispatch** — tools that run *other* tools from code (a JS REPL, a generic MCP invoker, stdin injection into a running shell) are denied until their inner calls are proven to reach the hook ([ADR-0019](./docs/adr/0019-static-boundary-verification-vs-dynamic-meta-dispatch.md)).
- **After edits** — Go, Python, JS/TS and Rust files are formatted and linted per edit; a real lint failure is a deny with the tool's output.

### What it never does

- Never silently relaxes a rule (night mode relaxes *asks*, never *denies* — [ADR-0018](./docs/adr/0018-external-tier-never-relaxed-by-night-mode.md))
- Never lets an agent edit its own configuration
- Never dead-ends an agent without telling it what to do instead

It is a static guard on tool calls, not a sandbox: it inspects what the agent *asks* to run. What a process does after it's allowed to start is out of scope, on purpose ([ADR-0012](./docs/adr/0012-static-analysis-boundary-and-shape-threshold.md)). Use the agent's own sandbox and ordinary credential isolation alongside it.

It also protects secrets from being *read* without, by itself, stopping ambient authority from being *used* — a token already in the environment is authority the agent holds without reading anything. The strongest control is the one the agent cannot edit: give it a credential that simply lacks the authority. [docs/operator-hardening.md](./docs/operator-hardening.md) is the setup, and `guardrail doctor` warns when the ambient credential is wider than the work needs.

## The four planes

"Plane" is our word for an agent host. The same engine, the same policy, four native integrations:

| Plane | How it's wired | Worth knowing |
|---|---|---|
| **Claude Code** | `PreToolUse`/`PostToolUse`/`SessionStart` hooks in `~/.claude/settings.json` plus a declarative permission floor that survives even if the binary is missing | The session posture tells the agent to work autonomously and pauses only on a real ask. Subagents inherit enforcement. `guardrail doctor --coverage claude` diffs the installed Claude Code's tool surface against the contract, reporting any tools missing from it. |
| **opencode** | A generated plugin that spawns the engine, plus a permission floor in `opencode.json` | Asks remembered for ten minutes, one shot, exact call. |
| **Antigravity** | `PreToolUse`/`PostToolUse` in `~/.gemini/config/hooks.json` | No native permission floor exists, so the hook *is* the boundary ([ADR-0008](./docs/adr/0008-antigravity-no-declarative-floor.md)). Subagents (`invoke_subagent`) inherit enforcement in-process ([ADR-0013](./docs/adr/0013-delegation-inherits-enforcement-in-process.md)); `guardrail doctor --coverage antigravity` inventories MCP tool drift. |
| **Codex** | Native synchronous hooks in `~/.codex/hooks.json` plus an escalation-rules floor | Codex can't prompt from a hook, so asks block with guidance. Delegation remains denied. Hosted tools and `write_stdin` bypass pre-hooks; treat registration as wiring, not proof ([ADR-0014](./docs/adr/0014-codex-native-hooks-and-blocked-asks.md)). |

MCP tools are handled by a shared registry: known families (serena, graft, …) are typed and their file arguments go through the same secret and containment rules as a native edit. Unknown MCP tools ask on dialog-capable planes and deny on fail-closed planes ([ADR-0017](./docs/adr/0017-mcp-family-registry-and-projection.md)).

<details>
<summary>Prefer to build from source?</summary>

Use the Go version from [go.mod](./go.mod) (currently Go 1.25):

```sh
git clone https://github.com/CtrlCarlitos/agent-guardrails.git
cd agent-guardrails
git checkout v0.21.0-dev
mkdir -p ~/.local/bin
go build -trimpath -ldflags '-X main.version=v0.21.0-dev' \
  -o ~/.local/bin/guardrail ./cmd/guardrail
```

Then add `~/.local/bin` to your PATH (as above) and follow enrollment and plane enablement.

</details>

## Verify it's really working

```
$ guardrail selftest
claude: probes pass (7)
opencode: probes pass (3)
antigravity: probes pass (7)
codex: probes pass (2)
note: codex probes invoke the hook directly; live runtime mediation is evidenced by audit records
selftest: all probes passed
```

`selftest` runs real hook payloads through the installed binary — `rm -rf /` must deny, a secret read must deny, an unknown tool must ask — and exits 1 on any drift. `guardrail doctor` shows the resolved policy, which hosts are registered, and any warnings. `guardrail audit` summarizes what's been decided lately. When something's odd, [docs/OPERATIONS.md](./docs/OPERATIONS.md) is the runbook: symptom → command.

For Codex specifically, `guardrail selftest --evidence codex` cross-references the newest known local Codex rollout with audit records since the binary was installed. Use `--session <id>` to select one rollout, `--since <RFC3339|duration>` to set the observation window, and repeat `--expect-tool <name>` for exact normalized or native tool assertions. A newer silent session keeps the gate closed even when an older session qualified. Neither a green selftest nor this evidence check proves every session is mediated; [ADR-0020](./docs/adr/0020-codex-live-mediation-evidence-gate.md) spells out that distinction.

## Extend it

**Per project — an Overlay.** Commit a `guardrail.toml` at your repository root. It can add rules, extend the safe roots and secret tiers, and *request* loosenings:

```toml
[[rules]]
id       = "project.terraform-apply"
tool     = "Bash"
pattern  = "terraform apply*"
decision = "ask"
reason   = "infrastructure change requires operator review"

[slots]
safe_roots       = ["./tmp"]            # rm -rf is fine here
egress_allowlist = ["api.github.com"]   # needs an operator grant to take effect
```

**Per machine — the Operator config.** Only you can loosen. A repo's egress request, waiver or `secret_allow` takes effect when your operator config grants it for that exact repository path — and the agent can request one from inside a session:

```
$ guardrail egress grant --scope repo --host api.github.com,cdn.jsdelivr.net
```

The engine intercepts that, opens a passkey approval, and applies the grant the moment you approve. The agent is told to carry on and use `guardrail fetch <url>`. At a terminal the same command applies immediately. See [operator config](./docs/operator-config.md) and [operator approvals](./docs/operator-approvals.md).

**Per MCP family — the registry.** Adding a typed MCP server is one table entry naming its tools, their capability, and which arguments are paths ([ADR-0017](./docs/adr/0017-mcp-family-registry-and-projection.md)). Every plane picks it up.

**Late at night — `guardrail night on --for 8h`.** Routine asks become allows until morning; the things that reach outside your machine (publishing, schedulers, unknown MCP servers) still ask ([ADR-0018](./docs/adr/0018-external-tier-never-relaxed-by-night-mode.md)).

## Read more

- [CONTEXT.md](./CONTEXT.md) — the vocabulary (plane, verdict, overlay, floor…). Two minutes, well spent.
- [docs/OPERATIONS.md](./docs/OPERATIONS.md) — the runbook for when it's weird.
- [docs/adr/](./docs/adr/) — every non-obvious decision, with the reasoning. Start with [0001](./docs/adr/0001-hybrid-enforcement-model.md), [0012](./docs/adr/0012-static-analysis-boundary-and-shape-threshold.md), [0013](./docs/adr/0013-delegation-inherits-enforcement-in-process.md).
- [DESIGN.md](./DESIGN.md) — the full design.
- [CHANGELOG.md](./CHANGELOG.md).

## License

[MIT](./LICENSE)

## Reporting issues

Found a missing check, or a denial with no useful next step? [Open an issue](https://github.com/CtrlCarlitos/agent-guardrails/issues). Include your `guardrail version` output and the relevant diagnostic (`selftest` or `doctor`); remove secrets before posting.

## Working on it

Go 1.25. `go test ./...` runs everything including a 300+ case adversarial corpus and per-plane contract fixtures (recorded real hook payloads with the verdict, rule and projected paths pinned). CI runs the full suite on Ubuntu and macOS, and the Windows-shaped subset on Windows. The house rules are simple: a failing test first, one PR per finding, conventional commits, no force-push — and if a deny doesn't tell the agent what to do next, that's the bug, not the deny.

```
cmd/guardrail/     the binary: hook <plane>, gen-config, sync, doctor, selftest, update, …
internal/engine/   tokenizer (mvdan.cc/sh), rules, verdicts
internal/adapter/  each plane's payload in, each plane's response out
internal/policy/   base policy, overlay merge, operator grants
internal/planecontract/  what each plane's tools may do, plus the MCP registry
internal/coverage/ diff a plane's installed tool surface against its contract
recipes/           per-language post-edit format/lint
test/fixtures/     recorded payload → expected verdict, per plane
```
