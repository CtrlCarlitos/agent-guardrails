# agent-guardrails

[![CI](https://github.com/CtrlCarlitos/agent-guardrails/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/CtrlCarlitos/agent-guardrails/actions/workflows/ci.yml)
[![Go version](https://img.shields.io/github/go-mod/go-version/CtrlCarlitos/agent-guardrails)](go.mod)

Guardrail checks what your AI coding agent is about to do before it runs a command, reads a file, or makes an edit. It can stop destructive commands, keep credentials out of the conversation, and ask you before sensitive changes. When it blocks something, it tells the agent what to do next—so “fix the tests” can keep moving without becoming “discard my working tree.” One small command-line program brings those checks to Claude Code, OpenCode, Antigravity, and Codex.

## A blocked command should come with a next move

Suppose an agent tries `git reset --hard` while cleaning up a failed change. Guardrail returns:

```text
Guardrail denied this action: git reset --hard/--keep discards the working tree and index irrecoverably.
Protected git state: use a non-destructive alternative (for example git revert instead of reset --hard),
or ask the operator if it is truly required; then continue.
```

The agent should preserve your uncommitted work, inspect the diff, and make a targeted edit. If the task is to undo a committed change, it can consider `git revert`. Rephrasing the same destructive command is not the next step.

Every checked action gets one of three answers:

| Answer | What happens | What the agent does next |
| --- | --- | --- |
| **Allow** | The action can proceed. | Continue the task. |
| **Ask** | The action needs your authorization. | Explain the exact action, get approval through the available host flow, and retry that action once where supported. |
| **Deny** | This action is blocked. | Follow the alternative in the message, or leave that step to you and continue other work. |

Checks cover destructive shell operations, risky Git changes, secret files such as `.env` and SSH keys, writes to Guardrail's own configuration, and network access. For example, an agent denied access to `.env` can work from `.env.example` and ask you for redacted diagnostics.

Approval support differs by agent. In particular, **Codex currently blocks Asks with guidance**; an approved retry flow is not implemented there. A Deny is never turned into an Allow merely because you retry it.

## Install without dotfiles

The setup below is for **Linux, macOS, or WSL**, from your own terminal. Install the coding agent you want to use first. Guardrail does not install the agents.

Download a binary and its checksum from the [releases page](https://github.com/CtrlCarlitos/agent-guardrails/releases). No Go toolchain is needed. This example pins `v0.20.27-dev`; choose an exact release deliberately when updating it.

Pick the asset for your machine (`uname -m` shows its architecture):

| Machine | Asset |
| --- | --- |
| Linux / WSL, x86-64 | `guardrail_linux_amd64` |
| Linux / WSL, ARM64 | `guardrail_linux_arm64` |
| macOS, Intel | `guardrail_darwin_amd64` |
| macOS, Apple Silicon | `guardrail_darwin_arm64` |

Change `guardrail_asset` below if you are not on Linux x86-64. This downloads into a temporary directory, checks the selected file, and installs it in your user's bin directory:

```sh
(
  set -eu
  guardrail_version=v0.20.27-dev
  guardrail_asset=guardrail_linux_amd64
  guardrail_url="https://github.com/CtrlCarlitos/agent-guardrails/releases/download/$guardrail_version"
  guardrail_download="$(mktemp -d)"
  cd "$guardrail_download"

  curl -fL -o "$guardrail_asset" "$guardrail_url/$guardrail_asset"
  curl -fL -o SHA256SUMS "$guardrail_url/SHA256SUMS"
  awk -v name="$guardrail_asset" '$2 == name { print }' SHA256SUMS > CHECKSUM
  test -s CHECKSUM
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum -c CHECKSUM
  else
    shasum -a 256 -c CHECKSUM
  fi

  mkdir -p "$HOME/.local/bin"
  install -m 0755 "$guardrail_asset" "$HOME/.local/bin/guardrail"
)
export PATH="$HOME/.local/bin:$PATH"
guardrail version
```

Keep `~/.local/bin` on your shell's PATH for future terminals, too. The expected version line for this example is `guardrail v0.20.27-dev`.

Next, enroll a passkey or security key and enable the agent you use:

```sh
guardrail operator enroll
guardrail plane enable claude
```

Each approval command prints a localhost URL. Open it yourself in your browser, review the action, and complete the passkey prompt. Enrollment is a one-time setup per machine; [operator approvals](docs/operator-approvals.md) covers SSH port forwarding and recovery.

Replace `claude` with `opencode`, `antigravity`, or `codex`. To enable all detected agents:

```sh
guardrail plane enable --all
```

Restart the affected agents after setup. **For Codex, review and trust the generated hooks with `/hooks`**, then restart. Registered hooks alone do not mean the runtime executes them.

Windows binaries (`guardrail_windows_amd64.exe` and `guardrail_windows_arm64.exe`) are also published. Native Windows approval and lifecycle support is still being completed; do not treat the Unix setup above as a PowerShell recipe. See the [Windows status and handover](docs/windows-handover.md). WSL can use the Linux setup.

<details>
<summary>Prefer to build from source?</summary>

Use Git and the Go version specified in [go.mod](go.mod), currently Go 1.25:

```sh
git clone https://github.com/CtrlCarlitos/agent-guardrails.git
cd agent-guardrails
git checkout v0.20.27-dev
mkdir -p "$HOME/.local/bin"
go build -trimpath -ldflags '-X main.version=v0.20.27-dev' \
  -o "$HOME/.local/bin/guardrail" ./cmd/guardrail
export PATH="$HOME/.local/bin:$PATH"
```

Then follow enrollment and plane enablement above. For development, `go test ./...` runs the test suite; see [CI](.github/workflows/ci.yml) for platform-specific checks.

</details>

## Install with CtrlCarlitos dotfiles

[CtrlCarlitos/dotfiles](https://github.com/CtrlCarlitos/dotfiles) includes Guardrail as a selectable package. This route also manages your shell configuration and the other packages you select.

For a new dotfiles setup on Linux/macOS/WSL:

```sh
git clone https://github.com/CtrlCarlitos/dotfiles.git
cd dotfiles
bash install.sh
```

Choose **guardrail** in the package menu (the standard preset includes it). The installer downloads its pinned, checksum-verified release and enables detected agents. It does not enroll an authenticator for you. If the first apply stops because enrollment is missing, run:

```sh
guardrail operator enroll
chezmoi apply
```

Already using these dotfiles? Change your selection and apply it:

```sh
bash "$(chezmoi source-path)/scripts/select-packages.sh"
chezmoi apply
```

The opt-in is `guardrail = true` under `[data.packages]` in your chezmoi config. The release pin belongs to the dotfiles repository; a later apply follows that pin. Details: [dotfiles install strategy](https://github.com/CtrlCarlitos/dotfiles/blob/main/docs/guardrail-install.md).

## Check it, then get back to work

```sh
guardrail selftest       # Does the installed evaluator give the expected answers?
guardrail doctor         # Which policies and agent integrations are active?
guardrail audit          # What decisions have been recorded?
```

Look for `selftest: all probes passed` and registered integrations for the agents you enabled. Missing integrations for agents you do not use are expected. If a probe fails, keep its named failure and your `guardrail version` output; the [operations runbook](docs/OPERATIONS.md) is the next stop.

Guardrail calls supported coding-agent hosts **planes**. All four use the shared policy, with different runtime boundaries:

| Plane | Integration | Boundary to know |
| --- | --- | --- |
| Claude Code | Hooks and native permission rules | Session-start diagnostics can flag newly discovered tools that lack a classification. |
| OpenCode | Plugin and native permission rules | Some Asks use its permission dialog; uncovered cases use the documented exact-retry fallback. |
| Antigravity | Pre/post tool hooks | No independent native permission floor; the hooks are the enforcement path. |
| Codex | Native hooks and limited command-escalation rules | Hosted tools and continued `write_stdin` input have pre-hook gaps. Delegation remains denied. |

For Codex, also run:

```sh
guardrail selftest --evidence codex
```

Exit 0 means the audit heuristic found qualifying live-mediation evidence; exit 1 means not yet, with counts. Synthetic selftest records do not qualify. Neither a green selftest nor this evidence check proves that every session or tool is mediated. [ADR-0020](docs/adr/0020-codex-live-mediation-evidence-gate.md) spells out that distinction.

Guardrail inspects actions that reach these integrations. It is not an operating-system sandbox: arbitrary code running as your user can conceal effects from static inspection. Use the agent's sandbox and ordinary credential isolation alongside it.

For a later standalone update, select an exact release and run `guardrail update <version>`. The updater verifies its checksum, replaces the binary, and runs doctor and selftest on the new release. Run `guardrail plane enable --all` to refresh registered configuration when needed.

## Make it fit your project

Start with the shipped policy. Add project-specific rules only when you have something concrete to protect.

**Overlay:** put `guardrail.toml` at your repository root. For example, treat a project-specific credential file as secret:

```toml
[slots]
secret_globs = ["**/partner-credentials.json"]
```

Then check and regenerate the project's agent configuration:

```sh
guardrail doctor
guardrail sync --planes claude
```

Use the plane names you work with; Codex still needs to trust the resulting hooks. An Overlay adds to the base policy. It cannot silently grant itself weaker protection.

**Operator config:** exceptions need your authorization outside the repository, usually in `~/.config/guardrail/waivers.toml`. For example, a website grant is tied to the exact repository and host. The repository's request and your grant must both agree. See [Operator config](docs/operator-config.md) for worked examples and boundaries.

**MCP registry:** when an agent gets a tool from an MCP server, Guardrail needs to know whether it reads files, changes them, or does something external—and which arguments contain paths. Add that classification to [the shared registry](internal/planecontract/mcp.go), with tests. A tool that edits `.env` should hit the secret-path rule even when it arrived through a different server. Unknown tools are handled differently across planes; do not assume every new tool is automatically protected.

## Keep these links nearby

- [Operations runbook](docs/OPERATIONS.md): blocked actions, approvals, drift, updates, and recovery.
- [Architecture decisions](docs/adr/): why the boundaries are where they are.
- [CONTEXT.md](CONTEXT.md): the project's vocabulary.
- [Design](DESIGN.md) and [changelog](CHANGELOG.md): deeper mechanics and what changed.
- [Issues](https://github.com/CtrlCarlitos/agent-guardrails/issues): report a missing check or a denial with no useful next step. Include the version and relevant diagnostic output; remove secrets before posting.
