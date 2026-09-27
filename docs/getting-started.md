# Getting started

From nothing installed to a machine you can check in one glance. It takes
about fifteen minutes. The [README](../README.md) says what guardrail is;
this page walks you through the first day with it.

## 1. Install

Pick an exact release tag from the
[releases page](https://github.com/CtrlCarlitos/agent-guardrails/releases).
The installer refuses `latest`. The examples use `v0.23.12-dev`; put your tag
in its place.

Linux, macOS and WSL:

```sh
(
  set -eu
  ver=v0.23.12-dev   # the release you want
  url="https://github.com/CtrlCarlitos/agent-guardrails/releases/download/$ver"
  tmp="$(mktemp -d)"; cd "$tmp"

  curl -fL -o install.sh "$url/install.sh"
  curl -fL -o SHA256SUMS "$url/SHA256SUMS"
  grep " install.sh\$" SHA256SUMS | { sha256sum -c - 2>/dev/null || shasum -a 256 -c - ; }

  sh install.sh --version "$ver"
)
```

Windows (Windows PowerShell 5.1 or PowerShell 7):

```powershell
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12  # Windows PowerShell 5.1 may default to TLS 1.0/1.1
$ver = 'v0.23.12-dev'   # the release you want
$url = "https://github.com/CtrlCarlitos/agent-guardrails/releases/download/$ver"
Set-Location (New-Item -ItemType Directory -Force -Path (Join-Path $env:TEMP "guardrail-$ver"))

Invoke-WebRequest -UseBasicParsing -Uri "$url/install.ps1" -OutFile install.ps1
Invoke-WebRequest -UseBasicParsing -Uri "$url/SHA256SUMS" -OutFile SHA256SUMS
$want = ((Select-String -Path SHA256SUMS -Pattern ' install\.ps1$').Line -split '\s+')[0]
if ((Get-FileHash -Algorithm SHA256 install.ps1).Hash -ne $want) { throw 'install.ps1 does not match SHA256SUMS' }

powershell -ExecutionPolicy Bypass -File .\install.ps1 -Version $ver
```

Run the downloaded file as shown. Do not pipe it into a shell: the script
exits on failure and hands your terminal to `guardrail setup`.

The binary lands in `~/.local/bin` (`%USERPROFILE%\.local\bin` on Windows).
On Linux and macOS, make sure that directory is on your `PATH`. Check it:

```sh
guardrail version
```

## 2. Setup and your passkey

The installer ends by running `guardrail setup`. Setup registers guardrail
with every agent host it finds (Claude Code, opencode, Antigravity, Codex),
then runs `guardrail selftest`.

On a first install no passkey exists yet, so there is nothing to approve
against. Setup arms the hosts anyway and prints, for example:

```
claude enabled (bootstrap: no operator enrolled)
setup: planes armed without an approval because no operator authenticator is enrolled.
setup: run 'guardrail operator enroll' from a real terminal to take control; every later plane change needs your passkey.
``` Only turning
protection **on** works this way. Turning it off or loosening it waits for a
passkey ([ADR-0030](adr/0030-first-install-bootstrap-arms-without-approval.md)).

Now enroll, from your own terminal (not from inside an agent session):

```sh
guardrail operator enroll
```

It prints:

```
guardrail: open operator approval page:
http://localhost:<port>
```

Open that URL yourself in the browser you trust. Guardrail never opens a
browser for you. Complete the passkey prompt: Windows Hello, a password
manager passkey or a physical security key. The command then prints
`guardrail: authenticator enrolled`. If you work over SSH, forward the port
first ([operator-approvals.md](operator-approvals.md)).

A passkey only works for the guardrail it was enrolled with. A Windows and a
WSL install on one machine each need their own. A phone cannot approve for
`localhost`; choose this device when the browser asks.

Restart the agents you wired so they load the hooks. **For Codex, run
`/hooks` inside Codex and trust the generated hooks.** Codex does not run
hooks you have not reviewed.

## 3. Your first approval

From now on, changes to guardrail itself need your passkey. Run setup again
to see one:

```sh
guardrail setup
```

If every host is already registered and current, it prints `already
enabled` and asks for nothing. If one needs registering again, it prints:

```
claude: approval required; open http://localhost:<port>
```

Open the page. It shows the exact action, the repository path, the scope and
when the request expires. Read them, then complete the passkey prompt. The
page ends with `Approved: plane-enable completed. You may close this page.`
and the command carries on.

The same page appears for `guardrail plane enable|disable`, `guardrail
recover`, `guardrail web-research on|off` and web-host grants. An agent can
never approve for you. It is denied from running `setup`, `plane`,
`recover`, `operator` or `night on|off` itself. When it runs `guardrail
egress grant`, guardrail turns that into an approval request that waits for
your passkey.

## 4. Check the machine

Two commands tell you where you stand.

```sh
guardrail doctor
```

Doctor prints the policy, each host's registration and any warnings. Read
the **last line**:

- `verdict: healthy`: nothing needs you.
- `verdict: 2 problems (see above)`: read the lines above it. Each problem
  names its fix; [OPERATIONS.md](OPERATIONS.md#symptom--command) maps each
  one to a command.

Doctor exits 0 whatever the verdict. `guardrail selftest` is the check that
fails (exit 1) when enforcement drifted; it should end with
`selftest: all probes passed`.

One line is not a fault on a fresh install:
`guardrail hook registered but NEVER OBSERVED FIRING`. It means no real
session has used the hook yet. It clears after your first agent session.
`guardrail selftest --evidence claude` confirms it.

```sh
guardrail next
```

Next prints what you still owe the machine, in order, and nothing when
nothing is owed:

```
next steps:
  1. claude: registered handlers differ from this binary; re-enabling. Run `guardrail plane enable claude` from an interactive terminal and approve it with your passkey.
  2. Restart the agents you wired so they load the new hooks.
```

It never changes anything and never asks for a passkey.

## 5. Exit codes

Scripts may rely on these ([stability policy](stability-policy.md#cli-surface)):

| Code | Plain meaning |
|---|---|
| 0 | Done, or nothing to do. |
| 1 | It ran and a check said no: a failing `selftest`, `night status` while night mode is off, an `update` whose new binary failed its checks. |
| 2 | It did not run: a typo, a bad argument, or no terminal where one is required. |
| 3 | Waiting on you. The change needs your passkey (or an enrolled passkey) and nothing was loosened. Run the command it names from a real terminal. |

## 6. When the agent is denied or asked

Guardrail answers every tool call the host sends it with **allow**, **ask**
or **deny**. Allow is silent.

**Deny.** The call does not run. The agent is told why and what to do
instead, for example:

```
Guardrail denied this action: downloaded content reaches an interpreter later
in the same pipeline. Download piped into a shell is denied. Download to a
file, inspect it, then run it as a separate reviewed step.
```

A good agent follows the next step and carries on. A deny with no usable
next step is a bug; [report it](https://github.com/CtrlCarlitos/agent-guardrails/issues).

**Ask.** The call waits for a person. Claude Code, opencode and Antigravity
show you their own permission prompt; approve or refuse it there. Codex
cannot prompt from a hook, so it blocks the call and the agent tells you what
it needs. The guidance for a push to `main` reads:

```
Operator authorization required: push to a protected branch. Request
authorization for this exact action: Bash {"command":"git push origin main"}.
```

**Why was that blocked?** Run this in the repository:

```sh
guardrail explain
```

It shows the newest ask or deny there: the command, the verdict, the rule ID,
the reason and the next step the agent was given. `guardrail explain --last 5`
shows more. `guardrail audit` summarises everything decided lately.

## 7. Where to go next

- [OPERATIONS.md](OPERATIONS.md): the runbook, from a symptom to the command
  that fixes it. Egress grants, night mode, updates and uninstalling are
  there.
- [compatibility-matrix.md](compatibility-matrix.md): which host, OS and
  shell combinations are verified, and which are not.
- [stability-policy.md](stability-policy.md): what you can depend on and what
  may still change.
- [CONTEXT.md](../CONTEXT.md): the words this project uses (plane, overlay,
  operator config).
- The README's [Extend it](../README.md#extend-it) section: add your own rules
  to a project with a `guardrail.toml`.
