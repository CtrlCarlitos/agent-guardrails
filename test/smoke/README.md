# Smoke test

`make smoke` runs `claude_smoke.sh`: it generates a throwaway Claude `settings.json`
with `guardrail gen-config claude --merge`, then runs a real `claude -p` session
against one destructive prompt (expected: blocked) and one benign prompt (expected:
runs). It needs a working `claude` login and **spends tokens**. Not in CI.

Exit codes: 0 pass, 1 fail, 77 skipped (claude or guardrail not on PATH).

The assertions are deliberately loose — Claude's phrasing varies. A "FAIL: no
guardrail block observed" with the model simply refusing on its own is a weak
signal, not necessarily a regression; inspect the transcript.

## Codex deterministic native probes

```sh
go build -o /tmp/guardrail-codex ./cmd/guardrail
python3 test/smoke/codex_probe.py /tmp/guardrail-codex
python3 test/smoke/codex_probe.py /tmp/guardrail-codex --code-mode
```

PowerShell on Windows:

```powershell
go build -o "$env:TEMP\guardrail-codex.exe" ./cmd/guardrail
python test/smoke/codex_probe.py "$env:TEMP\guardrail-codex.exe"
python test/smoke/codex_probe.py "$env:TEMP\guardrail-codex.exe" --code-mode
```

Requires Codex CLI 0.154.0, Python 3, Git, gofmt, and loopback sockets. Runs the
real Codex runtime against a scripted local Responses provider and a harmless
stdio MCP server. No login, credentials, model inference, or API charges. Hooks,
native rules, state, and fake secret files live in a fresh temporary directory;
the generated hook definitions use Codex's one-invocation trust override while
the command sandbox remains enabled. User Codex settings are not modified.

The report counts actual native hook invocations and checks side effects. Direct
mode also validates all generated prefixes through `codex execpolicy check`
without executing those commands. The unavailable-tool case is explicitly a
runtime rejection, not evidence that Codex forwarded it to Guardrail. Code mode
checks nested tools, including MCP. Both modes exercise the effective-workdir
guard and post-edit lint feedback. Exit 0 means the assertions passed, 1 means a
failed assertion, and 77 means a prerequisite is missing. Artifacts are retained
under the printed temporary path for inspection.

The harness uses the running `sys.executable` for its logger and MCP fixture.
On Windows it generates an inspectable `.cmd` launcher, resolves `codex.cmd`
instead of the extensionless POSIX npm shim, TOML-escapes backslash paths, and
uses PowerShell input plus Ctrl-Z/CRLF for the interactive EOF attempt. Windows
gets a 180-second process window; a timeout becomes an exit-124 report with
retained artifacts rather than an unhandled exception.

See [the probe report](../../docs/research/2026-09-17-codex-plane-probes.md)
for coverage and known runtime boundaries.

## Codex mediation follow-ups

```sh
python3 test/smoke/codex_probe.py /tmp/guardrail-codex --mediation
python3 test/smoke/codex_probe.py /tmp/guardrail-codex --mediation --code-mode
python3 test/smoke/codex_probe.py /tmp/guardrail-codex --mediation --restricted
python3 test/smoke/codex_probe.py /tmp/guardrail-codex --mediation --restricted --code-mode
```

The baseline deliberately reproduces a known gap: an approved `cat` process
receives bytes, a poll, and EOF through `write_stdin` with no new pre-hook. A
written fixture file and successful process termination prove execution. Exit 0
means the documented behavior was reproduced, **not** that stdin is mediated.
A future runtime that starts invoking stdin hooks will fail this expectation and
requires a contract/adapter review before updating the probe.

Restricted mode sets `web_search="disabled"` and `features.shell_tool=false` in
the disposable Codex config. It requires forced command/stdin calls to be
rejected, their output file to remain absent, and a hooked patch to succeed.
Both modes inspect the provider request for web-search availability. No hosted
search is executed; `hosted_execution_tested` is always false. The tests cover
web-search configuration, not all hosted tools or remote enforcement. Additional
`tools.json` evidence is retained with the normal artifacts.

Windows validation with Codex CLI 0.155.1 showed `web_search` advertised when
cached and absent when disabled, but no hosted execution was attempted and no
local-hook coverage is claimed. The unrestricted stdin probe could not reach a
live process: Windows rejected three interactive command forms (`cmd.exe`, a
.NET console reader, and PowerShell `$input | Set-Content`) before process
creation; every later `write_stdin` call returned unknown process ID. This is an
inconclusive Windows comparison, not evidence that stdin is mediated. Guardrail's
`write_stdin` contract remains Deny.
