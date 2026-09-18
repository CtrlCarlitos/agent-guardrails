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

See [the probe report](../../docs/research/2026-09-17-codex-plane-probes.md)
for coverage and known runtime boundaries.
