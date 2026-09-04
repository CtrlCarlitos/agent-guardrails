# Smoke test

`make smoke` runs `claude_smoke.sh`: it generates a throwaway Claude `settings.json`
with `guardrail gen-config claude --merge`, then runs a real `claude -p` session
against one destructive prompt (expected: blocked) and one benign prompt (expected:
runs). It needs a working `claude` login and **spends tokens**. Not in CI.

Exit codes: 0 pass, 1 fail, 77 skipped (claude or guardrail not on PATH).

The assertions are deliberately loose — Claude's phrasing varies. A "FAIL: no
guardrail block observed" with the model simply refusing on its own is a weak
signal, not necessarily a regression; inspect the transcript.
