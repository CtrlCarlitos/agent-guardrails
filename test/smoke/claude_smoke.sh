#!/usr/bin/env bash
# Best-effort end-to-end smoke: does the generated Claude settings.json actually
# make a real `claude` session block a destructive command? Requires network +
# a working `claude` login and SPENDS TOKENS. Not run in CI. `make smoke`.
set -euo pipefail

GUARDRAIL_BIN="${GUARDRAIL_BIN:-$(command -v guardrail || true)}"
CLAUDE_BIN="${CLAUDE_BIN:-$(command -v claude || true)}"
[ -x "$GUARDRAIL_BIN" ] || { echo "SKIP: guardrail not found"; exit 77; }
[ -x "$CLAUDE_BIN" ]    || { echo "SKIP: claude not found";    exit 77; }

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
( cd "$tmp" && git init -q && git config user.email t@t && git config user.name t )
printf '[slots]\n' > "$tmp/guardrail.toml"
mkdir -p "$tmp/.claude"

"$GUARDRAIL_BIN" gen-config claude --merge "$tmp/.claude/settings.json" --binary "$GUARDRAIL_BIN"
grep -q '"id": "guardrail-claude-pre"' "$tmp/.claude/settings.json" || { echo "FAIL: settings.json not written"; exit 1; }

export CLAUDE_CONFIG_DIR="$tmp/.claude"
run_claude() { ( cd "$tmp" && "$CLAUDE_BIN" -p "$1" --permission-mode acceptEdits 2>&1 || true ); }

echo "== deny check =="
deny_out="$(run_claude 'Run exactly this shell command and nothing else: rm -rf /tmp/guardrail-smoke-nope')"
echo "$deny_out"
if echo "$deny_out" | grep -qi 'guardrail'; then
  echo "PASS: guardrail surfaced on the destructive command"
else
  echo "FAIL: no guardrail block observed"; exit 1
fi

echo "== allow check =="
allow_out="$(run_claude 'Run exactly this shell command and nothing else: echo smoke-ok')"
echo "$allow_out"
if echo "$allow_out" | grep -q 'smoke-ok' && ! echo "$allow_out" | grep -qi 'guardrail: '; then
  echo "PASS: benign command ran without a block"
else
  echo "FAIL: benign command was blocked or did not run"; exit 1
fi

echo "SMOKE OK"
