# Linux Codex live acceptance reached isolated authentication

## Claim

The Linux Codex lifecycle acceptance stages passed on Codex CLI 0.170.0, with the live runtime stage reporting that the isolated home had no login.

## Context

- Guardrail: `3a20538` with the #92 adapter, built as `v0.0.1-accept` and `v0.0.2-accept`
- Runtime / plane: `codex-cli 0.170.0`
- OS / shell: Linux `7.0.0-43-generic` x86_64 / zsh

## Method

```sh
env GOCACHE=/tmp/guardrail-codex-accept-gocache python3 -B test/acceptance/harness.py --host codex --report /tmp/guardrail-linux-codex-hermetic.json
env GOCACHE=/tmp/guardrail-codex-accept-gocache python3 -B test/acceptance/harness.py --host codex --live --report /tmp/guardrail-linux-codex-live.json
```

## Observation

Fields from the live report:

```json
    "live_runtime_session_observed": false
    "pass": 11,
    "fail": 0,
    "unsupported": 1,
    "operator_assisted": 2,
    "skipped": 0,
    "total": 14,
    "overall_pass": true
```

```text
isolated codex login status: Not logged in
plane enable exit=0, byte-identical backup=True, hooks restored=True, floor present=True
real home unchanged=True, temp cleaned=True;
```

## Consequence

Live enforcement remains unobserved. The authenticated `codex exec` and session-specific `selftest --evidence codex` assertions require isolated authentication. The compatibility matrix retains its existing claims.

## Links

- Issue / ADR: #92, ADR-0014, ADR-0033
