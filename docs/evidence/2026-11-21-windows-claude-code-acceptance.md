# Windows Claude Code lifecycle acceptance

## Claim

The Guardrail lifecycle for the Claude Code plane passes in a disposable Windows 11 profile, with disablement and recovery applied through prompt-mode host-ask tickets; the nested `claude -p` stage had no login and reported `operator_assisted`.

## Context

- Guardrail: `337e1ac` with the #92 Windows Claude Code adapter, built as `v0.0.1-accept` and `v0.0.2-accept`
- Runtime / plane: Claude Code `2.1.330`
- OS / shell: Windows 11 (`windows/amd64`) / `pwsh`, non-elevated

## Method

```powershell
python -B test/acceptance/harness.py --host claude --report "$env:TEMP\acceptance-windows-claude.json"
python -B test/acceptance/harness.py --host claude --live --report "$env:TEMP\acceptance-windows-claude-live.json"
```

No credentials were supplied: neither `ANTHROPIC_API_KEY` nor
`CLAUDE_CODE_OAUTH_TOKEN` was set, and `--live-auth-from` was not passed.

## Observation

The `--live` run, 2026-11-22 UTC (2026-11-21 local):

```json
"summary": {"pass": 13, "fail": 0, "unsupported": 0, "operator_assisted": 3, "skipped": 0, "total": 16, "overall_pass": true}
"claims": {"universal_mediation_implied": false, "webauthn_live_validated": false, "live_runtime_session_observed": false}
```

```text
enablement              setup exit=0, isolated settings.json hook=True, claude: guardrail hook registered
host_hook_trust         selftest exit=0, live-evidence gate exit=1 not-yet-observed=True; claude settings: guardrail hook registered but NEVER OBSERVED FIRING — no audit record from a real session since this binary was built. Registration is not enforcement; confirm with `guardrail selftest --evidence claude`
harmless_deny           Bash cat .env: exit=2 audit=deny/P4.secret-path; Read .env: exit=2 audit=deny/P4.secret-path; PowerShell Get-Content .\.env: exit=2 audit=deny/P4.secret-path; Bash cat allowed.txt: allow
host_ask                hook exit=0, permissionDecision=ask, audit=ask/P1.chmod, retry guidance=True
approval_retry          initial=deny/P6.egress, grant without an ask refused=True, grant hook=ask/operator-action-ask, grant cli exit=0, overlay and operator config persisted=True, fetch refused as unapproved before=True and after=False, replay exit=2, host-ask audit=2
fixture_evidence_gate   7 fixture pre-hook records in the window, live-evidence gate exit=1 not-yet-observed=True
live_runtime_mediation  isolated Claude Code runtime is not logged in (session reported=True, its state under the isolated profile=True); supply --live-auth-from or an API key or OAuth token in the environment
disablement             disable without an ask refused=True, hook=ask/operator-action-ask, disable exit=0, guardrail hooks removed=True, user hook preserved=True, user settings preserved=True, replay exit=3; claude: present, hook NOT registered
recovery                recover without an ask refused=True, hook=ask/operator-action-ask, recover exit=0, replay exit=2, byte-identical backup=True, hooks restored=True
cleanup_isolation       real profile unchanged=True, HKCU Path unchanged=True, temp cleaned=True, isolated audit records=87;
```

The hermetic run without `--live` exited 0 with 13 passes, 2
`operator_assisted` and 1 `skipped`.

`setup` wrote the hook command quoted and with forward slashes:

```text
"<TEMP_ROOT>/bin/guardrail.exe" hook claude
```

A run kept with `--keep-artifacts` showed where the unauthenticated
`claude -p` wrote: `.claude.json` and `.claude\projects`, `sessions` and
`session-env` under the isolated home, and a `claude` directory under the
isolated `TEMP`. `cleanup_isolation` itself compares only the real
`settings.json`, the other watched config files and `HKCU\Environment\Path`.

## Consequence

No compatibility-matrix cell changes: Windows Claude Code was already
recorded as enforced and observed from real-session audit records, and this
run adds no harness-driven live session. It adds a repeatable lifecycle check
for the plane on Windows. An authenticated `--live` run is still open.

The fake-secret stage uses `Get-Content .\.env`. It makes no claim about a
bare file name passed to a PowerShell cmdlet.

## Links

- Issue / ADR: #92, ADR-0033
