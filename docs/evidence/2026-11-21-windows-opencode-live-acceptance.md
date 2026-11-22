# Windows OpenCode 2 live acceptance

## Claim

An OpenCode 2.3.2 session on Windows 11, started with `opencode run --standalone` in a disposable profile, was denied a read of a fake `.env` as `P4.secret-path` and allowed a read of a marker file in the same session.

## Context

- Guardrail: `381e8ee` with the #92 Windows OpenCode adapter, built as `v0.0.1-accept` and `v0.0.2-accept`
- Runtime / plane: `opencode v2.3.2` (ADR-0034 V2 wiring: `plugins` entry plus the `external_directory` ask)
- OS / shell: Windows 11 (`windows/amd64`) / `pwsh`

## Method

```powershell
python -B test/acceptance/harness.py --host opencode --report "$env:TEMP\acceptance-windows-opencode.json"
python -B test/acceptance/harness.py --host opencode --live --report "$env:TEMP\acceptance-windows-opencode-live.json"
```

No credentials were supplied. The isolated profile held only what the run
created, and OpenCode chose its own default model.

## Observation

The live run completed at 02:10 UTC on 2026-11-22 (2026-11-21 local).

```json
"summary": {"pass": 12, "fail": 0, "unsupported": 0, "operator_assisted": 2, "skipped": 0, "total": 14, "overall_pass": true}
"claims": {"universal_mediation_implied": false, "webauthn_live_validated": false, "live_runtime_session_observed": true}
```

```text
live_runtime_mediation  opencode run exit=0, session reported=True, fake secret read denied in that session=True, marker read allowed=True, marker returned by that read=True, fake secret absent=True, OpenCode state under the isolated profile=True
cleanup_isolation       real profile unchanged=True, HKCU Path unchanged=True, temp cleaned=True, isolated audit records=113;
```

Selected fields from the two records the live session wrote to the isolated
audit log:

```jsonl
{"ts": "2026-11-22T02:10:47Z", "session_id": "ses_dfefadb1dffes6GOkmS9Ba5r85", "plane": "opencode", "native_tool": "read", "event": "pre", "decision": "deny", "rule_id": "P4.secret-path", "paths": [".env"]}
{"ts": "2026-11-22T02:10:47Z", "session_id": "ses_dfefadb1dffes6GOkmS9Ba5r85", "plane": "opencode", "native_tool": "read", "event": "pre", "decision": "allow", "paths": ["hello.txt"]}
```

The lifecycle stages of the same run:

```text
install         bad checksum exit=1, mismatch reported=True, destination unchanged=True; valid install exit=0, version='guardrail v0.0.1-accept'
enablement      setup exit=0, isolated opencode.json holds the OpenCode 2 entry (host major 2), wiring complete=True, plugin artifact present=True
harmless_deny   read .env=('deny', 2), bash cat .env=('deny', 2), read hello.txt=('allow', 0), P4.secret-path audit records=2, fixture intact=True
approval_retry  egress=('deny', 2), grant without approval=('ask', 0), unapproved CLI refused=True, grant with host approval=('allow', 0), CLI exit=0, overlay and operator config persisted=True, fetch refused as unapproved before=True and after=False, replay exit=2, host-ask audit records=2
disablement     without approval=('ask', 0), unapproved CLI refused=True, hook='allow', disable exit=0, user plugin and theme preserved=True, guardrail entry and floor removed=True, doctor unregistered=True, replay exit=3
recovery        without approval=('ask', 0), unapproved CLI refused=True, hook='allow', recover exit=0, replay exit=2, byte-identical backup=True, wiring complete=True; doctor exit=0, selftest exit=0, opencode probes ok=True; opencode settings: guardrail integration registered (opencode 2, plugins entry); opencode ownership: manifest matches settings
```

The hermetic run without `--live` exited 0 with 11 passes, 2
`operator_assisted` and 1 `skipped`.

Three facts about the host surfaced while building the adapter:

- In the isolated profile, `opencode models` and `opencode auth list` failed
  with `Managed service port 28894 on 127.0.0.1 is already in use by another
  process`. The adapter therefore runs only `--version` and
  `run --standalone`.
- OpenCode's snapshot store leaves read-only objects that a plain recursive
  delete cannot remove on Windows.
- The OpenCode pre-hook allowed `guardrail fetch` for a host with no grant;
  the fetch command itself refused it as `unapproved host` until the grant.

## Consequence

The compatibility matrix cites this run for OpenCode 2 on Windows. The
observation covers the native `read` tool in one non-interactive session. The
approval stages supply the `host_approved` evidence themselves, so a human
answering OpenCode's permission dialog (ADR-0015) stays `operator_assisted`,
as does WebAuthn enrollment.

## Links

- Issue / ADR: #92, ADR-0015, ADR-0033, ADR-0034
