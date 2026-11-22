# Platform Acceptance Harness (#92)

Reusable lifecycle acceptance runner for Guardrail across hosts and platforms,
covering **Antigravity (`agy`) on Linux and Windows**, **Codex on Linux** and
**opencode on Linux**.

## Running

### Unit tests (cross-platform, CI)

```sh
python3 -B -m unittest discover -s test/acceptance -p 'test_*.py' -v
```

### Linux + Antigravity lifecycle acceptance (offline / hermetic)

```sh
python3 test/acceptance/harness.py --host antigravity --report /tmp/acceptance-linux-antigravity.json
```

Builds local `v0.0.1-accept` and `v0.0.2-accept` binaries into a disposable temp
root, runs every lifecycle stage inside an isolated `HOME`/`XDG_*`/`ANTIGRAVITY_APP_DATA_DIR`,
prints a sanitized JSON report to stdout (and writes `--report`), verifies the
real user's `$HOME` was untouched, and removes the temp root.

### Windows + Antigravity lifecycle acceptance (offline / hermetic)

```powershell
python -B test/acceptance/harness.py --host antigravity --report "$env:TEMP\acceptance-windows-antigravity.json"
```

Builds local `v0.0.1-accept` and `v0.0.2-accept` `guardrail.exe` binaries into a
disposable temp root, runs every lifecycle stage inside an isolated Windows
profile (`USERPROFILE`, `APPDATA`, `LOCALAPPDATA`, `ANTIGRAVITY_APP_DATA_DIR`,
with `XDG_*` stripped and `HKCU\Environment\Path` snapshotted and restored),
exercises `install.ps1` checksum-verified install and update, `view_file` and
`read_file` secret denies, ADR-0033 host-ask approval/retry, disablement, and
recovery, prints a sanitized JSON report, verifies the real user's profile and
`HKCU\Environment\Path` were untouched, and removes the temp root.

### Opt-in live `agy` runtime mediation (`--live`)

```sh
python3 test/acceptance/harness.py --host antigravity --live --report /tmp/acceptance-linux-antigravity-live.json
```

Invokes real `agy -p` inside the isolated home against a disposable workspace
containing only a harmless fake `.env` sentinel and `hello.txt`. Verifies the
sentinel never leaks and isolated `audit.jsonl` records real, non-synthetic
`plane=antigravity` session traffic.

If `agy` has no credentials in the isolated home, `live_runtime_mediation`
reports `operator_assisted` rather than faking validation; pass
`--live-auth-from <disposable-auth-dir>` to supply non-hook auth state from a
dedicated disposable account.

### Linux + Codex lifecycle acceptance

```sh
make acceptance-linux-codex
python3 -B test/acceptance/harness.py --host codex --live --report /tmp/acceptance-linux-codex-live.json
```

The hermetic stages install and update from local checksummed releases, inspect
the generated hooks and native escalation floor, and exercise the installed
adapter with synthetic hook input. Terminal disablement preserves user hooks,
user rules, and the native escalation floor. To recover a corrupt hooks file
in the isolated home, the runner moves it to a backup and re-enables Codex
through a terminal, then compares the backup with the original fixture bytes.

The live stage checks for isolated authentication before running `codex exec`.
Supply a dedicated disposable Codex state directory via `--live-auth-from` or
an `OPENAI_API_KEY` for the opt-in run. The runner copies only the disposable
`auth.json` and removes it after the runtime check. The live claim requires
allowed shell output, a blocked fake secret read, and matching session evidence
from `guardrail selftest --evidence codex`. Missing isolated authentication
is reported as `operator_assisted`.

### Linux + opencode lifecycle acceptance

```sh
python3 -B test/acceptance/harness.py --host opencode --report /tmp/acceptance-linux-opencode.json
python3 -B test/acceptance/harness.py --host opencode --live --report /tmp/acceptance-linux-opencode-live.json
```

`opencode` must be on `PATH`: Guardrail chooses the plugin wiring from the
installed opencode major (ADR-0034), and the report records the version. The
hermetic stages install and update from local checksummed releases, register
the plugin in an isolated `opencode.json`, and feed the installed adapter
synthetic plugin envelopes: a fake `.env` read is denied through `bash` and
`read`, `chmod 777` asks, and an egress grant is refused after an unanswered
ask, granted once from a host-approved envelope, and refused on replay.
Terminal disablement must leave the user's own plugin entry and settings in
place. Recovery corrupts `opencode.json`, runs `guardrail recover
opencode-config` at a terminal, and compares the backup with the corrupt
bytes.

No tool runs in those stages, and the harness sets `host_approved` itself:
no permission dialog is shown and no operator approval is claimed. The
operator records in the report are labelled `harness_driven_lifecycle`, and
accepting the real dialog is `operator_assisted`.

The live stage runs `opencode run --standalone` in the isolated home, so it
does not attach to your background opencode service. Its claim requires, in
the session the runtime reported: an allowed read whose output came back from
a completed tool call, a `P4.secret-path` denial of the fake `.env`, and no
leaked sentinel. The isolated home has no login and uses opencode's default
model, which receives the prompt and the fixture file names. If the runtime
makes no tool call the stage reports `operator_assisted`. `--live-auth-from`
is not supported for this host.

## Stage Statuses

| Status | Meaning |
|---|---|
| `pass` | Stage executed and all assertions passed. |
| `fail` | Stage executed and an assertion failed (exits `1`). |
| `unsupported` | Host/OS does not support this feature (e.g., Antigravity declarative floor, ADR-0008). |
| `operator_assisted` | Requires real operator user verification or credentials (e.g., WebAuthn passkey enrollment; unauthenticated `--live`). Never simulated as live validation. |
| `skipped` | Intentionally skipped by flags (e.g., `live_runtime_mediation` without `--live`). |

## Exit Codes

- `0` — zero failed stages (`summary.overall_pass == true`)
- `1` — one or more failed stages
- `77` — missing host prerequisite (wrong OS, `agy` missing from `PATH`, `go` or `install.sh` missing)

## Safety & Claim Boundaries

- **Isolation:** Every subprocess runs with disposable `HOME`, `XDG_CONFIG_HOME`,
  `XDG_STATE_HOME`, `XDG_DATA_HOME`, and `ANTIGRAVITY_APP_DATA_DIR`. `cleanup_isolation`
  snapshots and verifies real-home config files are unchanged.
- **No destructive payloads:** Deny and approval stages use disposable temp files
  and RFC 2606 `.invalid` hostnames (`accept-probe.invalid`).
- **Honest claims:** `report.json` always records
  `claims.universal_mediation_implied: false` and `claims.webauthn_live_validated: false`.
  `claims.live_runtime_session_observed` is `true` only when `--live` observes
  non-synthetic records of the target plane tied to a real session ID.
