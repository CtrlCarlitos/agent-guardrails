# Platform acceptance harness — design (2026-11-20)

Issue #92. Claimed by the Linux session; reusable lifecycle acceptance runner starting with **Antigravity (`agy`) on Linux** as the first real host target.

## Intent

Direct hook contract fixtures prove evaluator logic, not that a real host install, enablement, hook registration, prompt-mode approval/retry, update, disablement, recovery, and teardown actually work together in an isolated environment—or that a real host dispatches tool calls to the hook. This harness provides a repeatable lifecycle runner with structured, sanitized evidence (`report.json`) that cleanly distinguishes pass, fail, unsupported, operator-assisted, and skipped stages, starting with Antigravity (`agy`) on Linux and structured so additional hosts (Claude, OpenCode, Codex) and OSes (Windows, macOS) plug in as host adapters.

## Approaches Considered

1. **Python 3.12 stdlib runner under `test/acceptance/` (chosen):** Matches the existing `test/smoke/` probe convention (Python 3.12 is already pinned in `.github/workflows/ci.yml`), adds zero Go module dependencies (important because real Linux PTY testing for prompt-mode `[y/N]` approvals uses Python's stdlib `pty` module), keeps `cmd/guardrail` binary size untouched, and has fast cross-platform `unittest` coverage in CI.
2. **Go binary under `cmd/acceptance/`:** Good Go alignment, but Go's stdlib lacks a PTY driver (requiring a new third-party dependency in `go.mod` or shelling out to `script`), and adds a new package to maintain against Windows CI visibility guards (`test/ci_windows_visibility_test.go`).
3. **POSIX shell script (like `test/installer/install_sh_test.sh`):** Too brittle for structured JSON reporting, audit sanitization, PTY interaction, and future Windows host adapters.

## Architecture

```
test/acceptance/
├── harness.py             # Core runner, stage statuses, IsolationGuard, PTY driver, sanitizer, report schema, CLI
├── linux_antigravity.py   # First host adapter: Antigravity (agy) on Linux (hermetic lifecycle + opt-in --live)
├── test_acceptance.py     # Cross-platform unit tests (CI on Linux, macOS, Windows)
└── README.md              # Usage, stage matrix, status semantics, safety contract, adding hosts
```

### Stage Statuses

| Status | Meaning |
|---|---|
| `pass` | Stage ran and all assertions passed. |
| `fail` | Stage ran and an assertion failed (exits `1`). |
| `unsupported` | Host/OS does not support this capability (e.g., Antigravity has no declarative floor per ADR-0008). |
| `operator_assisted` | Requires real operator interaction or credentials (e.g., WebAuthn passkey enrollment/approval; `--live` without isolated auth). Never simulated as live validation. |
| `skipped` | Intentionally not run by flags (e.g., `live_runtime_mediation` without `--live`). |

### Stages (Linux + Antigravity)

1. `install` — Install `v0.0.1-accept` via `install.sh --base-url <local> --dest <isolated-bin> --no-setup`; verify checksum path, mode `0755`, and `guardrail version`.
2. `enrollment` — Verify default ADR-0033 `prompt` approval posture via `doctor`; record passkey/WebAuthn enrollment explicitly as `operator_assisted` (never simulated).
3. `enablement` — Run `guardrail setup --planes antigravity` (ADR-0030 bootstrap / prompt mode) in isolated `HOME`; verify `$HOME/.gemini/config/hooks.json` registers owned PreToolUse/PostToolUse entries pointing to the isolated binary.
4. `host_hook_trust` — Verify `hooks.json` ownership/enablement (`guardrail.enabled == true`, owned IDs, isolated binary path), `guardrail doctor` registration, and `guardrail selftest` pass. Note explicitly that Antigravity has no declarative floor (ADR-0008) and no separate hook-trust store.
5. `harmless_deny` — Invoke the installed binary's real `hook antigravity pre` path against a harmless fake `.env` in a disposable git workspace; assert `decision: "deny"`, rule `P4.file-secrets`, sanitized audit record written, and fake `.env` untouched.
6. `live_runtime_mediation` — Skipped unless `--live` is passed. With `--live`, invokes real `agy -p` inside the isolated home/workspace against a fake `.env` with a unique sentinel; verifies sentinel did not leak and isolated `audit.jsonl` holds non-synthetic `plane=antigravity` deny evidence tied to a real session ID. Unauthenticated isolated runs report `operator_assisted` rather than failing silently or faking validation.
7. `approval_retry` — Exercises ADR-0033 prompt-mode approval + retry on Antigravity using an RFC 2606 `.invalid` host (`accept-probe.invalid`, zero network): `curl https://accept-probe.invalid` denies (`P6.egress-not-allowed`) -> canonical `guardrail egress grant --scope repo --host accept-probe.invalid` asks (`force_ask`) and mints an approval ticket -> TTY-less CLI claims the one-shot ticket (`host-ask`) -> retry of `curl https://accept-probe.invalid` allows -> second TTY-less grant replay is refused. WebAuthn approval remains explicitly `operator_assisted`.
8. `update` — Stage `v0.0.2-accept` in the local releases dir, upgrade via `install.sh --base-url <local> --version v0.0.2-accept --dest <isolated-bin>`, verify `guardrail version`, `doctor`, and `selftest`.
9. `disablement` — Seed a sentinel user hook entry in `hooks.json`, run `guardrail plane disable antigravity` via a real Linux PTY (`y`), verify Guardrail hooks are removed/disabled while user config is preserved.
10. `recovery` — Corrupt `hooks.json` with invalid JSON, run `guardrail recover antigravity-hooks` via a real Linux PTY (`y`), verify timestamped backup (`hooks.json.guardrail-recover-*`), restored valid JSON with Guardrail hooks re-registered, and clean `doctor` + `selftest`.
11. `cleanup_isolation` — Verify zero modifications to the operator's real `$REAL_HOME/.gemini/config/hooks.json` and `$REAL_HOME/.config/guardrail/waivers.toml`, verify isolated audit records did not leak outside the temp root, and remove the disposable temp tree (unless `--keep-artifacts` is set).

## Safety & Claims Boundaries

- Never modifies real user config, state, or repositories; all subprocesses run with isolated `HOME`, `XDG_CONFIG_HOME`, `XDG_STATE_HOME`, `XDG_DATA_HOME`, and `ANTIGRAVITY_APP_DATA_DIR`.
- Never executes destructive payloads against real data; all deny/approval fixtures use disposable temp files and `.invalid` hostnames.
- `report.json` always sets `claims.universal_mediation_implied: false` and `claims.webauthn_live_validated: false`. `claims.live_runtime_session_observed` is `true` only when real `agy` emitted non-synthetic session audit records in `--live` mode.
