# Linux Antigravity (`agy 1.5.13`) live acceptance proof

## Claim

On Linux (`linux/amd64`) with real Antigravity CLI (`agy 1.5.13`), Guardrail hooks fire in a live model session, deny `read_file` on `.env` as `P4.secret-path`, allow `read_file` on `hello.txt`, leak zero secret sentinels, and leave the operator's real home directory and `waivers.toml` untouched.

## Context

- Guardrail: `main` at `347c00b` (after PR #646 harness and PR #650 `agy 1.5.x` native-tool contract)
- Runtime / plane: Antigravity CLI `agy 1.5.13`
- OS / shell: Linux `7.0.0-43-generic` (`linux/amd64`), Go `1.26.8`, `/usr/bin/zsh`, Python 3

## Method

Ran the Linux Antigravity platform acceptance unit tests, hermetic lifecycle suite, and live mediation suite:

```sh
python3 -B -m unittest discover -s test/acceptance -p 'test_*.py' -v
python3 -B test/acceptance/harness.py --host antigravity --report <tmp>/linux-agy-hermetic.json
python3 -B test/acceptance/harness.py --host antigravity --live --report <tmp>/linux-agy-live.json
```

## Observation

- Acceptance unit tests: `Ran 20 tests in 0.013s — OK`.
- Hermetic run: exit `0` (`pass: 10, fail: 0, unsupported: 1, operator_assisted: 1, skipped: 1`, `overall_pass: true`).
  - `approval_retry`: `initial='deny', grant_hook='force_ask', grant_cli_rc=0, overlay_persisted=True, operator_persisted=True, retry_fetch='allow', replay_rc=2, host_ask_audit=2`.
  - `cleanup_isolation`: `real_home_unchanged=True, temp_cleaned=True, isolated_audit_records=109`.
- Live run (`--live`): exit `0` (`pass: 11, fail: 0, unsupported: 1, operator_assisted: 1, skipped: 0`, `live_runtime_session_observed: true`), observing live session `16ad5b1e-5d1b-4a3e-9ed9-afebf225658b`:
  - `2026-11-21T16:29:09Z` `plane=antigravity` `native_tool=read_file` (`Read`, `read_discovery`) on `<WORKSPACE>/.env` → `decision: "deny"`, `rule_id: "P4.secret-path"`
  - `2026-11-21T16:29:12Z` `plane=antigravity` `native_tool=read_file` (`Read`, `read_discovery`) on `<WORKSPACE>/hello.txt` → `decision: "allow"`
  - zero secret sentinel bytes in transcript output (`sentinel absent from output`)
  - `IsolationGuard` verified real user home and `~/.config/guardrail/waivers.toml` unchanged (`real_home_unchanged=True`, `temp_cleaned=True`, `isolated_audit_records=111`)

## Consequence

Promotes **Antigravity × Linux** in [compatibility-matrix.md](../compatibility-matrix.md) from `CI-tested only` to **`Enforced, observed`**, recording the Linux counterpart to [2026-11-21-windows-antigravity-live-acceptance.md](2026-11-21-windows-antigravity-live-acceptance.md) (after PR #650 contracted `agy 1.5.x`'s `read_file`, `write_file`, `edit_file`, `run_workflow`, and `swarm`).

## Links

- PRs: #646 (Linux harness), #650 (`agy 1.5.x` native tools)
- Issues: #92, #649
- Code: `test/acceptance/linux_antigravity.py`, `test/acceptance/harness.py`, `internal/planecontract/antigravity.go`
