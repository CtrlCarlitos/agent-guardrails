# Windows 11 Antigravity (`agy 1.5.11`) live acceptance proof

## Claim

On Windows 11 with real Antigravity CLI (`agy 1.5.11`), Guardrail hooks fire in a live model session, deny `read_file` on `.env` as `P4.secret-path`, allow `read_file` on `hello.txt`, leak zero secret sentinels, and leave the host home directory and `HKCU\Environment\Path` untouched.

## Context

- Guardrail: `main` at `69d8b63` (PR #652)
- Runtime / plane: Antigravity CLI `agy 1.5.11` (`C:\ProgramData\chocolatey\lib\antigravity-cli\tools\agy.exe`)
- OS / shell: Windows 11 (`LAB-DOT-WIN-HOM`), `pwsh`, Python 3.15

## Method

Ran the Windows Antigravity platform acceptance harness in both hermetic and `--live` modes:

```
python -m unittest test/acceptance/test_acceptance.py
python test/acceptance/harness.py --platform windows --plane antigravity --output-dir <tmp>
python test/acceptance/harness.py --platform windows --plane antigravity --live --output-dir <tmp>
```

## Observation

- Acceptance unit tests: 20 tests run (19 OK, 1 POSIX PTY skip on Windows).
- Hermetic run: exit `0` (`pass: 10, fail: 0, unsupported: 1, operator_assisted: 1, skipped: 1`).
- Live run (`--live`): exit `0` (`pass: 11, fail: 0`, `live_runtime_session_observed: true`), observing live session `17e043a8-4231-4d1f-b0d3-fecd40a807bc`:
  - `read_file` on `.env` denied with rule `P4.secret-path`
  - `read_file` on `hello.txt` allowed
  - zero secret sentinel bytes in transcript output
  - `IsolationGuard` verified real user home, `AppData\Roaming\guardrail\waivers.toml`, and `HKCU\Environment\Path` unchanged

## Consequence

Merged `test/acceptance/windows_antigravity.py` and `select_antigravity_runner` dispatch into `main`, closing the Windows + Antigravity leg of #92.

## Links

- PR: #652 (merged 2026-11-21)
- Issue: #92
- Code: `test/acceptance/windows_antigravity.py`, `test/acceptance/harness.py`
