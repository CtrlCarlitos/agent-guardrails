# Windows UTF-8 BOM settings reads, launcher/shim fallback, and payload shapes

## Claim

Windows editors write UTF-8 BOMs that break raw `encoding/json` reads of plane settings, Windows Claude installs place a launcher or `.cmd` shim on `PATH` instead of the JS bundle, and drive-letter/UNC paths require host-aware containment with universal secret-tier denials.

## Context

- Guardrail: `main` as of 2026-09-18 (PR #66)
- Runtime / plane: Claude Code on Windows
- OS / shell: Windows (`windows-latest` CI) and Linux cross-checks

## Method

1. Tested Claude hook payloads with drive-lettered (`C:\Users\u\.ssh\…`, `C:\repo\.env`, `C:\repo\internal\a.go`) and UNC (`\\server\share\.env`) paths through `ParseClaude`, `engine.Evaluate`, and `test/fixtures/claude/windows/`.
2. Tested UTF-8 BOM-prefixed `settings.json` (as written by Notepad and Windows PowerShell 5) against `genconfig` merge, `doctor`, `plane status`, and SessionStart posture.
3. Inspected Windows native `~/.local/bin/claude.exe` launcher and npm-global `claude.cmd` shim behavior against `coverage.ClaudeBundlePath`.

## Observation

- Secret-tier Windows paths (`C:\Users\u\.ssh\…`, `C:\Users\u\.aws\…`, `C:\repo\.env`, `\\server\share\.env`) deny on every OS after separator normalization, whereas workspace containment for `C:\repo\internal\a.go` allows on Windows and fails closed to `P5.out-of-repo` ask on POSIX.
- A single Notepad or PowerShell 5 edit prepends a UTF-8 BOM (`EF BB BF`) that causes `encoding/json` to reject `settings.json`, making `plane enable` report `is not a JSON object; refusing to overwrite` and `doctor` report `"NOT registered"`.
- On Windows, `~/.local/bin/claude.exe` (native installer launcher) and `claude.cmd` (npm-global shim) do not carry the Claude tool lists; the versioned bundle lives under `$XDG_DATA_HOME/claude/versions` or `~/.local/share/claude/versions`.

## Consequence

- Added `genconfig.ReadJSONObject` to strip UTF-8 BOMs across merge, `doctor`, `plane` checks, and posture (writing back BOM-free JSON).
- Added launcher/shim fallback in `coverage.ClaudeBundlePath` to locate the newest versioned bundle when the `PATH` executable lacks a version marker.
- Added six Windows contract fixtures under `test/fixtures/claude/windows/` and four Windows-only selftest probes in `cmd/guardrail/selftest_windows_probes.go`, gated in CI's `windows-latest` job.

## Links

- PR: #66 (merged 2026-09-18)
- CI: `.github/workflows/ci.yml` (`windows-shaped tests`)
