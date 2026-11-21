# Update verified the superseded binary in-process and wrote a stale selftest marker

## Claim

Running `guardrail update` from `v0.20.18-dev` to `v0.20.19-dev` executed `doctor` and `selftest` in-process inside the replaced binary, verifying the superseded release and recording a stale `selftest-passed` marker.

## Context

- Guardrail: `v0.20.18-dev` updating to `v0.20.19-dev`
- Runtime / plane: Claude Code (SessionStart posture)
- OS / shell: Linux

## Method

Ran the first end-to-end `guardrail update v0.20.19-dev` hop and inspected the printed `doctor` header, `selftest` output, `selftest-passed` marker contents, and subsequent SessionStart posture line.

## Observation

```
guardrail updated to v0.20.19-dev at /home/…/.local/bin/guardrail
guardrail v0.20.18-dev            ← doctor header: the OLD release
…
selftest: all probes passed
--- marker ---
v0.20.18-dev                      ← recorded for the OLD release
```

Next SessionStart reported:

```
guardrail v0.20.19-dev is new here (selftest last passed on v0.20.18-dev); run guardrail selftest
```

## Consequence

`cmd/guardrail/update.go` switched from calling in-process `printDoctor` / `cmdSelftest` to exec-ing the freshly installed binary via `runInstalledBinary(exe, args, stdout, stderr)` for `doctor` and `selftest`, pinned by `TestUpdateVerifiesTheInstalledBinaryNotItself` and `TestUpdateReportsAFailedSelftestOnTheInstalledBinary`. Also established the N+2 rule for verifying updater fixes (the `v0.20.19` → `v0.20.20` hop is the first run executed by the fixed binary).

## Links

- PR: #58 (merged 2026-09-18)
- Related: #55, `CONTRIBUTING.md` (N+2 updater verification rule)
