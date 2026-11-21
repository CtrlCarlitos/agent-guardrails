# macOS `/tmp` symlink alias, case-insensitive paths, and socket fallback

## Claim

Validating the full POSIX suite on macOS exposed temp-path symlink aliases (`/tmp` → `/private/tmp`), long temporary directory socket-path limits, case-insensitive filesystem assumptions, and shared replay-journal collisions across concurrent grant fixtures.

## Context

- Guardrail: `main` as of 2026-09-18 (PR #68)
- Runtime / plane: All planes (full POSIX test suite + engine + adversarial corpus)
- OS / shell: macOS (`macos-latest` CI) and Linux (`TMPDIR=/tmp/opencode`)

## Method

```
go test ./... -count=1
TMPDIR=/tmp/opencode go test ./internal/engine/... ./test/adversarial/... -count=1
```

Ran concurrent grant fixtures 100 times repeatedly and executed the full POSIX suite on `macos-latest` CI.

## Observation

- On macOS, `/tmp` is a symlink to `/private/tmp` and `os.TempDir()` sits under `/var/folders/…` (deep paths that can exceed Unix domain socket `sun_path` length limits), causing lexical-only repository containment checks and raw approval socket paths to diverge from Linux.
- Several fixtures assumed case-sensitive filesystems and hardcoded `/tmp` as the platform temp root instead of fixture-owned output paths.
- Concurrent grant fixtures sharing broker request IDs and state collided on replay journals under tight concurrency loops.

## Consequence

- Added `macos-latest` to CI running the full POSIX suite without skipping any security tests.
- Hardened repository identity and containment across symlinked/aliased roots (including nonexistent destination paths), added hashed short-path fallback for the Unix approval socket, and isolated concurrent grant fixture state (later centralized further in `internal/pathutil/canonical.go`, #109).

## Links

- PR: #68 (merged 2026-09-18)
- Related: #109 (`pathutil.Canonical`)
