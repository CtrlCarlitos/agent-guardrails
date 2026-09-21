# ADR-0023 — Engine shell/host seam for POSIX cd-path analysis and standard-device redirects

**Date:** 2026-09-21  
**Status:** Proposed  
**Issues:** #214 (POSIX cd-path analysis), #215 (standard-device redirects)  
**Author:** AGY (Antigravity)

---

## Context

Issues #214 and #215 share one root cause: the command analyzer in
`internal/engine/tokenize.go` and `rules_bash.go` conflates two distinct
concerns when it reasons about paths inside POSIX Bash input:

1. **Shell-lexical judgment** — Is `/etc` an absolute path? Is `/dev/null`
   one of the four POSIX standard devices? These are questions about the shell
   language grammar and the POSIX shell contract, not about the machine
   running guardrail. The answers are constant regardless of host OS.

2. **Host-filesystem probing** — Does the candidate directory exist and
   admit `cd`? Is it searchable? These questions *do* require the host OS,
   but only to tighten containment, never to widen it.

On Linux/macOS both concerns happen to use the same APIs (`filepath.IsAbs`,
`os.Stat`, `filepath.Clean`) and produce correct results because the host OS
*is* POSIX. On Windows those APIs model Win32, not POSIX, so:

- `filepath.IsAbs("/etc")` → `false` (Win32: not absolute)
- `os.Stat("/etc")` → `ERROR_FILE_NOT_FOUND`
- `filepath.Clean("/dev/null")` → `\dev\null` (not the POSIX literal)

This causes the two bugs:

| Bug | Symptom | Effect |
|-----|---------|--------|
| #214 | `cd /etc && rm -rf .` → `allow` | cwd stays `/repo`; destructive tail passes containment |
| #215 | `echo x >/dev/null` → `ask/P1.redirect` | redirect exemption unreachable; false positives |

---

## Decision

Introduce a **host-filesystem seam** in the engine. Split the two concerns
into separate, independently testable abstractions.

### 1. Shell-lexical layer (POSIX, host-independent)

These functions operate purely on string values of Bash tokens and are
identical on every host OS. They must never call `filepath.*` or `os.*`.

#### 1a. POSIX path absoluteness

```go
// posixIsAbs reports whether p is absolute in POSIX shell grammar:
// it starts with '/'.  This is intentionally different from
// filepath.IsAbs which uses Win32 semantics on Windows.
func posixIsAbs(p string) bool { return len(p) > 0 && p[0] == '/' }

// posixJoin joins base and rel using '/' as separator.
func posixJoin(base, rel string) string { ... }

// posixClean returns the lexical POSIX normal form of p (same as
// path.Clean from the standard library).
func posixClean(p string) string { ... }
```

These replace `filepath.IsAbs`, `filepath.Join`, and `filepath.Clean` in
`resolveCdTarget`, `cdCandidate`, and `cdUsesSearchPath` — the places
where the analysis makes decisions about the *shell language*, not the host.

The POSIX separator `:` (not `filepath.ListSeparator`) is used when splitting
CDPATH entries.

#### 1b. Standard-device recognition

```go
// posixStandardDevice reports whether p is one of the four POSIX
// shell standard output devices, after POSIX lexical normalization.
// It is strictly redirect-only: no child paths, no volume names.
func posixStandardDevice(p string) bool {
    switch posixClean(p) {
    case "/dev/null", "/dev/stdout", "/dev/stderr", "/dev/tty":
        return true
    }
    return false
}
```

This replaces the `filepath.Abs` + `filepath.Clean` + string switch in
`rules_bash.go:1559–1564`. Because the input is a POSIX shell token (not a
host path), no `filepath.Abs` expansion is needed or correct.

The same POSIX-lexical check replaces `filepath.Clean(target) !=
filepath.Clean("/dev/null")` in `literalHarmlessTeeInput`
(`rules_bash.go:475`).

### 2. Host-filesystem layer (OS-aware, fail-closed)

`cdDirectoryState` already correctly falls back to `cdDirectoryUnknown` when
`os.Stat` fails. The missing piece is: it must not be *called* with a path
that cannot be probed on the current host.

A POSIX-absolute path (starts with `/`) on a Windows host is invisible to
`os.Stat`; the function currently returns `cdDirectoryMissing` (not found),
which can later become Allow through the failure-branch. The fix:

```go
// hostCanProbe reports whether the host OS can probe the existence of
// path using os.Stat.  On Windows, POSIX-absolute paths (starting
// with '/') are not Win32 paths and must be treated as unknown rather
// than missing.
func hostCanProbe(path string) bool {
    // implemented in probe_unix.go and probe_windows.go
}
```

- **Unix** (`probe_unix.go`): always `true` — the host *is* POSIX.
- **Windows** (`probe_windows.go`): `return filepath.IsAbs(path)` — Win32
  absolute paths (drive letters, UNC) can be probed; POSIX-absolute paths
  (starting with `/`) cannot.

`cdDirectoryState` becomes:

```go
func cdDirectoryState(candidate string) cdDirectoryStatus {
    if !hostCanProbe(candidate) {
        return cdDirectoryUnknown   // fail-closed, not cdDirectoryMissing
    }
    info, err := os.Stat(candidate)
    ...
}
```

The fail-closed choice (`cdDirectoryUnknown` rather than
`cdDirectoryMissing`) is the critical safety property: unknown ⇒ both
success and failure branches are carried; missing ⇒ the `cd` is assumed to
have failed and the tail is evaluated from the *prior* (potentially safe) cwd.
The latter is what causes `cd /etc && rm -rf .` to Allow on Windows.

### What does NOT change

| Concern | Stays the same |
|---------|----------------|
| POSIX Bash input paths — the text being analyzed | Always POSIX grammar |
| Host-filesystem probing for repo-relative `cd subdir` | Continues to use `os.Stat`; the repo is always a Win32 path when on Windows, so `hostCanProbe` returns true |
| `filepath.Abs` / `filepath.Clean` in `authorizedPath`, `findRootOverlapsRepository`, and other containment checks that reason about the *guardrail process* working directory | These correctly use Win32 on Windows — the guardrail process lives in Win32 space |
| `filepath.EvalSymlinks` for `cd -P` physical mode | Remains host-probed; skips (returns `cdDirectoryUnknown`) when `hostCanProbe` is false, consistent with `fsUncertain` handling |
| `path.Clean` (standard library `path` package) | Used by `posixClean`; already POSIX, no change needed |
| `filepath.Clean` in `gitInitExpected` comparison (`rules_bash.go:161`) | That comparison operates on the guardrail process's own cwd, not on shell-token paths; no change needed |

---

## Consequences

### Positive
- #214 fixed: `cd /etc && rm -rf .` on a Windows host → `cdDirectoryUnknown`
  → both branches carried → tail evaluated at unknown cwd → non-allow.
- #215 fixed: `/dev/null`, `/dev/stdout`, `/dev/stderr`, `/dev/tty` redirect
  exemptions work on Windows; `/dev/./null` normalization preserved.
- No change to Linux/macOS verdicts: `posixIsAbs` and `posixClean` produce
  identical results to `filepath.IsAbs` / `filepath.Clean` on POSIX hosts;
  `hostCanProbe` returns true on Unix.
- The two concerns are now independently testable. The shell-lexical helpers
  have no OS dependency and can be unit-tested on any host.

### Negative / trade-offs
- The `cd /repo/subdir` case on Windows is still probed via `os.Stat` (good
  — that's the intent). The operator must document that `CWD` and `RepoRoot`
  in ToolCall must be Win32 absolute paths on a Windows host.
- `hostCanProbe` is a new build-tag file pair; adds one small file per OS.

### Accepted narrowing — Git Bash / MSYS2 POSIX-absolute drive paths

`hostCanProbe` returns `false` for **all** POSIX-absolute paths on Windows,
including Git Bash / MSYS2 drive-mapped forms such as `/c/repo/src`. A guardrail
session running under Git Bash will therefore receive `cdDirectoryUnknown` for
every `cd /c/…` target, causing the tail to be evaluated at an unknown cwd
(non-allow / conservative ask) rather than allowing through.

This is an **accepted narrowing, not a defect**:

- The safe direction is preserved: the tail never silently Allows on a path
  the host cannot verify.
- The MSYS root mapping (`/c` → `C:\`) is environment-specific (Git Bash,
  Cygwin, WSL with interop, etc.) and requires an active mount table lookup.
  Encoding that in the engine couples the analyzer to a runtime dependency
  it does not otherwise have.
- A future ADR may extend `hostCanProbe` with an optional MSYS mount resolver
  injected at construction time. Until then the fail-closed behavior is the
  correct stance.

If a Git Bash user reports that all absolute `cd` targets produce ask verdicts,
the expected response is: "this is intentional — the guardrail cannot verify
POSIX-drive paths on Windows without an MSYS mount table; use Win32 paths
(`C:\repo`) in the `CWD` and `RepoRoot` fields of the tool call."

### Non-goal (explicit)
NUL (Windows null device) is **not** in the redirect exemption list. The
input being analyzed is Bash shell text; a Bash agent on Windows would still
write `/dev/null`, not `NUL`. If an agent sends `NUL` as a redirect target,
it is a Windows-specific escape attempt and must be treated by the existing
write-path rules.

---

## Files touched

| File | Change |
|------|--------|
| `internal/engine/posix_path.go` | New: `posixIsAbs`, `posixJoin`, `posixClean`, `posixStandardDevice`, `posixSplitList` |
| `internal/engine/posix_path_test.go` | New: unit tests for all five helpers, no OS dependency |
| `internal/engine/probe_unix.go` | New: `hostCanProbe` always true |
| `internal/engine/probe_windows.go` | New: `hostCanProbe` returns `filepath.IsAbs(path)` |
| `internal/engine/tokenize.go` | Replace `filepath.IsAbs/Join/Clean/SplitList` in shell-lexical paths with `posixIsAbs/Join/Clean/SplitList`; add `!hostCanProbe` guard in `cdDirectoryState` |
| `internal/engine/rules_bash.go` | Replace `filepath.Abs+filepath.Clean` redirect switch with `posixStandardDevice`; same for `literalHarmlessTeeInput` |
| `internal/engine/rules_bash_test.go` | Mark `TestStandardOutputDeviceRedirectsAreAllowed` and the `TestCd*` family as mandatory on `windows-latest` (currently they skip or fail on that runner) |

No new packages; no new exported symbols. All additions are package-private.

---

## TDD shape (after operator sign-off)

1. Add `posix_path_test.go` (host-agnostic unit tests) — all pass on every
   OS immediately because the helpers are pure string functions.
2. Add `probe_windows.go` / `probe_unix.go` — trivial, pass immediately.
3. RED: run `TestStandardOutputDeviceRedirectsAreAllowed` and
   `TestCdIsTrackedAcrossCurrentShellStatements` on `windows-latest` —
   both fail (existing bugs).
4. Apply `tokenize.go` and `rules_bash.go` changes → GREEN on all three OS
   runners.
5. All existing Linux/macOS tests unchanged.
