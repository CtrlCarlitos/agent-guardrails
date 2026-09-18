# Handover: agent-guardrails on Windows

For: GLM (opencode) on the Windows host, taking over the Windows program.
From: GLM on takumi-dream (Linux), session of 2026-09-17/18. Owner: Carlitos.

## Mission

Take agent-guardrails from "Windows builds and unit-tests green" to "Windows
is a first-class platform": the approval broker (ADR-0021), plane lifecycle,
update, and per-plane validation — coded, debugged, and verified on a real
Windows host, not just CI runners.

## Current state (do not rediscover)

- Repo: `CtrlCarlitos/agent-guardrails`, main at **v0.20.26-dev**. Four
  planes live on Linux/macOS: claude, opencode, antigravity, codex.
- On Windows today: `gen-config --merge` works (floor wiring only). Anything
  approval-gated returns exit 2: `operator *`, `plane enable|disable`,
  `recover`, egress grants, approvals. See `cmdOperator` / `cmdPlaneLifecycle`
  / `cmdRecover` for the exact gates.
- CI already runs `windows-latest` for the full unit suite and builds all
  Windows release assets. That is the floor you start from.
- **Read first, in this order:** `CONTEXT.md` (glossary), `CHANGELOG.md`
  (v0.19.0→v0.20.26 history), `docs/adr/0021-*.md` (the Windows broker
  design — your build sheet), `docs/OPERATIONS.md` (the runbook),
  `docs/adr/0007/0015/0017/0019/0020` as needed.

## Known Windows facts (verified this cycle — trust these)

1. `guardrail update` **fails at its final rename** on Windows: you cannot
   `os.Rename` over the running executable. Fix needs design (staged restart,
   PID hold, or rename-old-then-move). Needs a real-machine repro.
2. `opencode.json` must stay BOM-less; the dotfiles PowerShell installer
   writes with `UTF8Encoding($false)` for this reason.
3. ADR-0021 verified: the enrollment lock is already `gofrs/flock`
   (cross-platform), and `openURL` only *prints* the approval URL today —
   no browser-launch problem exists on any platform.
4. `internal/audit.DefaultPath` already branches: Windows audit log lives at
   `%LOCALAPPDATA%\guardrail\audit.jsonl`.
5. `daemon_windows.go` exists but is fail-closed plumbing around the Unix
   socket assumptions; ADR-0021 replaces the transport with a named pipe
   behind the existing `listenPrivate`/`dialPrivate` seams.

## The lift order (ADR-0021, steps a→d — one PR each, inert until gated)

- (a) **Named-pipe transport** with owner-only DACL behind
  `listenPrivate`/`dialPrivate`. The OS authenticates the peer — the exact
  property the 0700 socket dir provides on Unix. Constraint from review: the
  DACL/owner-SID property must be **test-asserted on windows-latest**, not
  just code-reviewed.
- (b) Enrollment/ceremony paths: `LockFileEx` behind the enrollment-lock
   seam; owner-SID + DACL checks replacing 0o077 mode-bit checks. Browser
   WebAuthn ceremony unchanged (Windows Hello works against a localhost
   origin).
- (c) Unlock the gated commands: strip the Windows early-returns from
  `operator`/`plane`/`recover`/approvals once (a)+(b) hold; wire Windows
  paths in `planeConfigPath` (`%USERPROFILE%` forms), lifecycle detection
  (`codex` on PATH, `CODEX_HOME`), and floor generation.
- (d) `guardrail update` on Windows: fix the rename-over-running-exe
  failure; a passing update must run doctor+selftest **via the installed
  binary** (see #58 — exec, never in-process).

TDD throughout, RED watched; conventional commits; one branch per PR off
`origin/main`; never force-push; `git add` explicit paths (a `git add -A`
once committed 73k lines of graft/ artifacts — .gitignore now blocks it, keep
the habit anyway). Report through the operator like the Linux cycle did.

## The hidden giant: command analysis on Windows

The engine's bash rules (P1/P2/P3/P6) target POSIX shells. Windows planes
will submit PowerShell and cmd.exe commands. Before treating any plane as
covered on Windows, probe: does `rm -rf /`-equivalent PowerShell
(`Remove-Item -Recurse -Force C:\`) deny? If not, command analysis parity is
a real work item — size it early, ADR it, don't discover it in step (c).

## Per-plane Windows validation (yes — every agent has its own work)

Hand each agent their sheet when the broker lands (or in parallel for
validation-only items):

- **opencode (you, in-session):** plugin spawns the binary with Windows
  paths (backslash payloads through `ParseOpencode` — path normalization,
  `apply_patch` extraction, MCP `relative_path` projection); `selftest` on
  Windows (probe payloads are POSIX-shaped — add Windows variants rather
  than breaking the Linux ones); audit-log location; `doctor --coverage`
  equivalents.
- **claude:** `%USERPROFILE%\.claude\settings.json` floor merge (BOM),
  Windows hook payload shapes from real Claude Code, coverage scanner
  against the Windows bundle install path, selftest probes with Windows
  paths.
- **antigravity:** does `agy` run on Windows at all; `%USERPROFILE%\.gemini`
  paths; `run_command` parity incl. the PowerShell question above.
- **codex:** does the CLI run on Windows; **do hooks fire** — the
  live-mediation question (ADR-0020, `selftest --evidence codex`) may answer
  differently on Windows and is worth checking first, cheaply.

## Environment setup (Windows box)

git + Go (version from `go.mod`) + `gh auth login`; clone the repo;
`go build ./cmd/guardrail`; `go test ./...` (windows suite is green in CI —
if it isn't green locally, fix that first, it's environment). Install the
release binary (`guardrail update` is broken on Windows by design until (d);
use the dotfiles ps1 installer or the release asset directly). Then:
`guardrail doctor`, `guardrail selftest`, `guardrail plane status`.

## Suggested skills for the next session

`verification-before-completion` (evidence before claims), `systematic-debugging`
(before any fix), `test-driven-development` (every step a→d),
`using-git-worktrees` (one branch per PR), `handoff` (when passing back).
Serena: re-onboard on the Windows clone; project memories live in the repo
worktree, not synced across machines.

## Communication

This program runs through the operator, who relays between plane agents
(claude, agy, codex on the Linux box) and you. PRs are the interface;
ADR-0021 is the contract; OPERATIONS.md grows with every incident you hit.


## Validated on windows-latest (claude #66 — test scaffolding facts, none were logic bugs)

1. `exec.LookPath("claude")` needs a PATHEXT extension on Windows: look for
   `claude.exe`. Affects `planeInstalled` detection and the coverage scanner's
   launcher resolution.
2. `os.UserHomeDir()` reads `USERPROFILE`, not `HOME` — environment handling
   in tests and tools must not assume HOME.
3. Runner temp dirs return in 8.3 short form (`RUNNER~1`) while
   `filepath.EvalSymlinks` yields the long form: compare with `os.SameFile`,
   never string equality.

Also verified from the first Windows run: adapter projection of `C:\`,
`C:/`, and UNC paths; secret-tier denies everywhere; **containment allows on
Windows but fails closed to P5.out-of-repo on POSIX** (expected divergence —
document before anyone "fixes" it); BOM read + merge; six Windows contract
fixtures through the built .exe; four Windows selftest probes with
audit-record rule verification.

## Confirmed: the PowerShell gap is real (measured, not theorized)

`Remove-Item -Recurse -Force C:\` and `Get-Content <secret>` currently pass
through the bash analyzer as unknown commands and allow. P1/P4 cmdlet
coverage is a precondition for trusting any Windows host with a PowerShell
tool — size it first (see "The hidden giant" above; claude's #66 supplies the
repro).

## Program mechanics (settled this session)

- CI ubuntu+windows matrix catches cross-platform regressions; no SSH-back
  needed. Live-machine verification = `guardrail selftest` after updates.
- macOS is build-only today (darwin assets compile; no test job). Adding
  `macos-latest` is a billing decision (private repo, 10x minutes).
- Living-on-Windows remains necessary regardless of CI: PATHEXT,
  USERPROFILE, 8.3 paths, the update rename lock, Windows Hello, and the
  daemon in daily use are all invisible to unit tests.
