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
- CI runs `windows-latest` for **build + vet + a name-filtered slice of the
  suite** (`-run 'Windows|BOM|ReadJSONObject'`), and builds all Windows
  release assets. It does **not** run the full unit suite there, and an
  earlier revision of this document said it did. The POSIX-native engine
  tests are ubuntu/macos only by design (see the comment in `ci.yml`), so
  **a new Windows test is invisible to CI unless its name matches that
  filter** — name Windows tests `TestWindows…`. Verified 2026-09-20.
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
  equivalents. The whole `selftest` matrix was red on Windows until #137;
  `codexSelftestProbes` there is the pattern for a host-shaped probe.
- **claude:** `%USERPROFILE%\.claude\settings.json` floor merge (BOM),
  Windows hook payload shapes from real Claude Code, coverage scanner
  against the Windows bundle install path, selftest probes with Windows
  paths. **Bundle path resolved 2026-09-20 on a real host:** the CLI's
  native installer uses the *same* layout as Unix —
  `~/.local/bin/claude.exe` (a full bundle copy, not a shim) plus
  `~/.local/share/claude/versions/<semver>` — so `claudeVersionsDir()`
  needs no Windows branch. `%LOCALAPPDATA%\AnthropicClaude` is the **desktop
  app** (Squirrel), not the CLI; do not point the scanner at it.
  `doctor --coverage claude` there reports the bundle, its version, 31
  runtime tools from 17 tool lists, and zero uncontracted tools.
- **antigravity:** does `agy` run on Windows at all; `%USERPROFILE%\.gemini`
  paths; `run_command` parity incl. the PowerShell question above.
- **codex:** does the CLI run on Windows; **do hooks fire** — the
  live-mediation question (ADR-0020, `selftest --evidence codex`) may answer
  differently on Windows and is worth checking first, cheaply.

## Environment setup (Windows box)

git + Go (version from `go.mod`) + `gh auth login`; clone the repo;
`go build ./cmd/guardrail`; `go vet ./...`. **Do not expect `go test ./...`
to be green on Windows and do not try to make it so** — an earlier revision
of this document said a red local run was an environment problem to fix
first. It is not: ~125 engine and cmd tests are POSIX-shaped by design and CI
never runs them on Windows. The Windows-relevant run is CI's own:

    go test ./internal/adapter/ ./internal/engine/ ./internal/genconfig/             ./internal/coverage/ ./cmd/guardrail/ ./test/             -run 'Windows|BOM|ReadJSONObject'

Take a baseline of the full run before you start and diff against it after;
new failures are yours, the rest are the floor. A Linux second opinion is
cheap if WSL is present (`go` under `/usr/local/go/bin`, repo readable at
`/mnt/c/...`) and covers the ubuntu leg before you push. Install the release
binary (`guardrail update` is broken on Windows by design until (d);
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

`Remove-Item -Recurse -Force C:\` passed through the bash analyzer as an
unknown command and allowed. So did `Format-Volume`, `Clear-Disk`,
`Set-ExecutionPolicy Bypass`, `Invoke-WebRequest <host>`, `iwr … | iex` and
`Invoke-Expression`.

**`Get-Content <secret>` did not.** That half of the claim was wrong, and
it was the half that made this look like a week of work: the secret tier
keys on the *operand*, not the command name, so it covered cmdlets from the
start — `Get-Content`, `Select-String`, `Set-Content`, `Out-File` and
`Copy-Item`, in their `-Path`, quoted, `$env:USERPROFILE` and `$HOME`
spellings, and through a pipeline. Re-measure before trusting a gap claim.

Closed by #135 (P1) and #136 (P6), which project each cmdlet onto the POSIX
command it stands for rather than building a parallel rule set.

**Still open, and the same disease in a second shell: `cmd.exe` (#139).**
Measured 2026-09-20:

    del /s /q C:\Windows              allow
    cmd /c "rd /s /q C:\Windows"      allow
    type C:\Users\u\.ssh\id_ed25519   deny  P4.secret-path

Forward-slash switches tokenise as path operands, so P1 never sees a
recursive delete — while P4 covers cmd for the same operand-keyed reason it
covered PowerShell. **A Windows host must not be trusted with a cmd tool
until #139 lands**, which is the sentence this section used to carry for
PowerShell. Also open: shutdown/reboot (#140), uncovered in *both* shells
and so a parity question rather than a Windows one.

## Program mechanics (settled this session)

- CI ubuntu+windows matrix catches cross-platform regressions; no SSH-back
  needed. Live-machine verification = `guardrail selftest` after updates.
- macOS runs the full POSIX suite in CI as of v0.20.27-dev; this document
  previously said it was build-only and that adding it was an open billing
  decision. That decision was taken. Verified 2026-09-20.
- Living-on-Windows remains necessary regardless of CI: PATHEXT,
  USERPROFILE, 8.3 paths, the update rename lock, Windows Hello, and the
  daemon in daily use are all invisible to unit tests.
