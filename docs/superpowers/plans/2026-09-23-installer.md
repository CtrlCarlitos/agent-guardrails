# Installer Implementation Plan (agent-guardrails half)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship `install.sh`, `install.ps1` and a `guardrail setup` subcommand so that installing, upgrading, disabling and uninstalling guardrail on Linux, macOS, WSL and Windows is this repo's job, and a caller (the dotfiles) supplies only a pinned version and a desired state.

**Architecture:** Two thin bootstrap scripts (download, verify, place, PATH, Defender) that end by exec'ing `guardrail setup`. `setup` is a Go subcommand that reuses the existing plane-enable approval flow but forces a re-merge whenever the registered hook handlers differ from what the running binary generates (#317), then runs the antigravity coverage gate and `selftest`. Scripts and `SHA256SUMS` entries for them ship as release assets. A new CI job installs from a locally built `dist/` on all three OSes.

**Tech Stack:** Go 1.26 (`/usr/local/go/bin/go`), POSIX `sh`, Windows PowerShell 5.1 + PowerShell 7, bash test harnesses, GitHub Actions.

**Spec:** `docs/superpowers/specs/2026-09-23-installer-design.md` — read it first; every task below argues from it.

**Plan style (deliberate):** this plan states behaviour, file scope, exact CLI contracts, exact messages and exact test expectations. It does **not** contain implementation code, and its test descriptions are behavioural rather than literal Go. Reason: on this codebase, plans that asserted implementation without running it shipped fourteen false premises across three revisions (Phase 4, see `docs/superpowers/plans/2026-09-06-remediation-phase4.md` Revision History). The agent that runs the code writes the code. Every test named below must exist with that name and assert what is written; an executor may add tests, never drop one.

## Global Constraints

- Go version from `go.mod` (`go 1.26.0`); `gofmt` clean; `go vet ./...` clean; `go test ./...` green on Linux before every commit (baseline verified green at `e5ab7d0`).
- Conventional Commits, one commit per task, on branch `feat/installer` in worktree `.worktrees/feat-installer`. Never push, never merge, never tag — the operator does those.
- `install.sh` is POSIX `sh` (`#!/bin/sh`, `set -eu`, no bashisms); must pass `shellcheck -s sh`.
- `install.ps1` must parse under Windows PowerShell 5.1 syntax (no `??`, no ternary, no `-Parallel`); tested with PowerShell 7 on CI.
- Version argument pattern everywhere: `^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$`. `latest` is always rejected with exit 2.
- Self-update floor constant in both scripts: `v0.19.2-dev` (fixed historical fact, not a pin).
- Release base default in both scripts: `https://github.com/CtrlCarlitos/agent-guardrails/releases/download`; assets `guardrail_<os>_<arch>[.exe]` and `SHA256SUMS` under `<base>/<version>/`.
- Install destinations: `$HOME/.local/bin/guardrail` (Unix), `%USERPROFILE%\.local\bin\guardrail.exe` (Windows).
- Never install an unverified binary. Any download/verify failure leaves the destination untouched.
- Defender exclusion is the exact binary file path only (#146). Never a directory, never a process name.
- `setup`, like `plane enable`, requires an interactive local terminal and one operator approval per batch. No non-interactive fallback that writes plane configs.
- Hermetic tests only: every test that touches home/config/state uses `internal/testenv` (`testenv.SetHome/SetConfig/SetState` or `testenv.Sandbox`) and the existing `guardTestHome`. No test may write to the real `$HOME`.
- Test seams follow the repo pattern: package-level `var` function values (as `updateReleaseBase`, `submitPlaneRequest`, `planeInstalled` already are), restored by the test.
- Output strings quoted in this plan are exact; tests match them with `strings.Contains` on the full line unless stated otherwise.

---

## File map

| File | Responsibility |
|---|---|
| `cmd/guardrail/setup.go` (new) | `cmdSetup`: argument parsing, terminal and staging refusals, reconcile batch, gates, summary. |
| `cmd/guardrail/setup_drift.go` (new) | `planeHandlerDrift(plane string) (bool, error)`: does the on-disk guardrail registration match what this binary generates. |
| `cmd/guardrail/setup_test.go`, `cmd/guardrail/setup_drift_test.go` (new) | Tests for the two files above. |
| `cmd/guardrail/plane.go` | Gains the shared `installedExecutable` seam consumed by `enablePlaneIntegration` and by `setup`. |
| `cmd/guardrail/run.go` | Dispatch `setup` + usage text. |
| `install.sh`, `install.ps1` (new, repo root) | Bootstrap scripts. |
| `test/installer/install_sh_test.sh`, `test/installer/install_ps1_test.ps1`, `test/installer/README.md` (new) | Script harnesses that run against a staged local release directory. |
| `scripts/build-dist.sh`, `Makefile`, `.github/workflows/release.yml`, `.github/workflows/ci.yml` | Ship scripts as assets; CI `installer` job. |
| `README.md`, `docs/OPERATIONS.md`, `docs/adr/0029-installer-lives-in-this-repo.md` (new), `CHANGELOG.md`, `DESIGN.md`, `docs/windows-handover.md` | Docs. |

---

### Task 1: `guardrail setup` skeleton — dispatch, arguments, refusals

**Files:**
- Create: `cmd/guardrail/setup.go`, `cmd/guardrail/setup_test.go`
- Modify: `cmd/guardrail/run.go` (dispatch switch and the `usage` string), `cmd/guardrail/plane.go` (seam)

**Interfaces:**
- Produces: `func cmdSetup(args []string, terminal bool, stdout, stderr io.Writer) int` in package `main`, dispatched from `run()` exactly like `plane` (terminal derived from `stdin.(*os.File)` + `term.IsTerminal`).
- Produces: package var `installedExecutable = os.Executable` in `plane.go`. `enablePlaneIntegration` switches from calling `os.Executable()` directly to calling `installedExecutable()`; behaviour identical in production. `setup` uses the same seam for the path it prints and compares against.
- CLI contract:
  - `guardrail setup [--state enabled|disabled] [--planes claude,opencode,...]`
  - Default `--state enabled`. Any other value → stderr `guardrail: setup --state must be enabled or disabled`, exit 2.
  - `--planes` is a comma list; each must satisfy `isSupportedPlane`; otherwise stderr `guardrail: setup --planes: unsupported plane "<name>"`, exit 2. Absent → all of `supportedPlanes`.
  - Unknown flag → stderr `guardrail: setup: unknown flag "<flag>"`, exit 2.
  - Non-terminal → stderr `guardrail: setup requires an interactive local terminal (run it from your shell, not from an agent or CI)`, exit 2. Checked before any filesystem read.
  - Staging/superseded path refusal: when `filepath.Base(installedExecutable())` is `.guardrail-update`, or the base name ends in `.old` → stderr `guardrail: setup refuses to register a staging or superseded binary path: <path>`, exit 2.
  - First stdout line on success paths: `setup: registering <absolute path of installedExecutable()>`.
- Usage block gains, after the `plane` lines:
  ```
    setup [flags]                     install-time reconcile: enable planes, verify, selftest (operator approval)
        --state enabled|disabled     desired plane state (default enabled)
        --planes <list>              comma-separated subset (default: every detected plane)
  ```

- [ ] **Step 1: Write the failing tests** in `cmd/guardrail/setup_test.go`. Each uses `testenv.SetHome/SetConfig/SetState` on fresh temp dirs and `guardTestHome`. Drive the command through `run([]string{"setup", ...}, strings.NewReader(""), &out, &errb)` for the non-terminal case (a `strings.Reader` is not an `*os.File`, so `terminal` is false, as `TestPlaneDisableRequiresInteractiveTerminal` already relies on) and through `cmdSetup(args, true, &out, &errb)` for terminal cases.
  - `TestSetupRequiresInteractiveTerminal`: via `run`, exit 2, stderr contains the exact non-terminal message. Assert that no file was created under the sandboxed home (walk it; it must be empty).
  - `TestSetupRejectsBadState`: `cmdSetup([]string{"--state","maybe"}, true, ...)` → exit 2, stderr contains the exact `--state` message.
  - `TestSetupRejectsUnsupportedPlane`: `--planes claude,gemini` → exit 2, stderr contains `unsupported plane "gemini"`.
  - `TestSetupRejectsUnknownFlag`: `--verbose` → exit 2, stderr contains `unknown flag "--verbose"`.
  - `TestSetupRefusesStagingPath`: override `installedExecutable` to return `<tmp>/.guardrail-update`; `cmdSetup(nil, true, ...)` → exit 2, stderr contains `refuses to register a staging or superseded binary path`. Second sub-case with `<tmp>/guardrail.old` (and on Windows `<tmp>/guardrail.exe.old`) → same.
  - `TestSetupPrintsRegisteredPathFirst`: override `installedExecutable` to `<tmp>/bin/guardrail`, override `planeInstalled` to always return false; `cmdSetup(nil, true, ...)` → exit 0, first stdout line is exactly `setup: registering <that path>`.
  - `TestUsageMentionsSetup`: `run([]string{"help"}, ...)` stdout contains `setup [flags]`.
- [ ] **Step 2: Run** `/usr/local/go/bin/go test ./cmd/guardrail/ -run 'TestSetup|TestUsageMentionsSetup' -v` — expected: build failure or FAIL (`cmdSetup` undefined).
- [ ] **Step 3: Implement** `setup.go` (parsing, refusals, the registering line, and — for this task only — a body that, after the header line, prints `<plane>: not detected` for every target plane `planeInstalled` rejects and returns 0; the reconcile logic arrives in Task 3). Add the `installedExecutable` seam in `plane.go` and switch `enablePlaneIntegration` to it. Wire dispatch and usage in `run.go`.
- [ ] **Step 4: Run** the same command plus `go test ./cmd/guardrail/` (whole package) — expected: PASS, and every pre-existing plane test still passes.
- [ ] **Step 5: Commit** `feat(cli): guardrail setup skeleton — arguments, terminal and staging refusals`.

---

### Task 2: Handler drift — does the registration match this binary?

**Files:**
- Create: `cmd/guardrail/setup_drift.go`, `cmd/guardrail/setup_drift_test.go`

**Interfaces:**
- Produces: `func planeHandlerDrift(plane string) (drifted bool, err error)`.
- Definition of "drift" (the spec's third reconcile trigger). Let `binary` be `installedExecutable()` made absolute (same transform as `enablePlaneIntegration`). Generate the fragment exactly as `enablePlaneIntegration` would for that plane and binary (`ClaudeConfig(base, binary)`, `OpencodeConfig(base, <absolute plugin path under planePluginDir()>)`, `AntigravityConfig(binary)`, `CodexConfigFor(path, binary)`). Then:
  - **claude**: the multiset of `command` strings inside guardrail-owned hook groups (a group is guardrail-owned when its `id` has prefix `guardrail-` **or** its command text contains `hook claude` — Claude Code strips `id`) on disk must equal the multiset of `command` strings the fragment generates. Missing settings file → drift is `false` (that case is "not registered", owned by `planeIntegrationRegistered`).
  - **antigravity**: same rule over the `guardrail` object's event arrays, using `hook antigravity`.
  - **codex**: same rule over `command` **and** `commandWindows` in groups whose `id` has prefix `guardrail-codex-`; additionally the wrapper file `<dir(hooks.json)>/guardrail-hook.cmd` must exist and its bytes must equal `genconfig.CodexWrapperContent(binary)`.
  - **opencode**: the `plugin` array entry whose basename is `guardrail.js` must equal (after `filepath.Clean`) the absolute expected plugin path, and that file's bytes must equal `genconfig.OpencodePluginFor(binary)`.
  - Any read error other than not-exist is returned as `err`; a JSON parse failure is `err`.
- [ ] **Step 1: Write the failing tests** in `setup_drift_test.go`. Every test sandboxes home/config/state, overrides `installedExecutable` to a fixed absolute path `A` inside the sandbox (create an empty file there), and uses the real `enablePlaneIntegration(plane)` to produce a matching on-disk registration where needed (it is exercised this way already by `TestExecutePlaneApprovalEnables*`).
  - `TestHandlerDriftFalseRightAfterEnable`: for each of the four planes: run `enablePlaneIntegration(plane)`, then `planeHandlerDrift(plane)` → `(false, nil)`.
  - `TestHandlerDriftTrueWhenBinaryPathChanged`: for each plane: enable with `installedExecutable` = `A`, then switch the seam to `B` (a sibling path) → `(true, nil)`.
  - `TestHandlerDriftIgnoresStrippedClaudeIDs`: enable claude, then rewrite `~/.claude/settings.json` removing every `id` key from hook groups (simulating Claude Code's serializer) → `(false, nil)`.
  - `TestHandlerDriftTrueWhenCodexWrapperMissing`: enable codex, delete `guardrail-hook.cmd` → `(true, nil)`.
  - `TestHandlerDriftTrueWhenCodexWrapperStale`: enable codex, overwrite the wrapper with `CodexWrapperContent("C:\\elsewhere\\guardrail.exe")` → `(true, nil)`.
  - `TestHandlerDriftTrueWhenOpencodePluginStale`: enable opencode, overwrite `guardrail.js` with `OpencodePluginFor(B)` → `(true, nil)`.
  - `TestHandlerDriftFalseWhenSettingsMissing`: no settings file for the plane → `(false, nil)` for all four planes.
  - `TestHandlerDriftErrorsOnUnparseableSettings`: write `{not json` to the claude path → `err != nil`.
- [ ] **Step 2: Run** `go test ./cmd/guardrail/ -run TestHandlerDrift -v` — expected FAIL (undefined).
- [ ] **Step 3: Implement** `setup_drift.go` to the definition above. Reuse `planeConfigPath`, `planePluginDir`, `policy.LoadBase`, and the `genconfig` generators; do not duplicate hook-command formatting.
- [ ] **Step 4: Run** `go test ./cmd/guardrail/` — expected PASS. Also run `go test ./cmd/guardrail/ -run 'TestHandlerDrift' -count=3` to catch order dependence.
- [ ] **Step 5: Commit** `feat(setup): detect registered handlers that differ from this binary (#317)`.

---

### Task 3: `setup --state enabled` — reconcile, approve once, gate, selftest

**Files:**
- Modify: `cmd/guardrail/setup.go`, `cmd/guardrail/setup_test.go`

**Interfaces:**
- Consumes: `planeHandlerDrift` (Task 2), `planeIntegrationRegistered`, `planeFloorDrift`, `planeInstalled`, `planesViaApproval(planes, "plane-enable", "enabled", stdout, stderr) bool`, `planeStatusState`.
- Produces three seams in `setup.go`, each a package `var`:
  - `setupAgyPresent = func() bool { _, err := exec.LookPath("agy"); return err == nil }`
  - `setupDoctorCoverage = func(stdout, stderr io.Writer) int { return cmdDoctor([]string{"--coverage", "antigravity"}, stdout, stderr) }`
  - `setupSelftest = func(stdout, stderr io.Writer) int { return cmdSelftest(nil, stdout, stderr) }`
- Behaviour, after the `setup: registering <path>` line, for `--state enabled`:
  1. For each target plane in `supportedPlanes` order: if `!planeInstalled(plane)` → stdout `<plane>: not detected`, skip. Else compute the reason, first match wins:
     - not `planeIntegrationRegistered` → stdout `<plane>: not registered; enabling`, add to batch.
     - `planeFloorDrift(plane) > 0` → stdout `<plane>: permissions floor drifted (<n> entries missing); re-enabling`, add.
     - `planeHandlerDrift(plane)` returns `(true, nil)` → stdout `<plane>: registered handlers differ from this binary; re-enabling`, add.
     - `planeHandlerDrift` returns an error → stderr `guardrail: setup: <plane>: <err>`, return 1 (nothing has been prompted yet).
     - otherwise → stdout `<plane>: already enabled`.
  2. If the batch is non-empty: `planesViaApproval(batch, "plane-enable", "enabled", stdout, stderr)`; on `false` return 1.
  3. If `setupAgyPresent()`: run `setupDoctorCoverage`; non-zero → stderr `guardrail: setup: doctor --coverage antigravity failed (exit <n>)`, return 1.
  4. Run `setupSelftest`; non-zero → stderr `guardrail: setup: selftest failed on this binary; investigate before continuing`, return 1.
  5. Print `setup: plane status` then one `<plane>: <planeStatusState(plane)>` line per target plane. Return 0.
- [ ] **Step 1: Write the failing tests** (all terminal=true, sandboxed, `installedExecutable` overridden to a real empty file `A`, `stubPlaneTransport(t, []string{"approved"})` where an approval is expected, `planeInstalled` overridden per test, and the three seams overridden to record calls and return chosen exit codes; restore all seams with `t.Cleanup`).
  - `TestSetupEnablesUnregisteredPlanes`: `planeInstalled` true for `claude` only; no settings file. Expect exit 0; stdout contains `claude: not registered; enabling`, then the stub's `approval required; open http://localhost:39169/approve` line, then `claude enabled`; afterwards `planeIntegrationRegistered("claude")` is true; the recorded selftest call count is 1; doctor-coverage call count is 0 (agy absent).
  - `TestSetupSkipsConsistentPlanes`: enable claude first via `enablePlaneIntegration`; expect stdout `claude: already enabled`, **no** `approval required` line (transport stub with an empty status list would return `expired`, so the absence of a prompt is provable: exit must be 0).
  - `TestSetupReenablesOnHandlerDrift`: enable claude with seam = `A`, then set seam = `B`; expect stdout `claude: registered handlers differ from this binary; re-enabling`, approval, exit 0, and after the run the settings' hook commands reference `B` not `A`.
  - `TestSetupOneApprovalForTheBatch`: `planeInstalled` true for claude and antigravity, neither registered; count `submitPlaneRequest` invocations = 1 and its `Parameters["planes"]` equals `claude,antigravity`.
  - `TestSetupDeniedApprovalFails`: stub statuses `[]string{"denied"}`; exit 1; selftest call count 0.
  - `TestSetupRunsAntigravityGateWhenAgyPresent`: `setupAgyPresent` → true, coverage seam returns 0, selftest 0 → exit 0, coverage call count 1.
  - `TestSetupFailsWhenAntigravityGateFails`: coverage seam returns 1 → exit 1, stderr contains `doctor --coverage antigravity failed (exit 1)`, selftest call count 0.
  - `TestSetupFailsWhenSelftestFails`: selftest seam returns 1 → exit 1, stderr contains `selftest failed on this binary`.
  - `TestSetupHonoursPlanesSubset`: `planeInstalled` true for all four; `--planes opencode`; stdout has exactly one reason line and it starts with `opencode:`; no line starts with `claude:` before the `setup: plane status` marker.
  - `TestSetupPrintsPlaneStatusLast`: last lines of stdout are `setup: plane status` followed by one line per target plane in `supportedPlanes` order.
- [ ] **Step 2: Run** `go test ./cmd/guardrail/ -run TestSetup -v` — expected FAIL.
- [ ] **Step 3: Implement** the enabled flow in `setup.go` per the behaviour list.
- [ ] **Step 4: Run** `go test ./cmd/guardrail/` and `go vet ./cmd/guardrail/` — expected PASS.
- [ ] **Step 5: Commit** `feat(setup): reconcile every detected plane against this binary, gate on coverage and selftest`.

---

### Task 4: `setup --state disabled`

**Files:**
- Modify: `cmd/guardrail/setup.go`, `cmd/guardrail/setup_test.go`

**Interfaces:**
- Consumes: `planesViaApproval(batch, "plane-disable", "disabled", ...)`, `planeIntegrationRegistered`.
- Behaviour after the header line: for each target plane, if `planeInstalled && planeIntegrationRegistered` → stdout `<plane>: registered; disabling`, add to batch; else if `planeInstalled` → stdout `<plane>: already disabled`; else `<plane>: not detected`. One `planesViaApproval` for the batch (skip when empty). No coverage gate, no selftest. Then the `setup: plane status` block. Exit 0 / 1 as in Task 3.
- [ ] **Step 1: Write the failing tests**:
  - `TestSetupDisableRemovesRegisteredPlanes`: enable claude and antigravity via `enablePlaneIntegration`; `--state disabled` with stub `approved`; exit 0; both `planeIntegrationRegistered` false afterwards; selftest call count 0; `submitPlaneRequest` called once with `Action == "plane-disable"` and planes `claude,antigravity`.
  - `TestSetupDisableIsNoOpWhenNothingRegistered`: nothing registered; exit 0; stdout contains `claude: already disabled`; no `approval required` line.
  - `TestSetupDisableDeniedFails`: stub `denied`; exit 1; claude still registered.
- [ ] **Step 2: Run** `go test ./cmd/guardrail/ -run TestSetupDisable -v` — expected FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** `go test ./cmd/guardrail/` — expected PASS. Then run the full suite once: `go test ./...` — expected PASS.
- [ ] **Step 5: Commit** `feat(setup): --state disabled removes every registered plane with one approval`.

---

### Task 5: `install.sh` and its harness

**Files:**
- Create: `install.sh`, `test/installer/install_sh_test.sh`, `test/installer/README.md`
- Modify: `Makefile` (target `installer-test`)

**Interfaces:**
- CLI contract (exact):
  ```
  install.sh --version <tag> [--state enabled|disabled] [--dest <dir>] [--base-url <url-or-dir>] [--no-setup]
  install.sh --uninstall [--purge] [--dest <dir>] [--no-setup]        (Task 7)
  install.sh --help
  ```
  - Exit 2: missing `--version` (when not `--uninstall`), version not matching the pattern (message must contain `exact release tag` and `latest`), unsupported OS/arch (message lists `linux/darwin` and `amd64/arm64`), unknown flag, `--state` with `--uninstall`, missing `curl`, no SHA-256 tool.
  - Exit 1: download failure, checksum mismatch (message contains `CHECKSUM MISMATCH`), install failure, post-install version check failure (message contains `did not report guardrail <version>`).
  - Otherwise the exit code is `guardrail setup`'s (or 0 with `--no-setup`).
  - Every message is prefixed `install: `. Progress goes to stdout, failures to stderr.
- Flow for `--state enabled` (default): exactly the spec's steps 1–7. Notes the executor must honour:
  - OS map: `Linux`→`linux`, `Darwin`→`darwin`; arch map: `x86_64|amd64`→`amd64`, `aarch64|arm64`→`arm64`.
  - Installed-version probe: `"$dest/guardrail" version 2>/dev/null` must print `guardrail <version>` exactly to count as already installed.
  - Floor comparison: parse `vMAJOR.MINOR.PATCH` (strip any `-suffix`), compare numerically field by field (no `sort -V`, macOS lacks it).
  - `--base-url` may be `http://`, `https://`, `file://<dir>` or a plain directory. For http(s): `curl -fsSL --max-time 180`. For a directory: `cp`. Same `<base>/<version>/<asset>` layout in both.
  - Verification: `grep " <asset>$" SHA256SUMS | <sha tool> -c -` run inside the temp dir; sha tool resolved in order `sha256sum`, `gsha256sum`, `shasum -a 256`.
  - Install: `mkdir -p "$dest"` then `install -m 0755`. Temp dir removed on every path (`trap`).
  - Step 7 exec: `exec "$dest/guardrail" setup` or `exec "$dest/guardrail" setup --state disabled`. With `--no-setup`, print `install: guardrail <version> installed at <dest>/guardrail (setup skipped)` and exit 0.
- Harness contract (`test/installer/install_sh_test.sh`, bash, `set -euo pipefail`): requires env `DIST` pointing at a directory containing `guardrail_*` assets, `SHA256SUMS`, and `install.sh` (what `make dist` produces after Task 8; until then the harness stages them itself from `./scripts/build-dist.sh` output). It stages `<tmp>/releases/<VERSION>/` (default `VERSION=v0.0.0-ci`), copies assets and `SHA256SUMS` there, and runs every case with `--base-url <tmp>/releases --no-setup`. Prints `PASS: <case>` / `FAIL: <case>` lines and exits 1 on any FAIL. Cases (names are the literal case labels):
  - `bootstrap-installs-and-verifies`: fresh `--dest`; exit 0; `<dest>/guardrail version` prints `guardrail v0.0.0-ci`; mode is `0755`.
  - `already-at-version-skips-download`: run again with `--base-url <tmp>/empty` (a directory with no release); exit 0; stdout contains `already installed`.
  - `latest-is-rejected`: `--version latest`; exit 2; nothing created in a fresh dest.
  - `tampered-checksum-refuses`: stage a copy of the release where `SHA256SUMS` has the asset's hash altered; exit 1; stderr contains `CHECKSUM MISMATCH`; fresh dest still has no `guardrail`.
  - `missing-sums-refuses`: stage without `SHA256SUMS`; exit 1; dest untouched.
  - `disabled-with-no-binary-is-noop`: `--state disabled` on a fresh dest with the empty base; exit 0; stdout contains `nothing to do`; no download attempted (dest stays empty).
  - `existing-at-or-above-floor-uses-self-update`: place a fake `<dest>/guardrail` shell script that answers `version` by printing `guardrail $(cat "$dest/.fake-version")`, answers `update <v>` by appending the args to `$dest/update.log` and writing `<v>` to `.fake-version`, and answers `setup` by exiting 0. Seed `.fake-version` with `v0.19.2-dev`. Run `--version v0.0.0-ci`; exit 0; `update.log` contains `update v0.0.0-ci`; no curl/cp of an asset happened (the release dir may be the empty one).
  - `existing-below-floor-bootstraps`: same fake seeded with `v0.3.0`; run with the real release dir; exit 0; `<dest>/guardrail` is now the real binary (`version` prints `guardrail v0.0.0-ci`); `update.log` absent.
  - `unsupported-arch-exits-2`: run with `uname` shadowed by a PATH-prefixed fake printing `Linux` / `mips`; exit 2.
  - `shellcheck`: `shellcheck -s sh install.sh` exits 0 (case is skipped with a `SKIP:` line when shellcheck is absent locally; CI has it).
- `Makefile`: `installer-test: dist` runs `DIST=dist bash test/installer/install_sh_test.sh`.
- `test/installer/README.md`: how to run locally (`make installer-test`), what the harness stages, why `--no-setup` (setup needs a TTY and an operator passkey), and that the self-update branch on Windows is covered by review, not by the harness (Task 6).
- [ ] **Step 1: Write the harness** with all cases; run `DIST=... bash test/installer/install_sh_test.sh` — expected: every case FAIL or the harness aborts because `install.sh` is missing.
- [ ] **Step 2: Write `install.sh`** to the contract.
- [ ] **Step 3: Run** `./scripts/build-dist.sh` with `VERSION=v0.0.0-ci` then `DIST=dist bash test/installer/install_sh_test.sh` — expected all `PASS`. Run `shellcheck -s sh install.sh` — clean.
- [ ] **Step 4: Manual probe against the real release (read-only):** `sh install.sh --version v0.23.0-dev --dest "$(mktemp -d)" --no-setup` must exit 0 and the installed binary must print `guardrail v0.23.0-dev`. Do not run it without `--dest`; the operator's real install is not a fixture.
- [ ] **Step 5: Commit** `feat(installer): install.sh — pinned, checksum-verified bootstrap that hands off to guardrail setup`.

---

### Task 6: `install.ps1` and its harness

**Files:**
- Create: `install.ps1`, `test/installer/install_ps1_test.ps1`
- Modify: `test/installer/README.md`, `Makefile` (`installer-test-windows` target: `pwsh -NoProfile -File test/installer/install_ps1_test.ps1`)

**Interfaces:**
- Parameters mirror Task 5 with PowerShell spelling: `-Version`, `-State enabled|disabled`, `-Dest`, `-BaseUrl`, `-NoSetup`, `-Uninstall`, `-Purge` (Task 7), `-Help`. Same exit codes and the same message texts (prefix `install: `). `$ErrorActionPreference = 'Stop'` with explicit try/catch at every native-command boundary (the repo's PS 5.1 lesson: native stderr is a terminating error under Stop).
- Flow differences from Unix, all from the spec:
  - Arch from `$env:PROCESSOR_ARCHITECTURE` (`ARM64`→`arm64`, else `amd64`); asset `guardrail_windows_<arch>.exe`.
  - Download: `Invoke-WebRequest -UseBasicParsing` for http(s); `Copy-Item` for a directory or `file://` base.
  - Verify: `Get-FileHash -Algorithm SHA256`, compared case-insensitively against the `SHA256SUMS` line anchored on ` <asset>$` (tolerate a trailing CR).
  - Install: `New-Item -ItemType Directory -Force`, `Copy-Item -Force`, `Unblock-File`. Then append `<dest>` to the **User** `Path` only if no existing entry equals it (exact match after trimming a trailing backslash), and also to the current process PATH.
  - Existing binary at or above the floor → `& "<dest>\guardrail.exe" update <version>` (works on Windows: rename-aside, CI-mandatory fixture `TestUpdateHappyPathReplacesBinary`).
  - Defender: `Get-MpPreference` / `Add-MpPreference -ExclusionPath <exe>` inside try/catch; on failure print `install: warning: could not add the Defender exclusion (needs an elevated shell); run:` followed by the exact `Add-MpPreference -ExclusionPath "<exe>"` line, and continue.
  - Hand-off: `& "<dest>\guardrail.exe" setup [--state disabled]`; exit with `$LASTEXITCODE`.
- Harness (`test/installer/install_ps1_test.ps1`, runs under `pwsh`): same staging as Task 5 from `$env:DIST`; cases `bootstrap-installs-and-verifies` (also asserts the dest was added to the *process* PATH; the User-PATH write is asserted by reading it back and then restored to its prior value in `finally`), `already-at-version-skips-download`, `latest-is-rejected`, `tampered-checksum-refuses`, `missing-sums-refuses`, `disabled-with-no-binary-is-noop`, `parses-under-windows-powershell-syntax` (uses `[System.Management.Automation.Language.Parser]::ParseFile` and fails on any parse error; additionally greps the script for `??`, `?.` and `-Parallel` and fails if present). The self-update branch is **not** harnessed on Windows (no way to fake an `.exe`); the README says so and points at the Unix case. When the harness runs under `pwsh` on a non-Windows host (`$IsWindows -eq $false`, as on the developer's Linux box) it runs only `parses-under-windows-powershell-syntax` and prints `SKIP:` for every other case, so the local loop is parse-only and the behavioural cases run on the Windows CI runner.
- [ ] **Step 1: Write the harness**; run it (locally only if `pwsh` exists; otherwise note it will first run on CI in Task 8) — expected FAIL / script missing.
- [ ] **Step 2: Write `install.ps1`.**
- [ ] **Step 3: Run** the harness under `pwsh` if available; at minimum run the parse case via `pwsh -NoProfile -Command "[System.Management.Automation.Language.Parser]::ParseFile('install.ps1',[ref]$null,[ref]$e); $e"` and require empty output. If `pwsh` is not installed locally, record that in the commit message body and rely on the CI job from Task 8; the task is not complete until that CI run is green.
- [ ] **Step 4: Commit** `feat(installer): install.ps1 — Windows bootstrap with Unblock-File, user PATH and scoped Defender exclusion`.

---

### Task 7: Uninstall in both scripts

**Files:**
- Modify: `install.sh`, `install.ps1`, both harnesses, `test/installer/README.md`

**Interfaces:**
- `--uninstall` / `-Uninstall`: if the binary exists at `<dest>` and `--no-setup` is absent → run `<dest>/guardrail setup --state disabled`; a non-zero exit aborts the uninstall with exit 1 and message `install: uninstall aborted: planes are still registered`. Then remove, in order: the binary; `guardrail.js` under the plugin dir (`${XDG_DATA_HOME:-$HOME/.local/share}/guardrail` or `%USERPROFILE%\.local\share\guardrail`; Windows only that path, matching `planePluginDir`); on Windows the User-PATH entry equal to `<dest>` and the Defender exclusion (`Remove-MpPreference`, try/catch, warn on failure). Print `install: guardrail removed from <dest>`.
- `--purge` / `-Purge` (only with uninstall, else exit 2): additionally remove `${XDG_STATE_HOME:-$HOME/.local/state}/guardrail`, `${XDG_CONFIG_HOME:-$HOME/.config}/guardrail`, `${XDG_DATA_HOME:-$HOME/.local/share}/guardrail`; on Windows `%LOCALAPPDATA%\guardrail`, `%APPDATA%\guardrail`, `%USERPROFILE%\.local\state\guardrail`, `%USERPROFILE%\.local\share\guardrail`. Print one `install: removed <path>` line per directory that existed.
- With no binary at `<dest>`: `--uninstall` prints `install: nothing installed at <dest>` and exits 0 (purge still runs if requested).
- Harness cases (both scripts; the sandboxed roots are set via `XDG_*`/`HOME` on Unix and `USERPROFILE`/`LOCALAPPDATA`/`APPDATA` on Windows so nothing real is touched):
  - `uninstall-removes-binary-and-plugin`: install (`--no-setup`), create a fake `guardrail.js` in the sandboxed plugin dir, run `--uninstall --no-setup`; exit 0; binary and plugin gone; state dir (pre-created with a marker file) still present.
  - `uninstall-purge-removes-state-roots`: pre-create every root with a marker; `--uninstall --purge --no-setup`; exit 0; every root gone.
  - `uninstall-nothing-installed-is-ok`: fresh dest; exit 0; message contains `nothing installed`.
  - `purge-without-uninstall-exits-2`.
  - `uninstall-aborts-when-disable-fails` (Unix only, via the fake binary whose `setup` exits 1): exit 1; binary still present.
- [ ] **Step 1: Add the cases** to both harnesses — expected FAIL.
- [ ] **Step 2: Implement** in both scripts.
- [ ] **Step 3: Run** both harnesses (Windows one where possible) and `shellcheck -s sh install.sh` — expected PASS.
- [ ] **Step 4: Commit** `feat(installer): --uninstall and --purge`.

---

### Task 8: Ship the scripts as release assets; CI `installer` job

**Files:**
- Modify: `scripts/build-dist.sh`, `.github/workflows/release.yml`, `.github/workflows/ci.yml`, `Makefile`

**Interfaces:**
- `build-dist.sh`: after building the binaries, `cp install.sh install.ps1 "$OUT/"`; `SHA256SUMS` is generated over `guardrail_* install.sh install.ps1`; the sha tool is resolved as `sha256sum` then `shasum -a 256` (macOS runners). Output of `cat SHA256SUMS` must list 8 lines.
- `release.yml`: the `gh release create` line uploads `dist/guardrail_* dist/install.sh dist/install.ps1 dist/SHA256SUMS`; the attestation `subject-path` gains `dist/install.sh` and `dist/install.ps1` (multi-line `subject-path` is supported by that action).
- `ci.yml`: new job `installer`, `needs: []`, matrix `[ubuntu-latest, macos-latest, windows-latest]`, steps: checkout (same pinned SHA as the existing jobs), setup-go (same), `VERSION=v0.0.0-ci ./scripts/build-dist.sh` (`shell: bash` on all three, Git Bash on Windows), then `DIST=dist bash test/installer/install_sh_test.sh` on ubuntu/macos, and `$env:DIST='dist'; pwsh -NoProfile -File test/installer/install_ps1_test.ps1` on windows. On ubuntu also `shellcheck -s sh install.sh` as its own step.
- `Makefile`: `dist` unchanged; `installer-test` and `installer-test-windows` from Tasks 5/6; `check` gains `installer-test` only on Linux (`ifeq ($(shell uname -s),Linux)` guard) so `make check` stays runnable on macOS without Docker.
- [ ] **Step 1: Write a harness case** `sums-cover-the-scripts` in `install_sh_test.sh`: `grep -c ' install\.\(sh\|ps1\)$' "$DIST/SHA256SUMS"` equals 2. Run — expected FAIL.
- [ ] **Step 2: Implement** the four file changes.
- [ ] **Step 3: Run** `VERSION=v0.0.0-ci ./scripts/build-dist.sh && DIST=dist bash test/installer/install_sh_test.sh` — expected all PASS. Validate the workflow YAML parses: `python3 -c "import yaml,sys; yaml.safe_load(open('.github/workflows/ci.yml')); yaml.safe_load(open('.github/workflows/release.yml'))"`.
- [ ] **Step 4: Commit** `ci(installer): ship install scripts as checksummed release assets and test them on all three OSes`.
- [ ] **Step 5: Push is the operator's call.** Report that the Windows harness has not run until the branch is pushed and CI runs; the operator pushes the branch (not this plan) and the executor reads the CI result before Task 9 is marked complete.

---

### Task 9: Documentation

**Files:**
- Modify: `README.md` (Install section, lines 45–100 region, and the planes table's "How it's wired" cell wording only where it says `gen-config`), `docs/OPERATIONS.md`, `CHANGELOG.md`, `DESIGN.md` (Distribution & install), `docs/windows-handover.md`
- Create: `docs/adr/0029-installer-lives-in-this-repo.md`

**Content requirements (each is checked by review, not by a test):**
- README Install becomes: one Unix block and one Windows block that download the pinned tag's script and `SHA256SUMS`, verify the script (`grep " install.sh$" SHA256SUMS | sha256sum -c -` / `Get-FileHash` compare), and run it with `--version <tag>`; a short "what it does" list (download, verify, place, PATH, Defender on Windows, then `guardrail setup` which needs your passkey); the enrol-once note stays; the four `gen-config` lines are removed; `guardrail update <version>` prose now says "then run `guardrail setup` to reconcile the registered handlers" (or "the installer does both"). The example tag is the next release tag the operator will cut; write it as `vX.Y.Z-dev` placeholder text **only in the ADR**; in README use the current `v0.23.0-dev` and note the operator bumps it at release time.
- OPERATIONS.md: new section `## Install, update, disable, uninstall` with the four commands, the `--no-setup` escape hatch, and uninstall/purge semantics including the three Windows state roots; the "Where things live" table gains `install.sh` / `install.ps1` (release assets) and the ownership manifests row if absent; the symptom table gains `registered handlers differ from this binary` → `guardrail setup`.
- ADR-0029: context (four copies in the dotfiles, #317, the two false premises), decision (the contract table from the spec), the `setup` reconcile rule, rejected alternatives (from the spec), consequences (dotfiles shrink to a call; a binary swap is followed by `setup`; CI installs from `dist/` on three OSes). Status: Accepted (operator, 2026-09-23).
- CHANGELOG: new `## Unreleased` section at the top with theme `### Installation` listing `install.sh`, `install.ps1`, `guardrail setup`, `#317` closure, release assets, CI job.
- DESIGN.md "Distribution & install": replace the "Dotfiles installer: a new gated, idempotent function…" bullet and the "Per-plane wiring: `jq`-merge…" bullet with two bullets that describe `install.sh`/`install.ps1` + `setup` and say the dotfiles call the pinned script.
- windows-handover.md: correct the two stale statements that `guardrail update` fails on Windows; point at ADR-0021 step (d) and the CI fixture.
- [ ] **Step 1: Make the edits.**
- [ ] **Step 2: Verify** no doc still tells a user to run `gen-config … --merge` as the install step: `grep -rn 'gen-config' README.md docs/OPERATIONS.md` must show only recovery/diagnostic uses. `grep -n 'update.*fails\|broken on Windows' docs/windows-handover.md` must be empty.
- [ ] **Step 3: Commit** `docs: install lives here — README one-liners, OPERATIONS runbook, ADR-0029, changelog`.

---

## Self-review against the spec

- Contract table → Tasks 5/6 (scripts), 3/4 (setup), 9 (docs). ✔
- Script flags: `--version`, `--state`, `--uninstall`, `--purge`, `--dest`, `--base-url`, `--no-setup` → Tasks 5/6/7. ✔
- Flow steps 1–7 incl. floor, sha tool fallback, `Unblock-File`, PATH, Defender → Tasks 5/6. ✔
- `setup` preconditions (installed path, staging refusal, TTY) → Task 1. Reconcile triggers incl. handler drift → Tasks 2/3. Coverage gate + selftest → Task 3. `--state disabled` → Task 4. `--planes` → Tasks 1/3. ✔
- Release assets + SHA256SUMS + CI matrix + shellcheck + PS parse → Tasks 6/8. Go tests hermetic → every Go task. ✔
- Docs list → Task 9. ✔
- Out of scope items untouched. ✔

## Hand-off to the dotfiles half

Only after the operator merges this branch and tags a release. The dotfiles plan (written then, in `~/.local/share/chezmoi`) replaces the four blocks with fetch-verify-run of `install.sh`/`install.ps1` at the pinned tag, bumps `.chezmoidata.yaml guardrail.version` to that tag, rewrites `tests/guardrail_lifecycle_contract.sh` and `tests/update_guardrail_versions.sh`, and rewrites `docs/guardrail-install.md` and `docs/tool-parity.md`.
