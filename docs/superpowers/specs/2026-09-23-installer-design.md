# Installer lives here: `install.sh`, `install.ps1`, `guardrail setup`

**Status:** design, approved by the operator 2026-09-23 (sections 1–3 in
chat). Companion plan: `docs/superpowers/plans/2026-09-23-installer.md`.
Cross-repo: the dotfiles half is a separate plan in
`~/.local/share/chezmoi` and lands after this repo tags a release.

## Problem

Installing guardrail is spread across four copies of the same logic in
the dotfiles repo (`run_onchange_install_packages.{sh,ps1}.tmpl`,
`scripts/update_ai_tools.{sh,ps1}`): OS/arch detection, asset download,
SHA256SUMS verification, install path, Windows PATH persistence,
`Unblock-File`, the exact-file Defender exclusion (#132, #146), the
self-update floor (`v0.19.2-dev`), a version-number comparator, the
four-plane `gen-config --merge` sequence on Windows, and the
`doctor --coverage antigravity` gate. Two dotfiles contract tests lock
that duplication in place. This repo has no installer at all: the README
is a hand-typed curl block, and `guardrail plane enable` skips a plane
that is already registered unless its permissions floor drifted, so a
binary upgrade that changes the hook command shape leaves stale handlers
in place (#317).

Two premises the dotfiles still encode are false on `origin/main`:
`plane` commands do not exit 2 on Windows (ADR-0021 step (d) landed),
and `guardrail update` works on Windows (rename-aside, CI-mandatory
fixture). The Windows-only `gen-config` path in the dotfiles therefore
also skips `WriteCodexWrapper`, leaving Windows Codex on the
`-EncodedCommand` form ADR-0024 replaced.

## Decision

Installation is this project's responsibility. The dotfiles become a
caller that supplies exactly two facts: the pinned version and the
desired state.

### The contract

| Concern | Owner |
|---|---|
| Pinned release tag | dotfiles (`.chezmoidata.yaml` `guardrail.version`) |
| Desired state (`enabled` / `disabled`) | dotfiles (`packages.guardrail`) |
| Fetching the pinned tag's install script and verifying it against that tag's `SHA256SUMS` | dotfiles (a few lines, both twins) |
| Everything after that | this repo |

"Everything after that" means: OS/arch detection, asset download and
verification, binary placement, PATH, `Unblock-File`, Defender
exclusion, choosing bootstrap vs `guardrail update`, plane wiring,
reconciliation after a binary swap, coverage gates, selftest, disable,
uninstall.

### Components

**`install.sh`** — POSIX `sh` (not bash), Linux / macOS / WSL.
**`install.ps1`** — Windows PowerShell 5.1 and PowerShell 7.
Both live at the repo root, are copied into `dist/` by
`scripts/build-dist.sh`, and are listed in `SHA256SUMS` next to the
binaries. A caller fetches `releases/download/<tag>/install.sh` and
`SHA256SUMS`, verifies the script, runs it. The scripts are deliberately
thin; anything that can be Go is Go.

**`guardrail setup`** — a new subcommand that is the post-install
reconcile seam. Scripts end by exec'ing it.

### `install.sh` / `install.ps1` behaviour

Flags (identical names in both; PowerShell uses `-Version` style):

| Flag | Meaning |
|---|---|
| `--version <tag>` | **Required.** Exact release tag matching `^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$`. `latest` is rejected. |
| `--state enabled\|disabled` | Desired plane state. Default `enabled`. |
| `--uninstall` | Disable all planes, remove the binary and installer-owned side effects. Mutually exclusive with `--state`. |
| `--purge` | With `--uninstall`: also remove guardrail's state and operator-config directories. |
| `--dest <dir>` | Install directory. Default `$HOME/.local/bin` / `%USERPROFILE%\.local\bin`. |
| `--base-url <url>` | Release base. Default `https://github.com/CtrlCarlitos/agent-guardrails/releases/download`. A `file://` URL or a local directory is accepted so CI can install from `dist/`. |
| `--no-setup` | Stop after the binary is in place and verified. For CI and for operators who want to run `setup` themselves. |

Flow, `--state enabled` (the default):

1. Resolve `os`/`arch` → asset name (`guardrail_<os>_<arch>[.exe]`).
   Unsupported → exit 2 with the supported list. `uname -s`/`uname -m`
   on Unix; `PROCESSOR_ARCHITECTURE` on Windows.
2. If `<dest>/guardrail[.exe] version` already prints
   `guardrail <version>` → skip to step 5.
3. If an installed binary exists and its version is at or above the
   self-update floor `v0.19.2-dev` → run `<dest>/guardrail update
   <version>`. This is the sanctioned replacement path (#146,
   OPERATIONS.md) and it already verifies SHA256SUMS, run-verifies the
   staged binary, and restarts the approval broker. The floor is a
   fixed historical constant in the script, not a pin.
4. Otherwise bootstrap: download asset + `SHA256SUMS` into a temp dir,
   verify with `sha256sum` / `gsha256sum` / `shasum -a 256` (Unix) or
   `Get-FileHash` (Windows), install `0755` / `Copy-Item` +
   `Unblock-File`. Never install unverified: any failure leaves `<dest>`
   untouched and exits non-zero. On Windows, append `<dest>` to the
   user PATH if absent.
5. Verify `<dest>/guardrail version` prints `guardrail <version>`, else
   exit 1.
6. Windows only: ensure the Defender exclusion for the exact binary file
   path (`Add-MpPreference -ExclusionPath <exe>`), idempotent via
   `Get-MpPreference`. Non-admin → print the exact command as a warning
   and continue. Never a directory or process-name exclusion (#146).
7. Unless `--no-setup`: exec `<dest>/guardrail setup` (or
   `setup --state disabled`). The script's exit code is `setup`'s.

`--state disabled`: steps 1–2 only decide whether a binary exists. No
download ever happens. If a binary exists, exec `guardrail setup --state
disabled`; otherwise print "nothing to do" and exit 0.

`--uninstall`: if a binary exists, run `guardrail setup --state disabled`
(operator approval, like any disable), then remove the binary, the
opencode plugin file under the plane plugin dir, the Windows user-PATH
entry the installer added, and the Defender exclusion. State
(`$XDG_STATE_HOME/guardrail`, `%LOCALAPPDATA%\guardrail`), operator
config (`$XDG_CONFIG_HOME/guardrail`, `%APPDATA%\guardrail`) and the
Windows `%USERPROFILE%\.local\state\guardrail` root are kept unless
`--purge`. Uninstall never touches plane settings files beyond what
`plane disable` restores from the manifest.

Output streams through untouched. `plane` approval prompts print their
WebAuthn URL and block; the installer must never silence or background
them.

### `guardrail setup`

```
guardrail setup [--state enabled|disabled] [--planes <list>]
```

Preconditions:

- Runs from its installed location: `os.Executable()` resolves to a
  file the caller can run again later. `setup` refuses (exit 2) when it
  is running from the updater's staging or superseded names (basename
  `.guardrail-update`, or a `.old` suffix), because
  `enablePlaneIntegration` bakes `os.Executable()` into every hook
  command. It prints the path it will register so an operator running
  it from an unexpected place sees it before approving.
- Requires an interactive local terminal, exactly like `plane enable`
  (the same `terminal` check in `run.go`). Non-TTY → exit 2 with the
  message naming the fix. This keeps ADR-0021's "registering a host is
  operator-only" intact; the dotfiles CI seeds already set
  `guardrail = false` for this reason.

`--state enabled` (default), for every supported plane that
`planeInstalled` detects (or the `--planes` subset):

1. **Reconcile, don't skip.** A plane counts as needing enable when
   any of: not registered; permissions floor drifted (existing check);
   **the registered hook command differs from what this binary
   generates** — compare the on-disk `guardrail-*` hook groups (and the
   codex wrapper / opencode plugin entry) against the fresh
   `<Plane>Config(base, binary)` output, ignoring keys the host
   serializer strips (`id`). Any difference re-merges. This closes
   #317: a binary swap followed by `setup` always leaves handlers that
   match the running binary.
2. One broker approval for the whole batch (existing
   `planesViaApproval`). Already-consistent planes print `already
   enabled` and do not prompt.
3. After the merge: `doctor --coverage antigravity` when `agy` is on
   PATH (its non-zero exit is `setup`'s exit; agy has no SessionStart
   surface, so this is the only "someone ran it" moment). Then
   `selftest`; a failed selftest is reported loudly and is a non-zero
   exit.
4. Print a one-line-per-plane summary in the `plane status` format.

`--state disabled`: `plane disable` for every plane that is registered
(one approval), then `plane status`. Nothing else.

`setup` does not download, does not touch PATH, does not touch Defender.
Those are the scripts' job because they need to happen before a binary
exists or need shell/OS facilities the binary deliberately avoids
(no elevation, ADR-0021 §7).

### Release and CI

- `scripts/build-dist.sh` copies `install.sh` and `install.ps1` into
  `dist/` and includes them in `SHA256SUMS` (`sha256sum guardrail_*
  install.*`). `release.yml` already uploads `dist/guardrail_*
  dist/SHA256SUMS`; it adds `dist/install.sh dist/install.ps1`.
- New CI job `installer` (matrix ubuntu / macos / windows): build
  `dist/` with `VERSION=v0.0.0-ci`, then run the platform's script with
  `--base-url <dist> --version v0.0.0-ci --dest <tmp> --no-setup` and
  assert `<tmp>/guardrail version` prints `guardrail v0.0.0-ci`.
  Also: a tampered-checksum case must exit non-zero and leave `<tmp>`
  empty; `--version latest` must exit 2. `shellcheck -s sh install.sh`
  on ubuntu. `install.ps1` parses under `PSScriptAnalyzer` on windows.
- Go tests for `setup`: hermetic via `internal/testenv` roots; cover
  the four reconcile triggers, the staging-path refusal, the non-TTY
  refusal, the `--state disabled` path, and the antigravity gate
  propagation. `test/ci_windows_visibility_test.go` gains the new
  Windows-named tests' package.

### Documentation

- `README.md` Install: replace the curl block and the four `gen-config`
  lines with the two one-liners (Unix / Windows) and a "what it does"
  list. Keep "build from source" as-is.
- `docs/OPERATIONS.md`: new "Install, update, disable, uninstall"
  section; the "Where things live" table gains the installer scripts
  and the Windows three-root note already there is cross-referenced from
  uninstall. The `update` prose says `setup` is what reconciles handlers
  after a swap.
- `docs/adr/0029-installer-lives-in-this-repo.md`: the decision above,
  the contract table, the rejected alternatives (scripts-only; Go-only
  with README bootstrap; keep it in the dotfiles), and the two false
  premises corrected.
- `docs/windows-handover.md:35-37,125`: fix the stale "update fails on
  Windows" lines.
- `CHANGELOG.md`: unreleased entry for the installer, `setup`, and
  #317.
- `DESIGN.md` "Distribution & install": the dotfiles-installer bullets
  become "dotfiles call `install.sh`/`install.ps1` with the pin".

### Rejected alternatives

- **Scripts carry all the logic, no Go.** Fast, but reproduces the
  Unix/Windows drift the dotfiles have today in a second place, and
  cannot compare generated hook shapes without re-implementing
  `genconfig` in shell.
- **Go subcommand only, README keeps the bootstrap curl.** The first
  install still needs a download the binary cannot perform, so the
  dotfiles could not shrink to one call.
- **Keep installing from the dotfiles, just fix the stale premises.**
  Leaves four copies and two contract tests guarding duplication.
- **A non-interactive `setup` that falls back to `gen-config --merge`
  without approval.** Bypasses the operator-only registration ADR-0021
  established; today's Windows-only use of that path existed because
  `plane` used to exit 2 there, and that reason is gone.

### Out of scope (deliberate)

- The devcontainer feature (`ghcr.io/CtrlCarlitos/devcontainer-features/guardrail`)
  keeps its own install path.
- The three inconsistent Windows state roots (`%LOCALAPPDATA%\guardrail`,
  `%APPDATA%\guardrail`, `%USERPROFILE%\.local\state\guardrail`) are a
  real bug; the uninstaller knows all three, nothing here unifies them.
- The version pin stays a manual bump in the dotfiles; no `latest`.
- Homebrew / winget / scoop packaging.

### Dotfiles side (summary; its own plan)

Both installer templates and both manual updaters shrink to: download
`<base>/<pin>/install.{sh,ps1}` and `SHA256SUMS`, verify the script,
run it with `--version <pin> --state <enabled|disabled>`. Removed:
`GUARDRAIL_UPDATE_FLOOR`, `guardrail_ver_num`, the four `gen-config`
calls, the Defender block, the direct `doctor` calls. Kept: the pin,
`packages.guardrail`, the menu entries, the dotfiles-doctor pin check.
`tests/guardrail_lifecycle_contract.sh` and
`tests/update_guardrail_versions.sh` are rewritten to the new contract;
`agent_tool_upgrade_contract.sh` and `installer_hygiene_contract.sh`
lose their Defender / #146 assertions (that text now lives here).
`docs/guardrail-install.md` and `docs/tool-parity.md` are rewritten.
Pin bumps to the tag that ships the installer.
