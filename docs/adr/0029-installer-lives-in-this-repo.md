# ADR-0029: The installer lives in this repo — `install.sh`, `install.ps1`, `guardrail setup`

## Status

Accepted (operator, 2026-09-23). Design:
`docs/superpowers/specs/2026-09-23-installer-design.md`. Closes #317.

## Context

Installing guardrail was spread across four copies of the same logic in the
dotfiles repo — `run_onchange_install_packages.{sh,ps1}.tmpl` and
`scripts/update_ai_tools.{sh,ps1}`: OS/arch detection, asset download,
`SHA256SUMS` verification, the install path, Windows PATH persistence,
`Unblock-File`, the exact-file Defender exclusion (#132, #146), the
self-update floor (`v0.19.2-dev`), a version-number comparator, a four-plane
`gen-config --merge` sequence on Windows, and the
`doctor --coverage antigravity` gate. Two dotfiles contract tests locked that
duplication in place. This repo had no installer at all: the README carried a
hand-typed curl block and four `gen-config` lines.

Nothing reconciled handlers after a binary swap. `guardrail plane enable`
skips a plane that is already registered unless its permissions floor drifted,
so an upgrade that changes the hook command shape left stale handlers
registered (#317).

The dotfiles also encoded two premises that are false on `main`:

1. **`plane` commands exit 2 on Windows.** They do not: ADR-0021 step (d)
   lifted the Windows operator/plane/recover/approval gates (#207). The
   Windows-only `gen-config` path the dotfiles took because of it also skipped
   `WriteCodexWrapper`, leaving Windows Codex on the `-EncodedCommand` form
   ADR-0024 replaced.
2. **`guardrail update` does not work on Windows.** It does: the running image
   is renamed aside to `guardrail.exe.old` before the new one moves in (#205,
   #208), and `TestUpdateHappyPathReplacesBinary` runs as a mandatory
   `windows-latest` CI step.

## Decision

**Installation is this project's responsibility.** The dotfiles become a
caller that supplies exactly two facts: the pinned version and the desired
state.

| Concern | Owner |
|---|---|
| Pinned release tag | dotfiles (`.chezmoidata.yaml` `guardrail.version`) |
| Desired state (`enabled` / `disabled`) | dotfiles (`packages.guardrail`) |
| Fetching the pinned tag's install script and verifying it against that tag's `SHA256SUMS` | dotfiles (a few lines, both twins) |
| Everything after that | this repo |

"Everything after that" is: OS/arch detection, asset download and
verification, binary placement, PATH, `Unblock-File`, the Defender exclusion,
choosing bootstrap versus `guardrail update`, plane wiring, reconciliation
after a binary swap, the coverage gate, selftest, disable and uninstall.

**Two scripts and one subcommand carry it.**

- `install.sh` (POSIX `sh`; Linux, macOS, WSL) and `install.ps1` (Windows
  PowerShell 5.1 and PowerShell 7) live at the repo root, are copied into
  `dist/` by `scripts/build-dist.sh`, listed in `SHA256SUMS` next to the
  binaries, and uploaded and attested by `release.yml`. Flags, identical in
  both (PowerShell spells them `-Version` etc.): `--version <tag>` (required,
  exact; `latest` refused), `--state enabled|disabled`, `--uninstall`,
  `--purge`, `--dest <dir>`, `--base-url <url-or-dir>`, `--no-setup`. The
  scripts are deliberately thin: anything that can be Go is Go. They
  bootstrap-download only when no binary at or above the `v0.19.2-dev`
  self-update floor exists; otherwise they call `guardrail update <tag>`, the
  sanctioned replacement path (#146). They end by running `guardrail setup`
  and exit with its code.
- `guardrail setup [--state enabled|disabled] [--planes <list>]` is the
  post-install reconcile seam. It does not download, touch PATH or touch
  Defender — those happen before a binary exists or need OS facilities the
  binary deliberately avoids (no elevation, ADR-0021 §7). It requires an
  interactive local terminal, exactly like `plane enable`, so registering a
  host stays operator-only (ADR-0021), and it refuses to register the
  updater's staging or `.old` path, because the running executable is baked
  into every hook command.

**The reconcile rule.** For each detected plane, `setup --state enabled`
re-merges when any of these holds:

1. the plane is not registered;
2. its permissions floor drifted;
3. its registered handlers differ from what this binary generates — the
   on-disk `guardrail-*` hook groups, the codex wrapper and the opencode plugin
   entry compared against a fresh generation for this binary, ignoring keys
   the host serializer strips.

Planes that already match print `already enabled` and do not prompt; the rest
go through one approval. Then `doctor --coverage antigravity` when `agy` is on
PATH, then `selftest`; either failing is `setup`'s non-zero exit. A binary
swap followed by `setup` therefore always leaves handlers that match the
running binary. `setup --state disabled` runs `plane disable` for every
registered plane under one approval, and nothing else.

`--uninstall` disables first (operator approval, like any disable), then
removes the binary, the opencode plugin file, and on Windows the PATH entry
and Defender exclusion it added. `--purge` also removes every state, config and
data root, including all three Windows state roots. Plane settings files are
changed only by `plane disable`, from the ownership manifest (ADR-0028).

A caller's whole job, on each OS:

```sh
url=https://github.com/CtrlCarlitos/agent-guardrails/releases/download/vX.Y.Z-dev
# fetch "$url/install.sh" and "$url/SHA256SUMS", verify install.sh's line, then:
sh install.sh --version vX.Y.Z-dev --state enabled
```

```powershell
# fetch install.ps1 and SHA256SUMS for vX.Y.Z-dev, compare Get-FileHash, then:
powershell -ExecutionPolicy Bypass -File .\install.ps1 -Version vX.Y.Z-dev -State enabled
```

## Rejected alternatives

- **Scripts carry all the logic, no Go.** Fast, but reproduces the
  Unix/Windows drift the dotfiles have today in a second place, and cannot
  compare generated hook shapes without re-implementing `genconfig` in shell.
- **Go subcommand only, README keeps the bootstrap curl.** The first install
  still needs a download the binary cannot perform, so the dotfiles could not
  shrink to one call.
- **Keep installing from the dotfiles, just fix the stale premises.** Leaves
  four copies and two contract tests guarding the duplication.
- **A non-interactive `setup` that falls back to `gen-config --merge` without
  approval.** Bypasses the operator-only registration ADR-0021 established.
  The dotfiles' Windows-only use of that path existed because `plane` used to
  exit 2 there, and that reason is gone.

## Consequences

- The dotfiles shrink to a call: download the pinned tag's `install.sh` /
  `install.ps1` and `SHA256SUMS`, verify the script, run it with `--version
  <pin> --state <enabled|disabled>`. The update floor, the version comparator,
  the four `gen-config` calls, the Defender block and the direct `doctor` calls
  leave the dotfiles; their contract tests are rewritten to the new contract.
- Any caller that downloads `install.ps1` under Windows PowerShell 5.1 must set
  `[Net.ServicePointManager]::SecurityProtocol` to include `Tls12` before the
  request, the same way `install.ps1` itself does before fetching its own
  release assets — Windows PowerShell 5.1 may default to TLS 1.0/1.1, which
  GitHub refuses. The dotfiles caller needs the same line.
- A binary swap is followed by `setup`. `guardrail update` alone still leaves
  handlers as registered; the installer runs both, and OPERATIONS.md says to
  run `setup` after a bare `update`.
- CI installs from `dist/` on ubuntu, macos and windows (the `installer` job,
  harnesses in `test/installer/`): a clean install with `--base-url <dist>
  --no-setup`, a tampered checksum that must exit non-zero and leave the
  destination empty, `--version latest` that must exit 2, the self-update and
  uninstall/purge paths, and `shellcheck -s sh install.sh` on ubuntu.
  `install.ps1` runs its harness under both PowerShell 7 and Windows
  PowerShell 5.1, and must parse as 5.1 syntax.
- The scripts are not pipe-able by design. They `exit` on failure — fatal to an
  interactive PowerShell session that evaluated them in-process — and hand the
  terminal to `setup` for a passkey approval. Every documented path downloads,
  verifies, then runs the file.
- `setup` needs an interactive terminal and an enrolled operator. A first
  install on a fresh machine is `--no-setup`, then `guardrail operator enroll`,
  then `guardrail setup`; unattended CI seeds keep `guardrail` disabled.
- Out of scope, deliberately: the devcontainer feature keeps its own install
  path; the three inconsistent Windows state roots are left as they are (the
  uninstaller knows all three); the version pin stays a manual bump in the
  dotfiles, with no `latest`; no Homebrew, winget or scoop packaging.
