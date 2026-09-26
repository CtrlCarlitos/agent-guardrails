# Installer harness

`install_sh_test.sh` exercises `install.sh` end to end against a locally
staged release. It needs no network and never touches your real install.

## Run it

```sh
make installer-test
```

That builds `dist/` with `VERSION=v0.0.0-ci ./scripts/build-dist.sh`, then
runs `VERSION=v0.0.0-ci DIST=dist bash test/installer/install_sh_test.sh`.
To run against an existing build, set `DIST` (the directory holding the
`guardrail_*` assets and `SHA256SUMS`) and `VERSION` (the version those
binaries report) yourself. `INSTALL_SH` overrides the script under test;
it defaults to the repo root's `install.sh`.

## What it stages

In a temp directory, removed on exit:

- `releases/<VERSION>/`: the six `guardrail_*` assets and `SHA256SUMS`
  copied from `$DIST`, laid out the way GitHub serves a release.
- `tampered/<VERSION>/`: the same, with the first hex digit of this
  platform's `SHA256SUMS` line flipped.
- `nosums/<VERSION>/`: the assets without `SHA256SUMS`.
- `empty/`: an empty directory, used as `--base-url` where a case must
  prove that no download happens.

Every install case passes `--base-url <one of the above> --dest <fresh
dir> --no-setup` and checks both the exit code and what is on disk
afterwards. The self-update cases put a small fake `guardrail` script in
`--dest` that reports a seeded version and logs `update` calls.

## Uninstall cases

The harness exports `HOME=<tmp>/home` and unsets `XDG_DATA_HOME`,
`XDG_STATE_HOME` and `XDG_CONFIG_HOME` before any case runs, and each
uninstall case also passes a fresh `HOME` of its own (setting one `XDG_*`
root where it tests that branch). The plugin file and every state root
therefore live in the temp directory, never in yours.

- `uninstall-removes-binary-and-plugin`: installs, drops a fake
  `guardrail.js` in the plugin dir (`$XDG_DATA_HOME/guardrail`) and the
  updater's `guardrail.old` / `.guardrail-update` leftovers in `--dest`,
  runs `--uninstall --no-setup`; the binary, the leftovers and the plugin
  are gone, the state dir (`$HOME/.local/state/guardrail`, with a marker
  file) is still there.
- `uninstall-purge-removes-state-roots`: pre-creates
  `$HOME/.local/state/guardrail`, `$XDG_CONFIG_HOME/guardrail` and
  `$HOME/.local/share/guardrail` with markers, runs `--uninstall --purge
  --no-setup`; every root is gone, with an `install: removed <path>` line
  each, and their parents are kept.
- `purge-ignores-relative-xdg`: runs `--uninstall --purge` from a scratch
  directory holding a `guardrail` dir, with `XDG_STATE_HOME=.`; the
  relative root is ignored, so the scratch `guardrail` survives and
  `$HOME/.local/state/guardrail` is removed instead.
- `uninstall-nothing-installed-is-ok`: an empty `--dest`; exit 0 and
  `nothing installed at <dest>`.
- `purge-without-uninstall-exits-2` and `state-with-uninstall-exits-2`:
  exit 2, nothing installed and nothing removed.
- `uninstall-aborts-when-disable-fails`: the fake `guardrail` answers
  `setup` with exit 1 (its setup exit code is read from `.fake-setup-rc`
  beside it; `fake_guardrail`'s third argument sets it). Without
  `--no-setup`, `--uninstall --purge` must log `setup --state disabled`,
  exit 1 with `uninstall aborted: planes are still registered`, and leave
  the binary and the plugin in place.

## Hand-off cases

These run without `--no-setup` against the fake `guardrail`, so the
script really hands off. Before the hand-off (and before the uninstall's
disable step) the script probes `guardrail setup` with stdin from
`/dev/null`: a binary that has `setup` refuses with `requires an
interactive local terminal` (exit 3, operator action pending, from #364 on;
exit 2 before); one that predates it exits 2 with `unknown subcommand`, and
only that pair reads as unsupported. A `fake_guardrail` third argument of `old`
makes the fake answer the second way; its `plane` calls go to
`update.log`.

- `handoff-propagates-setup-exit-code`: the fake's `setup` exits 3; the
  script exits 3.
- `disabled-falls-back-on-old-binary`: `--state disabled` against an old
  fake runs `plane disable --all` instead and exits 0.
- `uninstall-falls-back-on-old-binary`: `--uninstall` against an old fake
  disables with `plane disable --all`, then removes the binary.
- `enabled-refuses-old-binary`: `--state enabled` against an old fake
  exits 1 with `this guardrail predates 'setup'; re-run the installer
  with --version <a release that has it>`.

`sums-cover-the-scripts` checks that `$DIST/SHA256SUMS` has a line for
`install.sh` and one for `install.ps1`: `scripts/build-dist.sh` ships both
scripts as release assets and checksums them with the binaries.

It prints `PASS:` / `FAIL:` per case and exits 1 on any `FAIL:`. The
`shellcheck` case prints `SKIP:` when `shellcheck` is not installed; CI
has it.

## Why `--no-setup`

`install.sh` ends by exec'ing `guardrail setup`, which needs a terminal
and an operator passkey to approve plane changes. Neither exists in CI,
so the harness stops at a verified binary. `setup` has its own Go tests.

## Windows: `install_ps1_test.ps1`

`install_ps1_test.ps1` is the same harness for `install.ps1`, in
PowerShell. Run it with:

```sh
make installer-test-windows
```

That runs `VERSION=v0.0.0-ci DIST=dist pwsh -NoProfile -File
test/installer/install_ps1_test.ps1`. It does not build `dist/`: on
Windows, run `VERSION=v0.0.0-ci ./scripts/build-dist.sh` first (or point
`DIST` at an existing build). `INSTALL_PS1` overrides the script under
test; it defaults to the repo root's `install.ps1`.

On Windows it stages the same four directories as above and runs every
case: `bootstrap-installs-and-verifies`,
`already-at-version-skips-download`, `latest-is-rejected`,
`tampered-checksum-refuses`, `missing-sums-refuses`,
`disabled-with-no-binary-is-noop`, the uninstall cases
`uninstall-removes-binary-and-plugin`,
`uninstall-keeps-path-when-dest-shared`,
`uninstall-purge-removes-state-roots`, `uninstall-nothing-installed-is-ok`,
`purge-without-uninstall-exits-2` and `state-with-uninstall-exits-2`,
`handoff-propagates-setup-exit-code`,
`noninteractive-disable-can-skip-setup`, and
`parses-under-windows-powershell-syntax`. Each case runs `install.ps1`
in a child `pwsh` with `-BaseUrl <staged dir> -Dest <fresh dir>
-NoSetup`. The bootstrap case also checks that the install directory was
added to the script's process `PATH` and to the User `Path` in the
registry, and restores your User `Path` to its prior value afterwards.
Cases pass in an elevated or non-elevated shell: when the Defender
exclusion cannot be added or removed, `install.ps1` prints a warning and
carries on. An elevated run does add one exclusion, for the harness's
temp `guardrail.exe`; the bootstrap and uninstall cases remove it again
(`Remove-MpPreference`) when they finish.

The uninstall cases run the child `pwsh` with `USERPROFILE`,
`LOCALAPPDATA` and `APPDATA` pointed into a fresh directory under the
harness temp dir, and restore them afterwards. The state roots they
create and expect `-Purge` to remove are `%LOCALAPPDATA%\guardrail`,
`%APPDATA%\guardrail`, `%USERPROFILE%\.local\state\guardrail` and
`%USERPROFILE%\.local\share\guardrail`; the plugin file is
`%USERPROFILE%\.local\share\guardrail\guardrail.js`. The
`uninstall-removes-binary-and-plugin` case installs for real, so it also
checks that `-Uninstall` took `<dest>` out of the User `Path` and removed
the now-empty `<dest>`, and restores your User `Path` afterwards either
way. `uninstall-keeps-path-when-dest-shared` drops a foreign file in
`<dest>` first: the entry and the file must both survive, with
`install: leaving <dest> on PATH (other tools live there)`.
`handoff-propagates-setup-exit-code` installs the real binary without
`-NoSetup`, with the child's stdin piped instead of a console: the real
`setup` refuses with exit 3 (operator action pending) and `requires an
interactive local terminal`, and the script must exit 3 too.
`noninteractive-disable-can-skip-setup` starts without a binary and passes
`-State disabled -SetupIfInteractive` with the same redirected stdin. The
binary must install, setup must be deferred with an actionable message, and
the installer must exit 0.
`uninstall-aborts-when-disable-fails` is Unix only: faking a
`guardrail.exe` whose `setup` fails runs into the same limit as the
self-update branch below.

Under `pwsh` on Linux or macOS only
`parses-under-windows-powershell-syntax` runs; every other case prints
`SKIP:` and runs on the Windows CI runner. That case parses `install.ps1`
with `[System.Management.Automation.Language.Parser]::ParseFile`, fails
on any parse error, and also fails on PowerShell 7-only syntax that the
pwsh parser accepts but Windows PowerShell 5.1 does not: a literal `??`,
`?.` or `-Parallel` anywhere in the script, a ternary `? :`, or a
pipeline chain `&&` / `||`.

## In CI

The `installer` job in `.github/workflows/ci.yml` runs on ubuntu, macOS
and Windows. Each leg builds `dist/` with `VERSION=v0.0.0-ci
./scripts/build-dist.sh` and installs from it, so no network or published
release is involved. Ubuntu and macOS run `install_sh_test.sh` (ubuntu
also runs `shellcheck -s sh install.sh`); Windows runs
`install_ps1_test.ps1` twice, under `pwsh` and under Windows PowerShell
5.1, and both must pass.

## Not covered here

The Windows self-update branch (an existing `guardrail.exe` at or above
the floor, replaced via `guardrail update`) is covered by review, not by
a harness: there is no way to fake an `.exe` the way the Unix harness
fakes a `guardrail` script. The same branch is exercised on Unix by
`existing-at-or-above-floor-uses-self-update`, and `guardrail update`
itself is tested on Windows by `TestUpdateHappyPathReplacesBinary`.
