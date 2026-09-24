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

Every case passes `--base-url <one of the above> --dest <fresh dir>
--no-setup` and checks both the exit code and what is on disk afterwards.
The self-update cases put a small fake `guardrail` script in `--dest` that
reports a seeded version and logs `update` calls.

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
`disabled-with-no-binary-is-noop` and
`parses-under-windows-powershell-syntax`. Each case runs `install.ps1`
in a child `pwsh` with `-BaseUrl <staged dir> -Dest <fresh dir>
-NoSetup`. The bootstrap case also checks that the install directory was
added to the script's process `PATH` and to the User `Path` in the
registry, and restores your User `Path` to its prior value afterwards.
Cases pass in an elevated or non-elevated shell: when the Defender
exclusion cannot be added, `install.ps1` prints a warning and carries on.

Under `pwsh` on Linux or macOS only
`parses-under-windows-powershell-syntax` runs; every other case prints
`SKIP:` and runs on the Windows CI runner. That case parses `install.ps1`
with `[System.Management.Automation.Language.Parser]::ParseFile`, fails
on any parse error, and also fails on PowerShell 7-only syntax that the
pwsh parser accepts but Windows PowerShell 5.1 does not: a literal `??`,
`?.` or `-Parallel` anywhere in the script, or a ternary `? :`.

## Not covered here

The Windows self-update branch (an existing `guardrail.exe` at or above
the floor, replaced via `guardrail update`) is covered by review, not by
a harness: there is no way to fake an `.exe` the way the Unix harness
fakes a `guardrail` script. The same branch is exercised on Unix by
`existing-at-or-above-floor-uses-self-update`, and `guardrail update`
itself is tested on Windows by `TestUpdateHappyPathReplacesBinary`.
