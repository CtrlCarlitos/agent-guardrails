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

## Not covered here

The Windows self-update branch (`install.ps1`) is covered by review, not
by this harness.
