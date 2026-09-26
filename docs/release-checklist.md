# Release checklist

How a release of guardrail is cut, in the order it is done. This is the flow
the `chore(release)` commits on `main` actually follow (checked against
v0.23.9-dev, v0.23.10-dev and v0.23.11-dev on 2026-09-26), plus the one rule
that has cost a verification round more than once: **an updater change is
verified on N+2, not N+1** ([#108](https://github.com/CtrlCarlitos/agent-guardrails/issues/108)).

Versions are `vX.Y.Z-dev`. A patch bump is the norm, even for ADR-level
features. What may change between releases is in
[stability-policy.md](stability-policy.md).

## 1. Before cutting

- [ ] Every PR meant for the release is merged, and CI on `main` is green on
      every OS in the matrix (`gh run list --branch main --limit 4`).
- [ ] `## Unreleased` in [`CHANGELOG.md`](../CHANGELOG.md) has a bullet for each
      shipped change, under its theme, with its issue number. A change to a
      Stable surface has a **Breaking** note.
- [ ] If anything under "Updater changes" below applies, the PR that made the
      change says which release will *exercise* it.

## 2. The release PR

One PR from a fresh branch off `main` (recent ones: `chore/release-vX.Y.Z-dev`,
`release/vX.Y.Z-dev`), touching only two files:

- [ ] `CHANGELOG.md`: rename `## Unreleased` to `## vX.Y.Z-dev (YYYY-MM-DD)`.
      Do not leave an empty `## Unreleased` above it; the next change adds one.
- [ ] `README.md`: bump the install pin in its **three** places: `ver=...` in
      the shell block, `$ver = '...'` in the PowerShell block, and the
      `` `vX.Y.Z-dev` is an example `` sentence under them. Check with
      `grep -n "<old tag>" README.md` (must print nothing) and
      `grep -c "<new tag>" README.md` (must print 3).
- [ ] Title `chore(release): vX.Y.Z-dev`. Body: what it includes (issue
      numbers), `Root cause: none, release cut.`, and the verification you ran
      (`go vet ./...` and `go test ./...` on the commit you cut from; CI covers
      the other OSes, since only the two files change).
- [ ] Wait for CI green on every OS, then squash-merge:
      `gh pr merge <N> --squash --delete-branch`.

## 3. Tag

The tag goes on the squash commit the release PR produced on `main`, not on the
PR branch.

```
git fetch origin
git log --oneline -1 origin/main        # must be "chore(release): vX.Y.Z-dev (#N)"
git tag -a vX.Y.Z-dev -m "vX.Y.Z-dev" <that squash sha>
git push origin vX.Y.Z-dev
```

- [ ] Annotated (`-a`), message = the tag name. Check:
      `git cat-file -t vX.Y.Z-dev` prints `tag`, and
      `git rev-parse vX.Y.Z-dev^{commit}` equals the squash commit.
- [ ] Never move or re-push a published tag (and `git push --force` is denied to
      agents anyway). A bad release is fixed by the next patch release.

## 4. Publish (automatic) and check

Pushing a `v*` tag runs [`release.yml`](../.github/workflows/release.yml): it
builds with `scripts/build-dist.sh` (`VERSION` = the tag), attests build
provenance, and runs `gh release create --verify-tag` with nine assets.

- [ ] The run succeeded: `gh run list --workflow release.yml --limit 1`.
- [ ] Nine assets are published: `gh release view vX.Y.Z-dev --json assets --jq '.assets|length'`
      prints `9`: `guardrail_{darwin,linux,windows}_{amd64,arm64}` (the
      Windows two end in `.exe`), `install.sh`, `install.ps1`, `SHA256SUMS`.
- [ ] Do not announce or update until all nine are there. `guardrail update`
      run too early says `release assets may still be publishing; retry in a
      minute` (the v0.20.18 asset race); nothing is changed when it does.
- [ ] Optional: `gh attestation verify guardrail_linux_amd64 -R CtrlCarlitos/agent-guardrails`
      on a downloaded asset ([SECURITY.md](../SECURITY.md)).

## 5. Hand-off

- [ ] Report the tag (`vX.Y.Z-dev`) so the dotfiles can pin it. The dotfiles
      install an exact tag; they never follow `latest`.
- [ ] Update a machine: `guardrail update vX.Y.Z-dev`, then `guardrail setup`
      (update leaves registered handlers alone). Compare with
      [What a healthy update looks like](OPERATIONS.md#what-a-healthy-update-looks-like):
      the doctor header names the **new** release, `selftest: all probes
      passed`, the selftest marker holds the new version, and the next session
      start has no selftest or coverage line.
- [ ] If post-update `doctor` or `selftest` fails, roll back with
      `guardrail update <previous version>`. Nothing rolls back
      automatically, by design; the binary is already replaced
      ([OPERATIONS.md](OPERATIONS.md), `update` exit codes).
- [ ] Remove local leftovers: the merged release branch, `dist/` if you built
      one.

## Updater changes verify on N+2, not N+1

`guardrail update` is run by the binary **already installed**, and the
installers (`install.sh`, `install.ps1`) hand an existing install to that
binary's `guardrail update` too. So a change to the update path takes effect
on the first update performed *by* a binary that contains it, one release
later than it feels like:

| Release | What happens |
|---|---|
| N (installed when the change is written) | Old updater. |
| N+1 (contains the change) | The update N → N+1 is still run by N's updater. It shows **nothing** about the change. |
| N+2 | The update N+1 → N+2 is the first one run by the new updater. Verify the change here. |

This covers `cmd/guardrail/update.go`, the post-install verification
(`doctor`, `selftest`, the selftest marker, `next` after an update), and
anything the installers ask the installed binary's `update` to do.

- [ ] In the PR that changes the updater, name the release that will
      exercise it ("verifiable on the update from vX.Y.Z-dev to its
      successor"), not the one that contains it.
- [ ] Do not read a clean N → N+1 update as proof the change works.

**Current instance: #94.** `update` exiting 1 when post-install `doctor` or
`selftest` fails shipped in v0.23.11-dev (N+1). Updates *to* v0.23.11-dev were
run by v0.23.10-dev's updater, which still exits 0 on those failures, and the
installers cannot tell. The first update that exercises #94 is the one from
v0.23.11-dev to the next release (N+2). Earlier instance: #58 fixed
post-update verification in v0.20.20, and the v0.20.19 → v0.20.20 update was
still run by the old updater and wrote a stale selftest marker.
