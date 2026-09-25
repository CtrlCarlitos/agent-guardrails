# Agent instructions — agent-guardrails

Read first, in order: `docs/HANDOFF-2026-09-24.md` (current state, the
issue plan, and every mechanic that cost a previous session time),
`CONTEXT.md` (vocabulary), the top of `CHANGELOG.md`. Runbook:
`docs/OPERATIONS.md`. Decisions: `docs/adr/`.

## Standing rule

Fix on red. Merge on green. House cleaning. Root-cause a failing check or
test and fix it; never make it green by changing the expectation. Squash-
merge a green mergeable PR and delete its branch. Remove merged branches,
`.worktrees/*` leftovers and `dist/` before you finish. Report a cut
release's tag so the dotfiles can pin it.

## Rules that are enforced on you

- This machine runs guardrail. A shell command whose interpreter literal
  mentions `guardrail` with `night`, `setup`, `plane`, `operator` or
  `recover` is denied; put the script in a file and run the file.
  `git push --force` is denied; recover with a fresh branch instead.
- Measure before asserting: state an engine verdict, an exit code or a
  test result only after running it in this session.

## Working here

- Go `1.26`; `gofmt` clean, `go vet ./...` clean, `go test ./...` green on
  Windows **and** on Linux (WSL recipe in the handoff) before every push.
- Conventional commits, one PR per issue, TDD (failing test first), PR body
  carries root cause and verification per OS. No attribution trailers.
- A Windows-only test must be named `TestWindows…` or CI never runs it.
- Never stack a PR on another PR's branch.
