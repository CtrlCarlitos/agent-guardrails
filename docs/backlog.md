# Backlog

Compiled from the final Linux pass — every agent's suggestions, recommendations,
and improvements. Each item will be converted to a GitHub issue by its source
agent; once converted, the item is removed from this document. When the
document is empty, it is deleted.

## Immediate — small effort, high payoff


## Architecture — the big structural wins

- [ ] **Platform acceptance harness** — exercise real hosts end-to-end on disposable accounts: install, enroll, enable, trust hooks, provoke a deny, approve, update, disable, recover. *(codex — top priority)*
- [ ] **Host × OS × shell compatibility matrix** — one maintained document distinguishing binary availability, policy semantics, operator approvals, and live mediation per host. *(codex)*
- [ ] **Failed updates return non-zero exit** — retain previous binary, offer explicit rollback. *(codex)*

## Policy refinements

- [ ] **Session-scoped night mode** — `--scope session` for background agents without relaxing the primary terminal. *(agy)*

## Documentation

- [ ] **Test documentation examples in CI** — run install snippets against fixture downloads, parse Overlay TOML, check relative links. *(codex)*

## Process

- [ ] **Multi-agent handoff protocol** — base SHA, owned files, dependencies, checks, unresolved limits; originating reviewer verifies closure. *(codex)*
- [ ] **Worktree cleanup** — `make worktree-clean`, `.worktrees/` in gitignore, teardown protocol in OPERATIONS.md. *(agy)*
- [ ] **Contract golden linter** — check all plane fixtures against `internal/planecontract/` before PR. *(agy)*
- [ ] **Stale code-index warning** — graft should flag when its index doesn't match current HEAD. *(codex)*

## Future milestones

- [ ] **Desktop approval broker** — Touch ID on macOS, Windows Hello on Windows. *(agy)*
- [ ] **Out-of-band notification** — desktop notify when a background agent hits an ask. *(agy)*
