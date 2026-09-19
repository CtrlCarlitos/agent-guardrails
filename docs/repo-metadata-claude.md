# Repository metadata proposal (claude)

What to put in the GitHub settings gear for `CtrlCarlitos/agent-guardrails`, and why.

## Description (≤ 350 chars)

> One policy that keeps AI coding agents from the things you'd never forgive them for — destructive commands, secret reads, blind egress, pushes to main — across Claude Code, opencode, Antigravity and Codex. A single Go binary: allow / ask / deny, and every deny tells the agent what to do next.

(283 characters.)

Shorter alternative if the field ever tightens:

> Allow / ask / deny for AI coding agents, one policy across Claude Code, opencode, Antigravity and Codex. Every deny comes with a next step.

## Website

**Leave empty.** There is no docs site, and pointing the field at the README or a release page adds nothing GitHub doesn't already show. Set it the day a docs site or a landing page exists; until then an empty field is honest and an outdated one is worse than empty.

## Topics (pick 8–10)

Ordered by how someone would actually search:

1. `ai-agents`
2. `claude-code`
3. `codex`
4. `opencode`
5. `guardrails`
6. `agent-security`
7. `llm-safety`
8. `mcp` — the MCP family registry is a real feature, and MCP searchers are our audience
9. `golang`
10. `developer-tools`

Considered and left out: `antigravity` (too ambiguous as a topic — physics), `policy-engine` (vague), `hooks` (drowns in webhook repos). If GitHub caps you at fewer, drop from the bottom.

## Other settings worth setting

| Setting | Proposal | Why |
|---|---|---|
| **License** | Add a `LICENSE` file first — there is none in the tree today, which means "all rights reserved" by default and no license badge can be honest. MIT or Apache-2.0 both fit a single-binary tool people will vendor into dotfiles; Apache-2.0 if you care about the patent grant, MIT if you want the shortest file. | Without it, nobody can legally use the thing the README invites them to install. |
| **Releases → "Set as latest"** | Keep `-dev` tags marked *pre-release* until the first tag without the suffix; the Release badge in the README already uses `include_prereleases`. | Lets `guardrail update <version>` users and the badge agree on what "latest" means. |
| **Branch protection on `main`** | Require the CI status check (`test (ubuntu-latest)` and `test (windows-latest)`), require a PR, forbid force-pushes. | The repo's own discipline (no force-push, PR per finding) should be enforced by the host, not just by habit — the engine denies `git push --force` for agents; the branch rule does it for humans. |
| **Merge button** | Squash only, default the PR title as the commit subject. | The history is already squash-shaped; conventional-commit subjects come straight from PR titles. |
| **Automatically delete head branches** | On. | The Linux-phase cleanup deleted 19 merged `claude/*` branches by hand; this makes that the default. |
| **Issues → labels** | `plane:claude`, `plane:opencode`, `plane:antigravity`, `plane:codex`, `engine`, `adr`, `runbook`. | Findings arrive per plane; the labels match how the work is actually routed. |
| **Security → private vulnerability reporting** | On. | It's a security tool; give reporters a private door. |
| **Social preview** | Optional. If one is made: the three verdict words and the four plane names, nothing else. | The README already leads with the sixty-second demo; the preview should say the same thing in one glance. |
| **Discussions / Wiki / Projects** | Off. | Decisions live in `docs/adr/`, operations in `docs/OPERATIONS.md`; a second place for either would rot. |
