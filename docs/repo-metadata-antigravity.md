# Repository Metadata Proposal — Antigravity Plane

Proposed GitHub repository configuration for [`CtrlCarlitos/agent-guardrails`](https://github.com/CtrlCarlitos/agent-guardrails).

---

## 1. Description

> Universal pre-execution security guardrails for autonomous AI coding agents (Claude Code, Antigravity, OpenCode, Codex). Enforces path tiers, bash safety, MCP argument projection, and delegation inheritance with actionable model redirection.

*(254 characters — fits cleanly within GitHub's 350-character limit).*

---

## 2. Website

- **Recommendation**: Leave empty for now, or set to the repository releases page:
  `https://github.com/CtrlCarlitos/agent-guardrails/releases`
- **Rationale**: There is no external hosted documentation site yet; all documentation is committed in-repo ([`CONTEXT.md`](../CONTEXT.md), [`docs/OPERATIONS.md`](./OPERATIONS.md), and [`docs/adr/`](./adr/)). Directing visitors to the releases page surfaces the latest pre-compiled binaries and changelog directly.

---

## 3. Topics (Tags)

Select 10 high-signal, searchable GitHub topics:

1. `ai-agent`
2. `ai-security`
3. `guardrails`
4. `developer-tools`
5. `claude-code`
6. `antigravity`
7. `opencode`
8. `codex`
9. `mcp`
10. `golang`

---

## 4. Settings Gear Options

Recommended GitHub repository settings under the Settings gear:

### Features
- **Issues**: Enabled (use GitHub Issue forms for reporting uncontracted tools discovered by `guardrail doctor --coverage <plane>`).
- **Discussions**: Enabled (ideal for sharing project `guardrail.toml` overlays, recipes, and custom MCP family schemas).
- **Wikis**: Disabled (keep all architectural records in git under `docs/adr/` and `docs/OPERATIONS.md` to guarantee version-controlled documentation integrity).
- **Sponsorships**: Optional / as desired.

### Pull Requests & Merging
- **Allow Squash merging**: Enabled (default to PR title and commit summary).
- **Allow Rebase merging**: Enabled.
- **Allow Merge Commits**: Disabled (keep git history linear).
- **Automatically delete head branches**: **Enabled** (keeps the repository tidy after PR merges).

### Security & Analysis
- **Dependabot alerts**: Enabled.
- **Dependabot security updates**: Enabled.
- **Secret scanning**: Enabled (with push protection).
