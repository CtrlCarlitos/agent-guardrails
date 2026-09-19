# Repository metadata proposal — opencode

## Description (GitHub one-liner, <350 chars)

> One guardrail policy across every AI coding agent. A single binary that
> intercepts tool calls, evaluates them against a policy you control, and
> returns allow/ask/deny — with actionable guidance so agents keep working
> instead of stalling. Guards Claude Code, OpenCode, Antigravity, and Codex.

(246 chars — fits)

**Shorter alternative:**

> One security policy for every AI coding agent you use. Allow, ask, or deny
> — with next steps, never dead ends.

(115 chars)

## Website

**Recommendation: leave it empty for now.** The repo itself is the
destination; pointing the field at the repo URL is self-referential. When
there's a docs site (godoc, a landing page, or GitHub Pages with the ADR
index), set it then.

If you want something today: `https://github.com/CtrlCarlitos/agent-guardrails#readme`
(this is what GitHub shows by default anyway — no added value).

## Topics (5-10)

Primary (the problem domain):
- `ai-agents` — who it's for
- `llm-security` — what it does
- `guardrails` — the specific mechanism
- `developer-tools` — the category

Secondary (the technical identity):
- `go` — the implementation language
- `cli` — the interface shape
- `security` — the broader domain
- `code-review` — adjacent but not core; skip if 8 is enough

Recommended set (7): `ai-agents` `llm-security` `guardrails` `developer-tools` `go` `cli` `security`

## Other settings (the gear icon)

- **Releases**: already on — correct, this is the distribution channel
- **Deployments**: leave off — no deployment target exists
- **Packages**: you turned it off — correct, no container/npm packages

Settings I'd additionally configure (not in the gear, but on the repo):
- **Default branch**: `main` (already correct)
- **Merge strategy**: squash-only (matches the discipline this repo uses)
- **Branch protection on `main`**: require CI pass (3-OS matrix) before merge
- **Social preview image**: a simple card with the tagline "One guardrail
  policy across every AI coding agent" over the four plane logos — makes
  link shares look intentional
