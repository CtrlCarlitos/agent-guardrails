# Repository metadata proposal — Codex

These are suggestions for the repository owner, not changes to GitHub settings.

## Description

> Before your coding agent runs it: shared checks for destructive commands, secrets, and sensitive changes across Claude Code, OpenCode, Antigravity, and Codex. Blocks come with a next step.

188 characters, below GitHub's 350-character limit. Lead with the moment the
project helps; save “planes,” adapters, and capability contracts for the docs.

## Website

Leave empty for now. The README is the landing page and the repository has no
separate product site to send people to. Do not point this field at the dotfiles
repository: that would make a standalone tool look like an installation detail.
If a dedicated documentation site is published, put its stable root URL here.

## Topics

Suggested nine topics:

`ai-agents`, `coding-agents`, `guardrails`, `claude-code`, `opencode`, `codex`,
`antigravity`, `mcp`, `golang`

Avoid `sandbox`: Guardrail explicitly does not provide OS isolation.

## About panel and nearby settings

- Show **Releases**: the binary downloads are a primary installation route.
- Hide **Packages** until an actual package is published. Hide **Deployments**
  unless there is a deployed service or documentation site worth visiting.
- Keep **Issues** enabled for missing checks, tool-classification drift, and
  denied actions with no usable continuation.
- Keep **Wiki** off; versioned documentation already lives beside the code.
  Leave Discussions off until someone wants to maintain a support forum.
- Keep README and repository links visible. No speculative website or support
  promise, and no social-preview image is needed for this text-first proposal.

The About gear exposes the description, website, topics, and sidebar visibility
options; Issues/Wiki/Discussions are adjacent repository settings, not all in
that same dialog. No settings change is required to evaluate this proposal.

## Badges

The README includes two: the actual `ci.yml` workflow on `main` and the Go
version read from `go.mod`. Both link to the thing they describe. CI currently
covers Linux, macOS, and a selected Windows test set; the badge is not a claim
of equal runtime support on every platform.

Do **not** add a license badge yet. This repository has no license file and
GitHub reports no detected license. Choosing a license is an owner decision;
when one is committed, link the badge to that file. Do not borrow the dotfiles
repository's license by implication.

Skip shields for star count, downloads, or “100% secure.” They do not help a new
user decide whether the tool fits their workflow. A release badge can be added
later, but the install example should continue to name an exact reviewed tag.
