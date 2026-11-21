# Empirical Evidence (`docs/evidence/`)

One short, fixed-shape file per empirical finding (`YYYY-MM-DD-<slug>.md`,
tracked by #114). Keeping verified runtime transcripts and host measurements in
the repository makes them `grep`-able across sessions instead of burying them
in closed PR bodies or session memory.

ADRs and issues cite evidence files rather than duplicating transcripts.
Structure and index completeness are enforced in CI by
[`test/docs_evidence_test.go`](../../test/docs_evidence_test.go).

## Index

| Date | Finding | Links |
|---|---|---|
| 2026-09-18 | [Update verified the superseded binary in-process and wrote a stale selftest marker](2026-09-18-update-in-process-selftest-hop.md) | PR #58 |
| 2026-09-18 | [Claude Code `REPL` / `JavaScript` mediation probe and upgrade condition](2026-09-18-claude-repl-mediation-probe.md) | PR #60, [ADR-0019](../adr/0019-static-boundary-verification-vs-dynamic-meta-dispatch.md) |
| 2026-09-18 | [Windows UTF-8 BOM settings reads, launcher/shim fallback, and payload shapes](2026-09-18-windows-utf8-bom-settings-and-launcher-shim.md) | PR #66 |
| 2026-09-18 | [Windows PowerShell cmdlet gap and host shell-reporting boundary](2026-09-18-windows-powershell-cmdlet-gap.md) | PR #66, #501 |
| 2026-09-18 | [macOS `/tmp` symlink alias, case-insensitive paths, and socket fallback](2026-09-18-macos-temp-symlink-and-case-paths.md) | PR #68 |
| 2026-11-21 | [Windows 11 Antigravity (`agy 1.5.11`) live acceptance proof](2026-11-21-windows-antigravity-live-acceptance.md) | PR #652, #92 |

## Template

Name new files `docs/evidence/YYYY-MM-DD-<short-slug>.md` (lowercase letters,
digits, and hyphens) and include all six headings in order:

```markdown
# <Short title>

## Claim

One sentence stating the measured fact.

## Context

- Guardrail: `<version or commit>`
- Runtime / plane: `<name and version>`
- OS / shell: `<OS and shell>`

## Method

Exact commands or probe steps run.

## Observation

Verbatim output (trimmed for brevity, never paraphrased).

## Consequence

What code, contract, or ADR changed — or what open question this settled.

## Links

- PR: `#<n>`
- Issue / ADR: `#<n>`, `../adr/<file>.md`
```
