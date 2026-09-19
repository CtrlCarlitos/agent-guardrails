# Backlog

Compiled from the final Linux pass — every agent's suggestions, recommendations,
and improvements. Each item will be converted to a GitHub issue by its source
agent; once converted, the item is removed from this document. When the
document is empty, it is deleted.

## Immediate — small effort, high payoff

- [ ] **doctor verdict line** — `guardrail doctor` ends with `verdict: healthy` or `verdict: N problems (see above)`. *(claude)*
- [ ] **guardrail.toml.example** — a well-commented template showing every slot, a custom rule, an egress request, a waiver request. *(opencode)*
- [ ] **CONTRIBUTING.md** — how to propose a rule change, add a plane, add an MCP family to the registry, file an ADR. *(opencode + agy)*
- [ ] **Issue templates** (`.github/ISSUE_TEMPLATE/`) — pre-populate with diagnostics for "denial with no useful next step" and "tool not covered." *(opencode)*
- [ ] **guardrail explain** — print an audit record, the guidance the model saw, the rule's source, and the one-line fix. *(claude — fight for)*
- [ ] **Selftest fixtures directory** — probes become `test/selftest/<plane>/*.json` files, not Go literals; the count stops being a README fact. *(claude — fight for)*
- [ ] **Release checklist** — add "updater changes verify on N+2, not N+1." *(claude)*

## Architecture — the big structural wins

- [ ] **Platform acceptance harness** — exercise real hosts end-to-end on disposable accounts: install, enroll, enable, trust hooks, provoke a deny, approve, update, disable, recover. *(codex — top priority)*
- [ ] **Path identity centralization** — `pathutil.Canonical` used by every containment and grant comparison; prevents the /tmp-symlink, /var-folders, and 8.3-vs-long-form bug class. *(claude — fight for)*
- [ ] **Host × OS × shell compatibility matrix** — one maintained document distinguishing binary availability, policy semantics, operator approvals, and live mediation per host. *(codex)*
- [ ] **Unified guardrail status** — fold coverage drift, floor currency, and selftest marker into one cache key, one posture line, one command. *(claude — fight for)*
- [ ] **Daemon mode for hooks** — long-running process, hook connects via socket; amortizes fork+exec to sub-ms. *(opencode)*
- [ ] **PowerShell cmdlet rules** — P1/P4/P6 coverage for `Remove-Item`, `Get-Content`, `Invoke-Expression`, `Format-Volume`; must be sized before Windows is trusted. *(claude + codex + handover doc)*
- [ ] **Failed updates return non-zero exit** — retain previous binary, offer explicit rollback. *(codex)*

## Policy refinements

- [ ] **Inert redirect body rule** — when a shell's only effect is a redirect into a path the write rules allow, and the interpreter is cat/tee (not python/bash), the content is inert data. *(claude — hit 5× personally)*
- [ ] **Write seams ADR-0022** — the table of where writes are authorized and why. *(claude)*

## Documentation

- [ ] **Getting-started guide** (`docs/getting-started.md`) — walk through first deny, first ask, first grant, first overlay. *(opencode)*
- [ ] **Test documentation examples in CI** — run install snippets against fixture downloads, parse Overlay TOML, check relative links. *(codex)*
- [ ] **Evidence directory** (`docs/evidence/`) — one file per finding with the transcript that proved it. *(claude)*

## Process

- [ ] **Multi-agent handoff protocol** — base SHA, owned files, dependencies, checks, unresolved limits; originating reviewer verifies closure. *(codex)*
- [ ] **Pre-push branch-trap check** — "is HEAD already reachable from main?" before pushing. *(opencode)*
- [ ] **Stale code-index warning** — graft should flag when its index doesn't match current HEAD. *(codex)*

## Future milestones

- [ ] **Stable release v1.0.0** — with breaking-change policy and stability guarantees. *(opencode)*
