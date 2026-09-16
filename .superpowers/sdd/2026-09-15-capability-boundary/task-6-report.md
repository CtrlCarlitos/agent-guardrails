# Task 6 Report

## Status

Implemented the OpenCode and Antigravity capability contracts.

## Outcomes

- OpenCode classifies command, discovery, mutation, native web fetch/search,
  and safe-control tools. Explicit custom/MCP calls Deny; other unlisted calls
  retain the configured audit/deny posture.
- The generated OpenCode plugin projects only documented path fields and native
  fetch URLs. `apply_patch` has no trusted path projection and therefore reaches
  the Engine as a mutation with missing input, which Denies.
- Antigravity has the same explicit inventory and a catch-all `PreToolUse`
  matcher. It extracts only typed documented path and URL fields and retains its
  required `{}` post-hook response.
- Native web fetch is denied by the shared Engine boundary; native web search
  maps to Ask (`force_ask` in Antigravity).

## TDD Evidence

- RED: `go test ./internal/planecontract ./internal/adapter ./internal/genconfig -run 'Test(OpenCode|Antigravity)' -count=1 -v` failed because the two inventories,
  typed extraction, and Antigravity catch-all matcher did not exist.
- GREEN: focused adapter, inventory, generated-plugin, hook, and contract fixture
  tests pass after implementation.

## Verification

- `go test ./... -count=1`
- `make check`
- `git diff --check`

## Fix Round

- Replaced the Antigravity first-path scan with per-tool documented schemas.
  `view_file`, file mutations, `list_dir`, `find_by_name`, and `grep_search`
  each require their own documented path key and reject mismatched or decoy
  fields.
- Added the documented Antigravity task, scheduler, permission, collaboration,
  and media surface with explicit safe-control, delegation, or deny capabilities.
- Expanded OpenCode to its documented `lsp`, `skill`, and `todowrite` tools and
  explicitly denies `task` pending Task 7 inheritance evidence.
- External-surface assertions, unknown audit/deny posture tests, path-decoy
  fixtures, and the generated OpenCode plugin contract cover the boundary.

## Re-review Fix

- `read_url_content` now accepts only its documented case-sensitive `Url`
  argument. `URL` and `url` aliases, including an alias decoy alongside `Url`,
  are rejected before URL extraction.
- RED: `TestParseAntigravityRejectsURLAliasesAndDecoys` failed because the
  adapter accepted `URL`; GREEN passed after exact-field validation.
