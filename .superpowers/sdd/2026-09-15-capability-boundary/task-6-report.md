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
