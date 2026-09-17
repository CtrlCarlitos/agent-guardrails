# Task 5 Report

## Status

Implemented the Claude capability inventory and catch-all pre-hook contract.

## Outcomes

- The generated Claude `PreToolUse` matcher is `*`, supplied by the shared
  plane contract so every hook-visible native tool reaches Guardrail.
- Claude classifies documented command, discovery, mutation (including
  `NotebookEdit`), web fetch/search, delegation, safe-control, and unsupported
  capabilities. MCP-prefixed tools are an explicit Deny; unlisted native tools
  retain the Task 1 audit/deny posture.
- The adapter extracts typed command, path, and URL inputs only. Missing path
  or URL inputs remain Engine Denies; raw arguments are not added to audit
  metadata.
- Task 4's Unix/WSL/macOS broker support and Windows fail-closed behavior are
  untouched.

## TDD Evidence

- RED: `/usr/local/go/bin/go test ./internal/planecontract ./internal/adapter ./internal/genconfig -run 'Test(ClaudeInventory|ClaudePreHook|ParseClaudeClassifies|ClaudeHooks)' -v`
  failed because the inventory API, capability extraction, and catch-all matcher
  did not exist.
- GREEN: the same focused command passed after implementation.

## Verification

- `/usr/local/go/bin/go test ./internal/planecontract ./internal/adapter ./internal/genconfig -run Claude -v`
- `/usr/local/go/bin/go test ./...`
- `git diff --check`

## Review Fix: ShareOnboardingGuide

- Added Claude `ShareOnboardingGuide` as an explicit deny capability.
- Added an end-to-end Claude hook fixture proving parsing and Engine evaluation
  block the native call with exit `2`.
- Added generated pre-hook contract coverage proving the deny entry is present
  and covered by the generated catch-all matcher.
- RED: the focused hook test returned exit `0` before the inventory entry;
  GREEN and `/usr/local/go/bin/go test ./...` pass after the change.
