# Claude Code `REPL` / `JavaScript` mediation probe and upgrade condition

## Claim

`REPL` and `JavaScript` are not exposed to guarded Claude Code sessions on the probed version, and static bundle inspection cannot prove that command hooks fire on inner REPL tool calls, so `CapabilityDeny` stands until a matching inner-tool audit record is captured.

## Context

- Guardrail: `main` as of 2026-09-18 (PR #60)
- Runtime / plane: Claude Code `2.1.275`
- OS / shell: Linux

## Method

1. Probed live tool exposure inside a Claude Code session via `ToolSearch select:REPL,JavaScript`.
2. Searched all local session transcripts (`~/.claude/projects/*`) and the guardrail audit log for `repl_tool_call` and `tool_name: "REPL"`.
3. Inspected the installed Claude Code bundle for REPL pool gating and hook-runner telemetry strings.

## Observation

1. **Not exposed:** `ToolSearch select:REPL,JavaScript` returns no tool (`REPL`, `JavaScript`, and `SendUserMessage` are absent). In the bundle the REPL is gated by `replToolInPool` on the Artifact start-kit path (`startKitOn`), not as a general session tool.
2. **Never observed in local history:** Local transcripts under `~/.claude/projects/*` and the guardrail audit log contain zero `repl_tool_call` events and zero `tool_name: "REPL"` records outside the probe's own search strings.
3. **Ambiguous static hook path:** Inner calls surface as `tool_progress` events carrying `repl_call.inner_tool_name`, `inner_tool_input`, and `inner_tool_use_id`, while the hook runner includes a distinct `"PreToolUse function-hook chain"` path emitting `tengu_repl_hook_finished` telemetry. Whether external *command* hooks execute in that chain cannot be determined statically from the minified Bun bundle.

## Consequence

`REPL` and `JavaScript` remain `CapabilityDeny` per ADR-0019. **Upgrade condition:** a captured guardrail audit record for a Claude session whose `tool_name` is an inner tool invoked from a `REPL` call, with the transcript's `repl_call.inner_tool_use_id` matching the hook's `tool_use_id`. `guardrail doctor --coverage claude` will surface the tools immediately if a future bundle exposes them.

## Links

- PR: #60 (merged 2026-09-18)
- ADR: [ADR-0019](../adr/0019-static-boundary-verification-vs-dynamic-meta-dispatch.md)
