# ADR-0019: Static Boundary Verification vs Dynamic Meta-Dispatch

## Status

Accepted

## Context

The four-plane coverage audit and extended tool classification revealed a recurring class of tools that break pre-hook mediation: dynamic meta-dispatch and out-of-band input streaming. Examples include:
- `call_mcp_tool`: an Antigravity generic meta-dispatcher accepting `ServerName`, `ToolName`, and arbitrary `Arguments`.
- `tool_caller`: a generic invoker dispatching tools by dynamic name and payload.
- `send_command_input` / `manage_task(Action: send_input)`: primitives that deliver arbitrary stdin text into a previously spawned shell or background task.
- `REPL` / `JavaScript`: execution environments capable of launching inner tool invocations (`repl_tool_call`). See the evidence note below.

Guardrail's core security invariant requires static boundary verification: before any action executes on the host, the adapter must inspect the call, resolve its concrete tool identity, and project its parameters into canonical Engine input shapes (`ToolCall.Paths`, `ToolCall.Command`, `ToolCall.URL`, `ToolCall.Query`). The Engine then evaluates these canonical shapes against deterministic policies (P1 path containment, P2/P3 destructive command filtering, P4 secret protection, P5 self-configuration integrity, web egress restrictions).

Dynamic meta-dispatch undermines this model:
1. **Opaque indirection**: The concrete tool identity and its parameters are hidden behind a wrapper. Even if an adapter attempts to unpack nested JSON arguments dynamically, it cannot guarantee that the runtime will only dispatch the inspected payload or that nested tool calls will trigger intermediate pre-hooks.
2. **Asynchronous stream injection**: Once a process is launched (e.g. via `run_command`), injecting commands or text via stdin streams (`send_command_input`) bypasses the pre-hook command classifier and path resolution entirely.
3. **Audit loss**: Post-tool mutation hooks and audit log entries cannot reliably attribute changes to a specific, audited tool specification when actions are multiplexed through meta-invokers.

## Decision

1. **Adapters deny what they cannot statically inspect through indirection**: Any tool that acts as a dynamic meta-dispatcher or out-of-band input injector is classified as `CapabilityDeny` in its plane contract or demoted to `CapabilityDeny` within its adapter.
2. **Static boundary invariant**: Every mediated tool call presented to Guardrail must:
   - Identify a single, concrete, first-class tool identity known to the plane contract or MCP family registry.
   - Have a statically declared, inspectable schema whose parameters can be projected into canonical Engine input shapes.
3. **Direct invocation over dynamic indirection**: MCP tools must be invoked through first-class bindings (e.g., eager declarations like `mcp_<server>_<tool>` or plane-native bindings) where arguments are directly inspectable, rather than through `call_mcp_tool`.
4. **Non-interactive execution over stream injection**: Command execution must be non-interactive and self-contained within `run_command` (or equivalent), ensuring that the full command text is classified before execution. `send_command_input` and `manage_task(Action: send_input)` are strictly denied.
5. **Actionable redirection**: Denials for meta-dispatch tools must return actionable guidance explaining the boundary invariant and directing the model to the corresponding first-class native tool or registered MCP tool.

## Consequences

- **Preserved policy guarantees**: Security checks (secret path protection, command filtering, workspace boundaries) cannot be evaded through nested or deferred dynamic dispatch wrappers.
- **Fail-closed posture**: Runtimes introducing generic or dynamic invocation primitives default to denial until first-class, statically verifiable hooks are exposed.
- **Clear guidance for models**: Rather than uninformative rejections, models receive guidance specifying how to call the underlying capability directly.

## Evidence: Claude Code `REPL` / `JavaScript` (2026-09-18, Claude Code 2.1.275)

The question "do REPL-driven inner tool calls reach PreToolUse?" was probed and
could not be closed empirically, so the Deny stands on the following facts:

1. **Not exposed.** Neither `REPL`, `JavaScript` nor `SendUserMessage` is offered
   to a Claude Code session on this account/version: `ToolSearch select:REPL,JavaScript`
   returns no tool. The bundle gates the REPL through `replToolInPool` on the
   Artifact start-kit path (`startKitOn`), not as a general tool. A live nested
   call cannot be issued from a guarded session.
2. **Never used here.** All local session transcripts (`~/.claude/projects/*`)
   and the guardrail audit log contain no `repl_tool_call` event and no
   `tool_name: "REPL"`; the only matches are the probe's own search strings.
3. **Static signal is ambiguous, not reassuring.** Inner calls surface as
   `tool_progress` events with `repl_call.inner_tool_name`, `inner_tool_input`
   and an `inner_tool_use_id` — nested tool uses carry their own IDs, which is
   consistent with ordinary tool execution — but the hook runner also carries a
   distinct "PreToolUse function-hook chain" path with `tengu_repl_hook_finished`
   telemetry. Whether *command* hooks (the guardrail adapter) are part of that
   chain is undetermined from the minified bundle.

Upgrade condition: a captured guardrail audit record for a Claude session whose
`tool_name` is an inner tool invoked from a `REPL` call (evidenced by the
transcript's `repl_call.inner_tool_use_id` matching the hook's `tool_use_id`).
Until then the contract keeps `REPL` and `JavaScript` at `CapabilityDeny`, and
`guardrail doctor --coverage claude` will surface the tools the moment they
appear in a bundle's tool list, so the question re-opens on facts, not on memory.
