# ADR-0019: Static Boundary Verification vs Dynamic Meta-Dispatch

## Status

Accepted

## Context

The four-plane coverage audit and extended tool classification revealed a recurring class of tools that break pre-hook mediation: dynamic meta-dispatch and out-of-band input streaming. Examples include:
- `call_mcp_tool`: an Antigravity generic meta-dispatcher accepting `ServerName`, `ToolName`, and arbitrary `Arguments`.
- `tool_caller`: a generic invoker dispatching tools by dynamic name and payload.
- `send_command_input` / `manage_task(Action: send_input)`: primitives that deliver arbitrary stdin text into a previously spawned shell or background task.
- `REPL` / `JavaScript`: execution environments capable of launching inner tool invocations (`repl_tool_call`).

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
