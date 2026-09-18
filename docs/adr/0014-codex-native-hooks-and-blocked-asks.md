# ADR-0014: Codex native hooks and blocked Asks

Codex uses synchronous command handlers in `hooks.json`, discovered beside an
active config layer. The Adapter consumes Codex's native `session_id`, `cwd`,
`hook_event_name`, `tool_name`, and `tool_input` envelope. Shell and unified exec
arrive as `Bash` with `tool_input.command`; patches arrive as `apply_patch` with
the patch in that same field. Local function names retain their own arguments.
The parser bounds input, rejects malformed envelopes, and projects every patch
source and move destination. Unknown tools always Deny on this plane, including
when the general unknown-tool posture is audit-only.

Allow exits 0; shell calls additionally receive the directory guard described below. Deny exits 2 with model-facing guidance. Ask also
exits 2: Codex currently parses but does not support `permissionDecision: "ask"`
and continues execution after reporting that hook error. Conversational approval
therefore cannot release an Ask. The operator must perform the operation outside
the session or authorize the relevant policy using Guardrail. Complete blocks
and reports the broker request and approval URL. PostToolUse uses exit 2 for
recipe feedback; it cannot undo an already completed edit. SessionStart emits
additional context using the existing compatible output shape.

Generate catch-all PreToolUse, patch PostToolUse, and catch-all SessionStart
handlers. Registration and runtime trust are different: Codex skips new or changed
non-managed hooks until the operator reviews them in `/hooks`. Status reports
registration and explicitly asks for trust verification; it never claims that
registration proves active enforcement. The generated executable is shell-quoted.

This is a local tool guardrail with known runtime gaps, not complete confinement:
hosted web tools bypass these hooks, `write_stdin` does not rerun PreToolUse,
and specialized paths can opt out. Hook feature disablement, untrusted hooks,
runtime hook timeouts and failures cannot be made fail-closed by a Go
adapter that is never invoked. Native sandbox/managed policy remains necessary
for containment. Do not infer hosted-tool coverage from a fixture sent directly
to the Adapter. Delegation stays denied under ADR-0013's evidence requirement.

Evidence: Codex CLI 0.154.0; [official hook contract](https://learn.chatgpt.com/docs/hooks)
reviewed 2026-09-17, especially Tool coverage, Common input fields, PreToolUse,
and PostToolUse. The reproducible local Responses fixture in
`test/smoke/codex_probe.py` runs the installed CLI without model inference or
credentials. Its hook log distinguishes real runtime dispatch from direct
Adapter fixtures in `test/fixtures/codex/`.

## Effective shell directory (native probe finding)

CLI 0.154.0 omits unified exec's `workdir` from hook input and reports the session
cwd even when the command executes elsewhere. A relative read under a fake
`.ssh` directory passed evaluation against the session root in the native probe.
For allowed Bash calls the Adapter therefore returns supported `updatedInput`
with a shell precondition: the physical execution directory must equal the
physical evaluated cwd. Otherwise the command exits before any original action,
with guidance to use the session directory and an explicit `cd` in the command.
This preserves the original command's behavior when its evaluated directory is
correct and blocks the unprojectable form instead of silently moving its effects
to a different directory. Code-mode calls receive the same precondition.

The generated command handler maps nonzero evaluator exits (including a missing
binary) to native blocking exit 2. Codex-level hook timeout, skipped hook trust,
and hooks-disabled settings remain runtime limitations. This guard assumes the
same POSIX shell boundary as the Engine; Windows build support does not imply
PowerShell semantic parity.
