# Codex execution contract: Windows and WSL

Date: 2026-09-25. Status: investigation; production behavior unchanged.

## Finding

The current evidence does not establish a trustworthy shell execution context
for Guardrail on either platform. Windows and WSL need the same prerequisite:
host-owned execution metadata bound to the invocation actually launched. Hook
dispatch alone is not that prerequisite. Do not infer POSIX semantics merely
because Codex runs on Linux.

The official contract defines `cwd` as the session directory. Shell and unified
exec use the hook name `Bash` and expose `tool_input.command`; the documented
input does not establish the executor's resolved shell executable, invocation
flags, or effective per-command working directory. Supported rewrites replace
the command string, not a documented host-owned execution-context object.
[Official hooks: common input and PreToolUse](https://learn.chatgpt.com/docs/hooks#common-input-fields).

## Measured evidence from this session

The observer-only
[execution-contract probe](../../test/smoke/codex_execution_contract.py)
was run natively on each platform in direct and code modes:

| Runtime | PreToolUse observations | Fixed command execution |
| --- | --- | --- |
| Windows, Codex 0.155.1, direct | Six | All six rejected by native policy |
| Windows, Codex 0.155.1, code mode | Six | All six rejected by native policy |
| WSL/Linux, Codex 0.154.0, direct | Six | All six executed, including the alternate directory containing spaces and Unicode |
| WSL/Linux, Codex 0.154.0, code mode | Six | All six executed, including the alternate directory containing spaces and Unicode |

The runtime versions differ, so this is not a controlled OS-only comparison.
Windows reports probe exit 1 (execution not established); the final WSL
code-mode report records exit 2 with `--require-context` (observations complete,
host context still unverified). The invoking Windows/WSL shell reported 1 for
that nonzero Linux result; use `probe_exit` in the retained JSON report.
Neither result is an enforcement pass.

Code mode uses host-generated nested call IDs, not the outer Responses call ID.
The probe correlates each sequential provider-request window with its hook
events, retains original IDs, and rejects missing or duplicate pre-hooks. It
decodes the code-mode tool-output wrapper before checking the execution marker.

Tracked in [issue #347](https://github.com/CtrlCarlitos/agent-guardrails/issues/347).

In both runs, shell hook inputs contained only `tool_input.command`; the envelope
`cwd` remained the session root, including requests for the alternate execution
directory. Windows rejection means that run does not demonstrate an effective
execution directory. WSL command output establishes execution in the alternate
directory while the corresponding hook still reports the session root.

The probe submits a fixed `echo`/`pwd` command, uses disposable configuration,
records hook payloads and tool responses, and drives Codex with a local fixture
instead of a model service. Its hooks only observe; they do not invoke Guardrail.
These are **not Guardrail enforcement tests**. Requested shell overrides are not
proof that Codex honored them: their accepted schema and actual interpreter
selection remain unverified. The harness deliberately reports execution context
as unverified rather than treating a model-supplied field as host evidence.
Source: [probe implementation](../../test/smoke/codex_execution_contract.py).

## Relationship to the existing decision

[ADR-0014](../adr/0014-codex-native-hooks-and-blocked-asks.md) already records the
session/effective-directory mismatch and the need for a proven shell before
emitting a shell-specific directory precondition. Its POSIX rewrite is not
evidence that all Linux executions use a compatible interpreter. The new Windows
dispatch observation also does not establish usable shell enforcement or complete
coverage. This note does not amend that ADR or change the Adapter.

Official documentation separately warns that hosted tools and some specialized
paths are outside these hooks, and `write_stdin` does not rerun PreToolUse.
Therefore neither a successful rewrite nor observed dispatch establishes complete
containment. [Official tool coverage](https://learn.chatgpt.com/docs/hooks#tool-coverage).

## Proposed minimum host-owned context

This is a proposed upstream contract, not a claim that Codex implements it.
Before policy evaluation, the host must resolve and provide:

- The actual shell executable's absolute identity and shell dialect/version
  needed by the supported parser. The hook name `Bash`, hook launcher shell,
  operating system, PATH, and a requested shell string are insufficient.
- The exact ordered executor argv, including login/profile flags, command-mode
  flags, and the command-bearing argument. Any startup code or inherited state
  that changes execution semantics must be constrained or explicitly accounted
  for; reporting argv alone does not neutralize profiles.
- The effective absolute working directory in the executor's filesystem
  namespace, resolved after per-tool overrides. Session cwd is separate metadata.
  Windows-to-WSL or reverse execution must identify the destination environment
  and path interpretation rather than silently reuse host paths.
- A versioned, host-generated context tied to the tool invocation and the exact
  command evaluated. Model arguments must not be able to impersonate it. The
  executor must launch that context without a later shell/directory substitution;
  a relevant change or rewrite requires revalidation before execution.

Guardrail should reject missing, contradictory, or unsupported context with
specific guidance. It should not add a configuration switch that merely asserts
which interpreter the host will use.

## Implementation gate and next steps

1. Obtain and validate the host contract above, or separately review an execution
   mechanism that itself controls the real interpreter and directory. Changing
   the execution boundary is a design decision, not an adapter-only repair.
2. Capture the accepted host schema and real payloads as regression fixtures.
   Implement native Windows and Linux normalization behind the shared Engine;
   unsupported shells and cross-environment execution remain explicit cases.
3. Run real enforcement tests on both systems: an ordinary command must execute,
   a policy-denied command must not execute, and alternate directories cannot
   evade path policy. Cover supported shells/flags, profiles, spaces, Unicode,
   quoting, directory aliases, rewritten commands, code-mode nested calls, edits,
   and missing executables. Observer probe success is not this acceptance gate.
4. Validate installation, trust review, upgrades, and failure diagnostics on both
   platforms before declaring support. Keep dispatch, command execution, policy
   enforcement, and containment claims separate.

Completion remains blocked on trustworthy host context or a separately reviewed
execution mechanism. Removing the Windows refusal or guessing a shell on Linux
does not satisfy this gate. No production change follows from this research.
