# Upstream draft: expose host-resolved execution context to shell policy hooks

Date: 2026-09-25. Status: condensed proposal and recorded evidence submitted as
[a comment on openai/codex#32360](https://github.com/openai/codex/issues/32360#issuecomment-5835671119).
Duplicate search found the existing working-directory/execution-context thread
and related [shell issue #44836](https://github.com/openai/codex/issues/44836);
no new upstream issue was opened. This document retains the fuller design draft.
No production behavior changes are proposed in this repository by this document.

**Status update, 2026-09-30:** the Windows observation below (0.155.1, every
command rejected by native policy) is superseded. On Codex 0.159, `PreToolUse`
dispatches for Windows commands and `updatedInput` is honored, but `tool_input`
still carries only `command`. Guardrail now mediates Windows commands behind a
PowerShell working-directory check proven by the session transcript
([#454](https://github.com/CtrlCarlitos/agent-guardrails/issues/454)); the
ask in this proposal, host-resolved execution context, still stands.

## Problem

Shell-policy integrations need to evaluate the command that will actually run,
under its actual interpreter and effective directory. The documented `Bash`
projection supplies command text; its envelope `cwd` means session directory.
It does not specify resolved shell identity, exact launch arguments, or the
per-command effective directory. Existing `updatedInput` supports command
rewrites. [Official hook contract](https://learn.chatgpt.com/docs/hooks#pretooluse),
[common fields](https://learn.chatgpt.com/docs/hooks#common-input-fields).

Inference: those fields alone cannot establish a safe interpreter-specific
rewrite or resolve relative paths against the actual execution directory.
Neither the operating system nor the hook launcher's shell identifies the
command interpreter. Native Linux may use a non-POSIX interpreter; Windows may
use PowerShell, cmd, or a POSIX shell.

## Reproduction and recorded observations

Use the observer-only probe from agent-guardrails commit `e45b278`:
[probe source](https://github.com/CtrlCarlitos/agent-guardrails/blob/e45b278/test/smoke/codex_execution_contract.py).
Prerequisites: a checkout of that revision, Python 3.11+, and a native `codex`
available on PATH in each environment. Run from the checkout root. Preserve the
printed artifact directory and `report.json`; record the actual Codex version.

Native Windows, in PowerShell:

```powershell
codex --version
python -B test/smoke/codex_execution_contract.py --require-context
python -B test/smoke/codex_execution_contract.py --code-mode --require-context
```

Inside WSL/Linux, using Linux Python and Linux Codex, not `codex.exe` interop:

```bash
codex --version
python3 -B test/smoke/codex_execution_contract.py --require-context
python3 -B test/smoke/codex_execution_contract.py --code-mode --require-context
```

The probe uses disposable settings, a local provider fixture, observing hooks,
and fixed `echo`/`pwd` commands. It requests default and available alternate
shells, with session-root and alternate-directory cases; the latter contains
spaces and Unicode. A requested shell field is not proof that Codex accepted
or honored that override. The fixture does not invoke Guardrail or test its
enforcement. The probe uses a one-invocation hook-trust bypass for its disposable
observer configuration; this is not an instruction to disable production hooks.
[Probe implementation](https://github.com/CtrlCarlitos/agent-guardrails/blob/e45b278/test/smoke/codex_execution_contract.py).

Previously recorded results, **not rerun for this draft**:

| Runtime | Direct and code-mode observations, each |
| --- | --- |
| Native Windows, Codex 0.155.1 | Six pre-hooks; all six commands rejected by native policy |
| WSL/Linux, Codex 0.154.0 | Six pre-hooks; all six commands executed, including alternate cwd |

Hook inputs contained only `tool_input.command`; envelope `cwd` stayed at the
session root. WSL output established the alternate execution directory despite
that envelope value. Windows rejection established dispatch, **not** an effective
execution directory or working Windows shell enforcement. Runtime versions differ:
this is not a controlled OS-only comparison. Full qualifications and recorded
probe-exit interpretation are in the
[committed investigation](https://github.com/CtrlCarlitos/agent-guardrails/blob/e45b278/docs/research/2026-09-25-codex-execution-contract.md).

`--require-context` intentionally cannot report success until the probe knows a
reviewed host-owned schema. A nonzero result is not itself evidence of a Codex
regression. Attach fresh raw artifacts and exact versions when submitting;
do not generalize these observations to newer builds.

## Proposed additive contract

Add host-generated `execution_context` outside model-controlled `tool_input`.
The following is illustrative, not an implemented API or final naming decision:

```json
{
  "execution_context": {
    "schema_version": 1,
    "invocation_id": "host-generated-id",
    "revision": 1,
    "environment": {
      "id": "host-owned-environment-id",
      "kind": "wsl-native",
      "os": "linux",
      "path_style": "posix"
    },
    "executable": "/usr/bin/bash",
    "shell": { "dialect": "bash", "version": "resolved-version" },
    "argv": ["/usr/bin/bash", "--noprofile", "--norc", "-c", "pwd"],
    "command_arg_index": 4,
    "effective_cwd": "/work/project/space dir unicode-é"
  }
}
```

Requirements for the contract, not claims about present behavior:

- Resolve the actual executable and supported dialect/version through the host,
  not model declarations, `Bash` naming, PATH guesses, or the hook process.
- Define `argv` as the exact ordered launch vector, including argv[0], command
  argument, login/profile and command-mode flags. For native Windows, also
  define the final process command-line serialization and quoting semantics;
  a reconstructed display command must not substitute for launch data.
- Supply the absolute effective cwd after per-call overrides, in the execution
  environment's namespace. Keep existing `cwd` meaning session cwd for backward
  compatibility. Define alias/canonicalization semantics rather than assuming
  a printed path proves directory identity.
- Bind context to the host's actual launch plan. Model arguments cannot create,
  replace, or override it. An ID or hash alone does not establish provenance;
  the host must enforce the binding and reject stale-context decisions.
- Identify native Windows, native Linux/WSL, and interop transitions distinctly.
  A Windows `wsl.exe` launch is not a native WSL shell contract. Resolve each
  relevant destination launch and path namespace, or report it unsupported.
- Expose schema availability explicitly. Missing or unsupported information
  must not be silently filled from the session environment by consumers.

Exact argv is necessary but does not confine the environment: profiles, startup
files, shell snapshots, inherited functions and environment variables can affect
semantics. Document what the host constrains and what remains outside the
contract. Executable/directory replacement races also need an explicit threat
model; string equality is not a general filesystem-confinement guarantee.
Do not include credential values or dump the full environment into hook payloads
to provide this context. IDs are correlation, not cryptographic authorization.

## Final validation after rewrites

Matching command hooks currently run concurrently. Consequently, approving the
original command cannot by itself authorize a different command another hook
returns through `updatedInput`.
[Official runtime behavior](https://learn.chatgpt.com/docs/hooks).

Propose an opt-in final, read-only validation phase after all input rewrites and
host normalization. Every validator sees the same immutable execution plan;
no `updatedInput` is accepted in this phase. A deny prevents launch. Define
fail-closed handling for required-validator errors/timeouts and conflicting
rewrites instead of accidentally treating unavailable validation as approval.

Any later shell, argv, command, environment, or cwd change invalidates that
validation. Rebuild the context and revalidate with a bounded retry limit, or
reject the launch. Do not repeatedly run command-rewriting hooks until an
unbounded fixed point; this creates rewrite loops. The executor must consume
the validated plan without an intervening substitution. Specify these semantics
for both direct calls and code-mode nested calls.
An equivalent upstream design is welcome; the requirement is validation of the
final host-owned launch, not these particular fields or event names.

## Acceptance criteria

1. Host tests compare context with actual launch parameters on native Windows
   and Linux/WSL, across supported interpreters, flags, cwd overrides, Unicode,
   spaces, and direct/code-mode calls. Unsupported shells are explicit.
2. Model-supplied context lookalikes cannot override host data; existing hooks
   keep their session-cwd and command-input compatibility.
3. Concurrent rewrite and validator tests prove no command can execute using
   approval for a previous plan. Late mutations, conflicting rewrites, timeout,
   missing validators, and retry exhaustion produce deterministic outcomes.
4. A supported ordinary command executes; a validator-denied command demonstrably
   does not. Native Windows policy rejections are recorded separately from hook
   denials. Windows tests must establish execution, not only hook dispatch.
5. Native WSL and Windows/WSL interop have separate fixtures. No host/destination
   path or dialect inference is accepted as execution-context evidence.
6. Documentation states the limits. Hosted/specialized tool paths and subsequent
   interactive input remain separate coverage questions, not claims solved by
   this addition. [Current coverage limits](https://learn.chatgpt.com/docs/hooks#tool-coverage).

This proposal supplies a prerequisite for sound shell-policy integration; it
does not claim complete containment or justify removing current fail-closed
behavior before the contract and real enforcement tests exist.
