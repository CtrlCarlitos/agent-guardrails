# One Go binary, per-plane subcommand adapters

"Best tool per plane" could mean genuinely independent adapter implementations
(opencode's plugin doing policy in TypeScript against its typed API, Antigravity's in
Python). That is more platform-faithful but reproduces the drift this project exists
to kill.

Decision: the policy logic lives once in a single Go binary (`guardrail`). Each
command-hook plane is a subcommand — `guardrail hook claude`, `guardrail hook
antigravity pre`, `guardrail hook codex` — that reads that plane's stdin payload and
emits its native response contract. opencode, whose native mechanism is an in-process
JS plugin, gets a ~30-line plugin that `spawnSync`s `guardrail hook opencode` and maps
the result. "Best tool per plane" is satisfied by using each plane's *native
extension mechanism*, not by rewriting the matcher.

Go specifically: `mvdan.cc/sh` (Go) is the best-in-class shell parser, and the P3
tokenizer is non-negotiable; static binary, zero runtime deps, cross-compiles to
Linux/macOS/Windows.

## Consequences

- opencode does a subprocess exec per tool call instead of an in-process call —
  sub-millisecond, and exactly what takumi-dream's `takumi-guard.js` already does.
- Adding a plane = a new subcommand + (if it needs a code plugin) a thin shim.
