# Codex plane probe results — 2026-09-17

Implemented on `codex/plane`, based on `origin/main` at `981cf13`, in
`.worktrees/codex-plane`. Native runtime: `codex-cli 0.154.0` on Linux. Probes use
a deterministic loopback Responses provider, a fixture model catalog, and fake
secret data in disposable directories. There is no model inference or API use.

| Check | Result |
| --- | --- |
| Adapter contract fixtures | 15 cases pass, including malformed/unknown tools |
| Native direct tools | 17 cases pass: 16 pre-hooks, 3 post-hooks, 1 host rejection |
| Native code-mode nested tools | 14 cases pass: 14 pre-hooks, 3 post-hooks |
| Native declarative floor | All 32 prefixes return `forbidden` in Codex execpolicy |
| Full Go regression suite | `go test ./... -count=1` passes |
| Static/build checks | `go vet ./...`, Windows amd64 cross-build, gofmt, diff check pass |
| Lifecycle | Broker validation, enable/disable, sync, CODEX_HOME, merge ownership and drift tests pass |

## Native matrix

Both modes cover an allowed shell command; denied secret read and hard reset;
Ask-to-block conversion; allowed patch creation and deletion; denied secret
write, move destination and Codex configuration edit; secret-image denial;
post-edit Go lint failure; MCP denial; unapproved egress; and an alternate
execution directory. Direct mode also covers a safe local control, denied
`spawn_agent`, and an unknown name rejected by Codex before hook dispatch.

The native unknown-name rejection is not counted as adapter coverage. Direct
hook fixtures separately prove unknown tools fail closed even when the shared
policy has an audit-only unknown-tool posture. Native delegation denial proves
that the parent call can be blocked, not that child execution inherits complete
mediation. Delegation therefore remains denied under ADR-0013.

Native MCP and delegation calls use the namespace/name pairs advertised by
Codex: `mcp__fixture` / `read` and `multi_agent_v1` / `spawn_agent`. Their hook
payloads use canonical `mcp__fixture__read` and `spawn_agent`. Code-mode nested
calls have fresh `exec-<uuid>` hook call IDs; the fixture compares their ordered
invocations rather than incorrectly equating them with the outer call ID.

## Stops resolved

- Codex does not support PreToolUse Ask. The adapter blocks with actionable
  guidance and never emits the unsupported `permissionDecision: "ask"` value.
- Patch paths include move destinations. A move into `.env` was blocked before
  changing either source or destination.
- Post-edit deletion omits deleted files from recipe execution, while malformed
  Go edits produce real PostToolUse lint feedback.
- Native `exec_command.workdir` is absent from the hook envelope; its `cwd`
  remains the session directory. The probe initially reproduced an allowed
  relative read from a fake `.ssh` directory. Allowed commands now receive a
  supported input rewrite that verifies the physical execution directory before
  running the original command. On mismatch it exits with guidance to use the
  session directory and explicit `cd`, making path changes visible to analysis.
  Direct and code-mode probes confirm the fake content is not returned.
- Missing/evaluator-failure exits are converted by the generated command handler
  to Codex's blocking exit 2. A shell execution test verifies both missing-binary
  blocking and executable-path quoting against shell injection.
- Native hook trust is separate from registration. Status includes that caveat;
  enable reconciliation also detects missing/stale generated escalation rules.

## Reproduction and retained artifacts

Run the two commands in `test/smoke/README.md` after building the binary. The
runner prints a JSON summary and retains hook input, native stdout/stderr,
provider requests, and report JSON under its printed temporary directory.
The successful direct run from this session is
`/tmp/guardrail-codex-native-9wdggyr_/report.json`; the successful code-mode run is
`/tmp/guardrail-codex-native-ydbjwfdl/report.json`.

Go tests need local sockets for the existing broker/HTTP tests. A sandboxed
recheck also exposed a synthetic read-only `/tmp/.git`, which changes Git
repository discovery in `TestFindCallbacksPreserveGitRepositoryState`. The
unchanged `origin/main` baseline failed identically in that sandbox. Outside
that sandbox `/tmp/.git` does not exist, and the full suite passes. No existing
engine assertion was relaxed to hide the environmental failure.

## Remaining runtime boundaries

Full host containment is not established: hosted tools bypass local hooks,
`write_stdin` does not rerun PreToolUse, specialized paths can opt out, and
untrusted/disabled/timed-out hooks cannot be repaired by an adapter that is not
invoked. The native floor governs command escalation, not all reads or hosted
network use. Hook registration must not be presented as proof of complete
runtime parity. These are documented in
[ADR-0014](../adr/0014-codex-native-hooks-and-blocked-asks.md) and
[ADR-0015](../adr/0015-codex-native-escalation-floor.md), with links to the official
Codex contracts. The filesystem/shell implementation follows the project's
POSIX policy semantics; Windows is cross-built, not native-runtime certified.
