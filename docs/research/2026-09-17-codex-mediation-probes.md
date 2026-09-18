# Codex mediation follow-ups — 2026-09-17

Worktree `.worktrees/codex-mediation`, branch `codex/mediation`, based on
`origin/main` at `535d55b`. Runtime: Codex CLI 0.154.0 on Linux. The existing
local Responses fixture now tests interactive stdin and native tool removal in
both direct and code-mode sessions. No model inference, credentials, or hosted
search execution is involved.

## Findings

| Probe | Baseline | Restricted configuration |
| --- | --- | --- |
| Launch `cat > stdin.txt` | Allowed Bash pre-hook; process starts | Runtime rejects command tool |
| Send fixture bytes with `write_stdin` | Bytes reach file; no pre-hook | Runtime rejects stdin tool |
| Poll with empty `chars` | Executes; no pre-hook | Runtime rejects stdin tool |
| Send EOF | Process exits 0; no pre-hook | Runtime rejects stdin tool |
| Apply a harmless patch | Allowed pre-hook; file created | Allowed pre-hook; file created |
| Outgoing web-search tool declaration | Present | Absent |

Both execution modes pass these five-call sequences. Baseline has two pre-hooks
(Bash and patch); restricted mode has one (patch). Baseline passing means the
known gap was reproduced; it does not mean stdin is protected. The fixture
asserts actual file contents and process completion, so an unknown session ID
or failed stdin call cannot masquerade as evidence of missing mediation.

For hosted tools, the measured boundary is **web-search availability in the
provider request**. The fixture does not perform a hosted search and reports
`hosted_execution_tested: false`. The claim that hosted web search bypasses local
hooks comes from the [official hook contract](https://learn.chatgpt.com/docs/hooks),
reviewed 2026-09-17. Simulating a hosted response would not establish remote
policy enforcement. Other hosted integrations remain outside this matrix.

## Optional native restriction

For sessions that can work without commands and web search:

```sh
codex -c 'web_search="disabled"' --disable shell_tool
```

The equivalent native settings, exercised in the isolated fixture, are:

```toml
web_search = "disabled"

[features]
shell_tool = false
```

Codex omits web search and rejects forced `exec_command`/`write_stdin` calls,
including nested code-mode calls. Hooked patches still work. These are native
feature restrictions, not a translation of Guardrail policy. They remove **all
shell execution**, including tests and builds. They do not disable every hosted
integration, establish complete containment, or justify enabling delegation.
Guardrail enable/disable does not rewrite the operator's config, consistent with
[ADR-0016](../adr/0016-codex-native-escalation-floor.md).

An exploratory run with `features.unified_exec=false` still advertised and ran
`exec_command` with this fixture's `shell_type: unified_exec` model catalog.
That flag alone is therefore not the prescribed mitigation. The
[official configuration reference](https://learn.chatgpt.com/docs/config-file/config-reference)
documents the shell feature and web-search mode; runtime evidence here is scoped
to CLI 0.154.0 and the checked-in model catalog.

## Runtime work still required

Preserving interactive execution requires Codex to mediate subsequent input.
An upstream contract needs to expose the target process/session, its original
command and effective directory, and the bytes being submitted before delivery.
A deny must deliver no bytes; polling must remain distinguishable from input.
Then Guardrail can design a continuation policy and test allow/deny behavior in
both direct and code-mode calls. Treating arbitrary stdin as a new shell command
would be incorrect: it may be data for any running program.

Hosted-tool policy requires a host-side enforcement point with trustworthy tool
arguments and a deny outcome before provider execution, or native managed
restrictions that remove the corresponding capability. The local hook adapter
cannot supply that missing enforcement point. Web-search removal addresses only
that capability. Delegation stays denied under
[ADR-0013](../adr/0013-delegation-inherits-enforcement-in-process.md).

Status and doctor now name the hosted-tool and stdin pre-hook gaps explicitly.
No capability classification or enforcement policy was relaxed.

## Reproduction and validation

Run the four mediation commands in [the smoke README](../../test/smoke/README.md).
Each retains `report.json`, `tools.json`, `requests.json`, native stdout/stderr,
and the actual hook log under its printed temporary directory. If a future
runtime introduces stdin pre-hooks, the baseline expectation fails and the
contract must be reviewed before updating this matrix.

The original direct matrix also passes (17 cases, 16 pre-hooks, 3 post-hooks,
one runtime rejection, 32 native floor checks), as does the original code-mode
matrix (14 cases, 14 pre-hooks, 3 post-hooks).

`go vet ./...`, the Windows amd64 cross-build, Python syntax, and diff checks
pass. The normal full Go run passes except two existing Git-discovery tests:
`TestFindCallbacksPreserveGitRepositoryState` and
`TestGitConfigApprovedWritesAllowSystemTempRepositories`. This environment has
an unrelated `/tmp/.git` marker; both tests pass when run alone with
`TMPDIR=/var/tmp`. Running the entire suite under an alternate nested temp root
is unsuitable: other tests assume `/tmp` and Unix socket paths exceed their
length limit. No engine tests or policy rules were changed to hide these
failures; CI must supply the clean-environment full-suite result.
