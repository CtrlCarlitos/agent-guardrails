# Plane Tool Coverage: 2026-09-15

## Scope and conclusion

`agent-guardrails` currently implements adapters only for Claude Code, OpenCode,
and Antigravity. It normalizes a call to `Bash`, `Read`, `Edit`, `Write` (plus
OpenCode `List`) and evaluates path, shell, and Overlay checks; an unrecognized
tool can still match an Overlay rule, but has no adapter-extracted command or
path data ([`internal/engine/evaluate.go`](../../internal/engine/evaluate.go),
[`internal/engine/toolcall.go`](../../internal/engine/toolcall.go)). The Engine
is explicitly not an OS sandbox, so dynamically concealed same-user I/O is out
of scope ([`README.md`](../../README.md)).

| Plane | Active integration | Directly enforced native shapes | Important uncovered/bypass surface | Fallback if Engine/hook is unavailable |
|---|---|---|---|---|
| Claude Code | `guardrail hook claude` command hook | `Bash`, `Read`, `Edit`, `Write`, legacy `MultiEdit`; `PostToolUse` only for write/edit; `SessionStart` posture | All other built-ins, notably `PowerShell`, `NotebookEdit`, `Agent`/tasks, `WebFetch`/`WebSearch`, LSP, MCP, and terminal-adjacent `Monitor`; indirect subprocess I/O | Generated `permissions.deny`/`ask` floor for coarse Bash, `Read`, and `Edit` rules |
| OpenCode | Generated in-process JS plugin spawning `guardrail hook opencode` | Plugin sends every `tool.execute.before` call, but only normalizes `bash`, `read`, `edit`, `write`, `list`; post enforcement is not installed | `apply_patch`, `grep`, `glob`, LSP, `task`/subagents, web tools, custom tools, MCP and unknown tools are not classified as Engine file tools; plugin `ask` is a throw, not a native prompt | Generated `permission.bash`/`read`/`edit` floor; it covers OpenCode `write` and `apply_patch` as `edit`, but not every tool |
| Antigravity | `guardrail hook antigravity pre|post` command hooks | `run_command`, `view_file`, `write_to_file`, `replace_file_content`, `multi_replace_file_content` | `list_dir`, `find_by_name`, `grep_search`, `search_web`, `read_url_content`, task/scheduling/permission tools, subagent/collaboration, questions/media; post results never gate | None: hooks are the entire boundary; failed/missing hook behavior is platform-dependent and unverified |
| Codex | **Planned only; no adapter, generator, sync target, or fallback in this repository** | None | All Codex tools are outside agent-guardrails today, including Bash, `apply_patch`, local functions/`spawn_agent`, MCP, and hosted `WebSearch` | None from agent-guardrails |

## Claude Code

The generated `PreToolUse` matcher is exactly
`Bash|Read|Edit|Write|MultiEdit`; its post matcher is
`Write|Edit|MultiEdit`, and its only other installed event is `SessionStart`
([`internal/genconfig/claude.go:192-223`](../../internal/genconfig/claude.go)).
`ParseClaude` preserves the native name and only extracts `command` and a
single `file_path`, so the listed shapes receive the complete data required by
the Engine ([`internal/adapter/claude.go:24-62`](../../internal/adapter/claude.go)).

This leaves native `PowerShell` and `NotebookEdit` outside the matcher, as well
as task/subagent (`Agent`, `Task*`), network (`WebFetch`, `WebSearch`), and
other read/write-capable families. MCP tools are hook-matchable by Claude Code
but are not in this matcher. Anthropic's current tool reference enumerates
these tools, and its hook reference says `PreToolUse` can match regular MCP
tool names. A `Bash` path check also cannot constrain arbitrary child-process
I/O; Anthropic documents the same limitation for read/edit permission rules.

The failure fallback is real but intentionally coarse: generated Claude
`permissions.deny` and `ask` rules cover shell, secret read/edit, self-config,
and CI/infra-lock patterns ([`internal/genconfig/claude.go:15-68`](../../internal/genconfig/claude.go),
[`internal/genconfig/claude.go:178-189`](../../internal/genconfig/claude.go)).
It is not a complete command or filesystem sandbox.

## OpenCode

The plugin is registered with OpenCode's `tool.execute.before` hook. It passes
the plugin-defined envelope to the binary; the adapter maps only native
`bash/read/edit/write/list` to the normalized tool names
([`internal/adapter/opencode.go:27-74`](../../internal/adapter/opencode.go),
[`docs/adr/0007-opencode-wire-format-and-ask-via-throw.md`](../adr/0007-opencode-wire-format-and-ask-via-throw.md)).
The plugin forwards a common path argument for unknown tools where present, but
the Engine treats only `Read`, `Edit`, `Write`, and `MultiEdit` as direct file
tools; an unknown tool's path is available only to an Overlay match
([`internal/engine/rules_path.go:15-21`](../../internal/engine/rules_path.go),
[`internal/engine/rules_path.go:98-154`](../../internal/engine/rules_path.go)).
The repo also documents that a missing `tool.execute.after` plugin hook means
P8 post-edit denial only surfaces on Claude today
([`README.md:35-47`](../../README.md)).

OpenCode's current built-ins include `apply_patch`, `grep`, `glob`, optional
LSP, `skill`, `todowrite`, `webfetch`, `websearch`, and `question`; it also
supports custom tools and MCP. None except the five mapping names is explicitly
normalized here. Its declarative `edit` permission covers `edit`, `write`, and
`apply_patch`, but the generated floor declares only `bash`, `read`, and `edit`
([`internal/genconfig/opencode.go:23-81`](../../internal/genconfig/opencode.go)).
It is the actual interactive fallback boundary: OpenCode's plugin API can allow
or throw only, so the Engine's `ask` throws and relies on declarative
permissions for a real prompt. OpenCode's plugin documentation confirms the
pre-tool hook and throw behavior; its permissions documentation confirms the
tool families and `ask`/`deny` model.

## Antigravity

The generated pre-hook matcher is precisely
`run_command|view_file|write_to_file|replace_file_content|multi_replace_file_content`;
post hooks only the three mutators ([`internal/genconfig/antigravity.go:6-32`](../../internal/genconfig/antigravity.go)).
The adapter maps those five exact call names to `Bash`, `Read`, `Write`, and
`Edit`, extracting only `CommandLine`, `AbsolutePath`, or `TargetFile`
([`internal/adapter/antigravity.go:28-92`](../../internal/adapter/antigravity.go)).
`ask` is emitted as Antigravity `force_ask`, preserving a fresh approval gate
([`internal/adapter/antigravity.go:94-110`](../../internal/adapter/antigravity.go)).

Antigravity's first-party hooks reference lists its additional native tools:
directory/list and search, `search_web`/`read_url_content`, terminal task and
schedule management, `ask_permission`, subagent creation/messaging/management,
questions, and image generation. They are known native tools but are excluded
by this registration, so they bypass the Engine. It also states that
`PreToolUse` can gate a matching tool, demonstrating that these omissions are
coverage choices, not an inherent hook limitation.

There is no declarative fallback. The repository's accepted design is that
Antigravity `hooks.json` is the whole boundary and missing/crashed-hook
behavior is likely fail-open but unverified
([`docs/adr/0008-antigravity-no-declarative-floor.md`](../adr/0008-antigravity-no-declarative-floor.md)).
Post-hook responses are `{}`, so they are audit-only rather than a post-execution
block ([`README.md:40-50`](../../README.md)).

## Codex

Codex is expressly described as planned in this repository
([`README.md:3-6`](../../README.md)); `cmd/guardrail` accepts only `claude`,
`opencode`, and `antigravity` for `hook` and `gen-config`
([`cmd/guardrail/hook.go:22-55`](../../cmd/guardrail/hook.go),
[`cmd/guardrail/genconfig.go:14-25`](../../cmd/guardrail/genconfig.go)). The
older design/ADR mentions a future `guardrail hook codex`, not an implementation
([`DESIGN.md:84-91`](../../DESIGN.md),
[`docs/adr/0002-single-go-binary-subcommand-adapters.md`](../adr/0002-single-go-binary-subcommand-adapters.md)).

This is not because Codex lacks an integration point. Its current first-party
hooks support `PreToolUse`/`PostToolUse` for `Bash` (including unified exec),
`apply_patch` (also matchable as `Edit`/`Write`), MCP, and other local functions
such as `update_plan` and `spawn_agent` (`Agent`). But hosted tools such as
`WebSearch` do not traverse that hook path; `write_stdin` does not re-run
`PreToolUse`; and some specialized paths can opt out. Thus a future Codex
adapter could cover local function-tool shapes but would still need a fallback
or sandbox strategy for hosted/network and opt-out paths. No such adapter,
generated Codex config, or fallback currently exists here.

## First-party sources

- Anthropic: [Tools reference](https://code.claude.com/docs/en/tools-reference), [Hooks reference](https://code.claude.com/docs/en/hooks), and [Permissions](https://code.claude.com/docs/en/permissions).
- OpenCode: [Tools](https://opencode.ai/docs/tools/), [Plugins](https://opencode.ai/docs/plugins/), and [Permissions](https://opencode.ai/docs/permissions/).
- Google: [Antigravity Hooks](https://antigravity.google/docs/hooks.md).
- OpenAI: [Codex Hooks](https://developers.openai.com/codex/hooks/) and [Codex Permissions](https://developers.openai.com/codex/permission-modes/).
