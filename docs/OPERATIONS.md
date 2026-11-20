# Operations runbook — when it's weird, run this

For the operator at a terminal, not for the agents. Every command here is safe to
run at any hour; the ones that change anything ask for your approval first: a
`[y/N]` on the terminal by default, or your passkey if Operator config says
`approval = "passkey"` ([operator-approvals.md](operator-approvals.md),
ADR-0033). Where a row below says "Passkey", read "approval".

## Autonomous delivery

For the standing "fix on red, merge on green, clean up on merged" workflow,
enable [repository-authorized delivery](delivery.md) once from your terminal.
Agents then use a bounded exact-head merge/cleanup operation; ordinary command
grants and all other protections stay in force. A narrower task endpoint still
wins, and CI-control changes or valuable uncommitted work remain exceptions.

## First 60 seconds

```
guardrail doctor        # wiring: policy, overlay, hooks per plane, warnings
guardrail selftest      # behaviour: the installed binary still denies/asks as it should
guardrail audit         # what happened: decisions, top rules, unclassified tools
```

Healthy looks like: doctor's last line reads `verdict: healthy`,
`selftest: all probes passed`, and no rule in the audit top list you don't
recognise. If all three are clean, the problem is not Guardrail.

`verdict: N problems (see above)` is the sum of everything doctor printed in a
warning register: each policy warning, an overlay warning or parse error, an
unreadable operator config, a plane that is present but not registered (or
disabled, unparseable, or `CANNOT SPAWN`), unmarked legacy hook groups,
ownership drift, an Antigravity floor warning, an unreachable engine, a spawn
latency warning, each credential-posture `WARNING`, and, with `--coverage`,
uncontracted tools. It is not counted: `NEVER OBSERVED FIRING` (a soft caveat a
fresh enrolment legitimately shows), `no manifest`, advice lines (`allow list`,
`credential variables set`) and the codex Windows `unenforced` note. Plain
`doctor` exits 0 whatever the verdict (use `selftest` to gate); `--coverage`
keeps its exit 1. No verdict is printed when doctor fails to run (exit 2).

**`registered` is a claim, not enforcement.** doctor can see that a hook is
installed; only an audit record shows it ran. A claude plane that is healthy
but has not yet been exercised legitimately reads:

```
claude settings: guardrail hook registered but NEVER OBSERVED FIRING — no audit
record from a real session since this binary was built. Registration is not
enforcement; confirm with `guardrail selftest --evidence claude`
```

That is not a fault. It clears itself the first time a real session is
mediated, and `guardrail selftest --evidence claude` is the direct check —
exit 0 once two pre-hook records from one real session exist, exit 1 until
then. A freshly built or freshly installed binary resets the window, because
the scan starts at the binary's mtime. When real-session records exist but all
predate the binary — the state right after every update — doctor says so
instead of warning (#520):

```
claude settings: guardrail hook registered — evidence window reset by the recent
update (N earlier real-session records predate this binary): start a Claude
session, then re-run `guardrail selftest --evidence claude`
```

The window is not carried across binaries on purpose: a new binary is a new
handler, and only its own records show that it runs.

The line that *is* a fault names its own cause instead:

```
claude settings: guardrail hook registered but CANNOT SPAWN — <reason>. Nothing
is being enforced; re-run `guardrail plane enable claude` to rewrite the command
```

A command that cannot spawn has necessarily never fired, so doctor prints the
spawn fault and suppresses the never-observed caveat — cause, not consequence.
Neither is appended when nothing is registered at all. This is what #149 looked
like from the outside for four days: `registered`, green, enforcing nothing.

Which plane, OS and shell combinations have been seen enforcing, and which
are only registered or CI-tested, is recorded in
[compatibility-matrix.md](compatibility-matrix.md). A new dated run of the
checks above is how a cell there moves up.

## Symptom → command

| You see | Run | Why |
|---|---|---|
| doctor: `verdict: N problems (see above)` | Read the `WARNING` and warning-register lines above it; the rows below name each fix | The last line of doctor counts them so you do not have to (#105). `verdict: healthy` means none. |
| Agent says it was blocked and you don't know why | `guardrail explain` from the repository (or `guardrail explain <session-id>`) | Prints the newest ask/deny for this repository: what was evaluated, the verdict and `rule_id`, the reason, the next step the agent was given, and what only you can do about it. Selftest probes are excluded. See **Why was this blocked** below. |
| A verdict looks wrong and you want to file it | `guardrail report` (or `--last N` / `--id <timestamp\|request-id>`) | Prints a ready-to-paste GitHub issue title and body for that record: version, OS, plane, tool, verdict, rule, reason and command, with every field run through the audit redaction and your home directory shown as `~`. It prints only (no `gh`, no network), so review the body, then paste it at the new-issue page it names on stderr. |
| `operator action pending: …` (exit 3) from `setup`, `plane enable` or `plane disable`: no terminal and no host approval, the `[y/N]` was declined, or (passkey mode) the approval daemon is not running or the request was denied or expired | Run `guardrail setup` from an interactive terminal, approve it (answer `y`, or your passkey in passkey mode), then re-run what provisioned the machine | Nothing is broken: the binary is installed and what is registered keeps enforcing. Only the change waited on you (#364). `guardrail next` lists what is still owed. |
| An agent's host asked you to approve a `guardrail …` command | Read the action it names; approve only if you asked for it | Prompt mode (ADR-0033): the command runs once with the approval ticket the hook recorded. Declining leaves nothing usable. If the command then exits 3 saying no host approval was recorded, run it yourself from a terminal. |
| `no operator authenticator is enrolled` from `setup --state disabled`, `plane disable` or `recover` (exit 3; passkey mode only) | `guardrail operator enroll` from a real terminal, then re-run the command it named | No passkey is enrolled, so no approval ceremony can start, and loosening actions wait for one (ADR-0030). The daemon is fine; nothing was changed. `approval daemon unavailable` now means exactly that: nothing answered on the socket and none could be spawned (#326). |
| doctor: `operator enrollment: UNKNOWN (cannot read the credential store at …)` | Fix or move aside the named `operator-auth` directory, or `guardrail operator recover-reset` from a trusted terminal | The store exists but fails guardrail's owner-only check or doesn't decode, for example after a restore or a copy made by another account. `operator enroll` refuses over it rather than guess (#593). Counts as a doctor problem. |
| doctor: `operator approvals: disabled (no authenticator enrolled; planes armed by bootstrap; …)` (passkey mode) | `guardrail operator enroll` | The first install armed the planes without an approval (ADR-0030). They are guarding; nothing can loosen them until a passkey exists. Enrolling puts every later change behind it. |
| doctor: `N unmarked guardrail-like hook entries in settings.json` | `guardrail plane enable claude` | Legacy pre-marker hook groups; enable absorbs them (ADR-0004). Passkey. |
| doctor: `guardrail hook registered but CANNOT SPAWN` | `guardrail plane enable claude`, or `guardrail gen-config claude --merge <settings.json> --binary <path>` where plane commands are gated | The registered command cannot be spawned by a shell — an unquoted path with a backslash or a space. Nothing is being enforced while it reads this. Re-merging rewrites it (#149). |
| doctor: `guardrail hook registered — evidence window reset by the recent update …` | `guardrail selftest --evidence claude` after a Claude session | Not a fault: real records exist, all older than this binary (#520). Clears itself once a real session is mediated by the new binary. |
| doctor: `guardrail hook registered but NEVER OBSERVED FIRING` | `guardrail selftest --evidence claude` | Registered, spawnable, no real-session record at all. Expected on a fresh enrolment; clears itself once a real session is mediated. Exit 1 until two pre-hook records from one real session exist. If it persists across real sessions, the hook is not being invoked — treat as #149's shape. |
| doctor: `present, hook NOT registered` / `no settings.json` | `guardrail plane enable <plane>` (or `--all`) | Re-registers the integration (hooks, and for opencode the plugin). Passkey. |
| Claude session posture: `Claude plane lifecycle: … drift` or `permissions floor drifted` | `guardrail plane enable claude` | A release changed what guardrail writes; enable re-merges idempotently. It also removes the retired permissions floor an earlier release wrote (ADR-0028, #357), keeping your own entries |
| Claude session posture: `claude coverage: Claude Code X — N uncontracted tool(s)` | `guardrail doctor --coverage claude` | Claude Code shipped a tool the contract doesn't know; it is **allow-by-default** until contracted. Open an issue with the doctor output. |
| An MCP server was added or upgraded (serena, graft, …) | `guardrail doctor --coverage <claude\|codex\|opencode> --mcp` | Starts each configured stdio server, lists its tools, and diffs them against the MCP registry under that plane's naming. `uncontracted` tools need a registry entry; a server listed as `unknown` (did not start or answer within 45 s, or is remote) is **not** covered. Only server and tool names are printed. Antigravity's `--coverage antigravity` already covers MCP. |
| Codex hook wiring or trust is uncertain | `guardrail doctor --codex-hooks` | Review registration, Codex-reported trust/hash, direct handler exit/stderr, runtime dispatch evidence, and observed capabilities separately. A green direct probe is not a coverage claim. |
| Claude session posture: `guardrail vX … run guardrail selftest` | `guardrail selftest` | Nothing has proven this release's enforcement on this machine yet. A pass records it and the line goes away. |
| settings.json / opencode.json / hooks.json corrupt or hand-edited | `guardrail recover claude-settings` (or `opencode-config`, `antigravity-hooks`) | Repairs Guardrail-protected machinery from a known-good shape. Passkey. Never edit these files by hand — sessions are P5-denied from doing so and so should you be. |
| An agent is waiting on an approval you never saw | `guardrail approvals list` then `guardrail approvals approve <id>` | Lists `<id>  <action>  expires <time>`; `approve` re-opens the ceremony and waits. `no approval daemon is running` means nothing is pending. |
| Approval page never opened / daemon looks stuck | `guardrail approvals list`; if that hangs, kill the `guardrail approvals daemon` process — the next request re-spawns it from the installed binary | The daemon is spawned on demand and shut down by every `update`, so it can never outlive a release |
| `registered handlers differ from this binary` (printed by `setup`), or a plane still runs the previous release's hook command after `guardrail update` | `guardrail setup` | `update` swaps the binary but leaves registered handlers alone; `setup` compares each plane's registered hooks (and the codex wrapper / opencode plugin entry) with what this binary generates and re-merges any that differ, under one approval (#317). Seeing the line during `setup` means it is fixing it. |
| `guardrail update` says `release assets may still be publishing; retry in a minute` | wait 60 s, run it again | You raced the release uploader; nothing was changed |
| `update` (or the installer) exited 1 with `<step> failed on the new binary` / `already replaced` | `guardrail selftest` (read the FAILED lines) then `guardrail rollback` (the message names it; `guardrail update <previous version>` also works) | The new release drifted on a probe or doctor failed. The binary is already replaced, and the exit is 1 so automation does not read it as success (#94). `rollback` restores the exact binary the update replaced, after checking it against its record; run it from your own terminal (sessions cannot, #512) |
| Agent needs a website | agent runs `guardrail egress grant --scope repo --host a.example.com,b.example.com` inside its session → you approve its host's prompt (or the passkey page in passkey mode); or you run the same at a terminal (immediate) | Grants live in `~/.config/guardrail/waivers.toml` plus the repo's `guardrail.toml`; **both** must agree. A grant authorizes `guardrail fetch <url>`, the sanctioned path; it does **not** let `curl`/`wget` through (they reach only `egress_allowlist`). With web-research enforcement on, native WebFetch is denied. The deny, the `guardrail fetch` ask and the session posture all name the exact grant (#125) |
| Agent says it "can't fetch" a page but never tried | tell it to run `guardrail fetch <url>` | Agents denied egress once tended to stop attempting fetches (#125). The session posture now says the path exists; the fetch prints the exact grant to run when the host is unapproved. |
| Too many asks tonight | `guardrail night on --for 8h` (terminal only) | Relaxes routine asks to allow until then. External-tier asks (publishing, schedulers, unknown MCP) are never relaxed (ADR-0018). `guardrail night off` restores. `guardrail night status` works from anywhere and exits 1 when inactive — a state, not a failure. |
| Windows: an opencode agent reports *every* tool call failing `guardrail: could not run (spawnSync … ETIMEDOUT); failing closed` | see **Windows: engine unreachable** below | Per-spawn latency (Defender scan + NTFS `CreateProcess`, #132) exceeded the opencode plugin's budget; the plugin denies everything when the engine cannot run — fail-closed by design. Other planes have larger hook budgets and keep working; opencode failing alone is expected, not evidence of a binary bug. |

## Agent access to guardrail commands

Which guardrail commands a mediated
session may run, per plane, and how each plane renders an operator ask:
[command-access.md](command-access.md).

## Why was this blocked: `guardrail explain`

One command from an audit record to the fix (#106). Agents can run it too; it
only reads the audit log and changes nothing.

```
guardrail explain                     # newest ask/deny for the repository you are in
guardrail explain --last 5            # the five newest, newest first
guardrail explain <session-id>        # newest ask/deny in that session, any repository
guardrail explain <request-id>        # a brokered operator action, with its latest status
guardrail explain 2026-09-26T10:01:00Z  # the record written at that instant
guardrail explain --all               # search every repository, not only this one
guardrail explain --path <file>       # read another audit log
```

For each record it prints what was evaluated (plane, session, repository, tool,
command, paths), the verdict and `rule_id`, the reason, and:

- **home**: where the deciding rule lives (#410). A built-in base-policy rule
  names the source file that mints it. An overlay rule names the
  `guardrail.toml` it comes from, read as the file is now. An operator rule
  (grant, night mode, operator action) and an adapter-tier rule (decided from
  the tool's contract capability or the host's posture, with no policy file
  behind it) say so. A rule this binary does not know says that too. An
  escalated verdict adds an **origin** line with the home of the rule it
  escalated;
- **next step**: the continuation the agent was given for that verdict, taken
  from the same code that wrote the guidance, so it cannot drift from it;
- **operator**: what only you can do. For a grantable ask, the exact
  `guardrail approvals grant --repo … --rule … --command …` line for that
  command (not printed when the log redacted part of the command, since a grant
  built from it could never match); for an ask that can never be granted, which
  rule says so; for a brokered action, `guardrail approvals approve <id>` and
  the request's latest status in the log;
- **guidance**: the full text re-rendered from the record. The record keeps the
  normalized command, not the raw tool arguments, so the quoted action is a
  summary rather than the exact bytes the plane sent.

A deny with **no rule ID** was not decided by a rule: the hook failed closed
before it could evaluate the call (an unparseable payload, or a policy or
Overlay that would not load). Those denies are recorded with `audit_kind:
hook-fail-closed` and the reason the agent saw; `explain` says so and points at
`guardrail doctor`, which names the broken file.

The default scope is the repository you run it from, plus records that name no
repository (written before records carried `repo_root`, or by a hook that
failed before it knew the repository). It exits 0 when it explained something,
1 when nothing matched (a state, not a failure), 2 on a usage error or an
unreadable log. `explain` never re-evaluates a call: the policy may have changed
since, and the record is what the agent saw.

## Native web research

From your own terminal, `guardrail web-research status` reports the setting.
`guardrail web-research off` requests approval to permit native
research; `guardrail web-research on` requests strict enforcement again. Here
**on means enforcement on**, not search enabled. Both changes need an operator
approval (the terminal `[y/N]` or a host ask by default; an enrolled
authenticator in passkey mode); a declined, failed or denied approval does not
authorize a change.
The command reports success only after the approved setting is persisted.

Off covers native search, image search, opening pages, following links, finding
text and screenshots, including Codex batches and opaque result references. It
does not enforce the outbound query data or destination hosts. Host-native
permissions still apply. It does not permit shell networking, arbitrary MCP
calls, secret-file access or destructive commands. Context7 setup is separate.

Verified fresh setup records off. An upgrade or a missing/invalid setting stays
strict; existing users opt out through the command above. Windows and WSL each
have their own machine-scoped Operator config. Doctor and session-start posture
report the setting; permitted research is audited as
`web-research-enforcement-off`, not an enforced allow.

## Grant one exact command

When a policy verdict asks but repeating the command should not require a live
approval ceremony, issue a scoped grant from an **interactive operator
terminal**:

```
guardrail approvals grant --repo <absolute-repo-path> --rule <rule-id> --command "<exact-command>"
```

Issuance is refused from agents, CI, pipes, and other non-interactive contexts.
Copy the rule ID and the complete command from the ask or audit record. Shell
quotes used to pass `--command` are not part of the value.

Before accepting `yes`, the ceremony prints the command whole and then prints
an exact quoted representation with its byte count. Read both: the first makes
the intended operation legible; the second exposes tabs, trailing whitespace,
control characters, and any other byte-level difference that literal matching
would otherwise hide. The grant matches only that repository, rule, and exact
command. A longer command, a near miss, or the same text in another repository
is not authorized.

Omitting `--uses` creates a one-use grant. Omit `--for` for the 30-minute
default; longer requested lifetimes are clamped to 24 hours. Spending is
rechecked and committed under the machine-wide operator lock, so two concurrent
calls cannot consume the same final use and a non-matching call consumes
nothing.

Inspect active and spent grants with `guardrail approvals list --grants`.
Revoke an unspent grant by repeating its exact scope:

```
guardrail approvals revoke --repo <absolute-repo-path> --rule <rule-id> --command "<exact-command>"
```

The audit log records issuance and revocation as operator actions, including
the repository, rule, exact command, decision, and reason. A successful spend
is recorded with rule `ask-allowed-by-operator-grant` and preserves the original
ask rule as `origin_rule_id`. See [ADR-0027](adr/0027-operator-issued-grants-authorize-one-exact-command.md)
for the trust and transaction design.

## Approve a Codex exact-action request

When Codex reports a pending exact-action request, run this in your own
interactive terminal:

```
guardrail approvals grant --record <request-id>
```

Review the entire command or patch, affected paths, repository, working
directory, session and quoted text. Prompt mode requires `yes`; passkey mode
uses the enrolled authenticator and does not bypass enrollment. Chat approval
cannot authorize the retry. The approval covers one identical action before
the request's original 15-minute expiry. Changed text, paths, rule, working
directory or session requires a separate approval. An identical pending
request does not extend its lifetime.

To cancel a pending or approved request:

```
guardrail approvals revoke --record <request-id>
```

Requests are stored privately under the operator configuration's `actions`
directory; full bodies are absent from audit and broker state. Denies and
fail-closed backstops such as `tokenize-failed` cannot be granted. A post-tool
finding reports an action that already ran; it is not a pending approval.

## Approvals from a phone or remote session

The desktop hand-off line (`! <command>`) does not execute from a mobile or
remote-control session: the line arrives as chat and nothing runs (#616). What
works from the phone:

- **Host permission prompts** appear in the mobile app and can be answered
  there, like any other permission.
- **Engine-gated asks** can be approved conversationally in chat: say what
  you approve and the agent retries the exact call.
- **Passkey approvals**: when an approval URL is printed, open it on the
  phone; the ceremony needs the operator passkey on that device.
- **Merges**: the GitHub mobile UI, or let the agent run
  `guardrail delivery finish --pr <N> --head <sha>` once repository delivery
  is enabled.

Typing a command into chat yourself never runs it. ADR-0035 keeps the
operator's own terminal as the honest channel for terminal-only ceremonies;
if none of the paths above applies, wait for a desktop session.

## Passing credentials to commands

Everything a command prints enters the session and is sent to the model
provider. A command whose output is a credential (`gh auth token`, `az account
get-access-token`, `aws ecr get-login-password`, `kubectl config view --raw`,
`git credential fill`, `op read`, `vault kv get`, …), a dump of the
environment (`env`, `printenv`, PowerShell `gci env:`), or an echo of a
secret-looking variable (`echo $GITHUB_TOKEN`, a name containing TOKEN,
SECRET, PASSWORD, PASSWD, API_KEY, PRIVATE_KEY or CREDENTIAL) asks under
`P4.credential-print` unless its output never reaches the session (#436).

These shapes stay allowed, because the value goes straight to the command that
needs it:

```
GH_TOKEN=$(gh auth token) gh pr list                     # env prefix of one command
tool --token "$(gh auth token)"                          # argument
docker login ghcr.io -u me --password-stdin <<< "$(gh auth token)"
gh auth token | docker login ghcr.io -u me --password-stdin
aws ecr get-login-password | docker login --username AWS --password-stdin <registry>
```

(An argument of a program whose operands the Engine does not know already asks
`P3.unresolved`, as any substituted argument does.)

These ask, because the value lands where the session can read it:

- the bare command, or a pipe into anything but a credential consumer
  (`--password-stdin`, `--with-token`, `gh secret set`); `tr`, `cut`, `jq` and
  `base64` pass the value on to wherever their own output goes;
- `echo $(gh auth token)`, `cat <<< "$(…)"`, or a substitution handed to any
  other printing command (`printf`, `printenv`, `env`, `cat`, `tee`,
  `Write-Output`, `Write-Host`, …) or to interpreter code (`bash -c`,
  `python -c`);
- a redirect to a file, or `>&2`;
- a plain assignment (`TOKEN=$(gh auth token)`, `export …`): a later command
  can print the variable under a name nobody reads as secret. Use the prefix
  form on the one command that needs it;
- anything under `set -x` or `bash -x`, which prints every expanded command.

What this does not do: Guardrail judges the shape of the command, not what the
consuming program does with the value. A program that prints its own
arguments, its environment, or an error message that repeats a bad argument
still leaks the value into the session. This
narrows the channel; it does not close it. The durable fix is a credential the
session never needs to see (#277).

## Things that look like bugs and aren't

For the full table of authorised write seams, self-config protections, the two-file Overlay $\leftrightarrow$ Operator config handshake, and the three secret tiers, see [ADR-0037](./adr/0037-write-seams.md).

- **Writing `.env` inside the repo is denied.** `.env` is a File secret (definitive tier). Use `.env.example`, or an operator-authorised `secret_allow` ([ADR-0037](./adr/0037-write-seams.md)).
- **`rm -rf /tmp/x` is allowed.** Strict descendants of a system temp root (along with linked git worktrees of the same repository, the active Antigravity session `brain/<conversationId>` directory, and Claude's `~/.claude/projects/<slug>/memory/**`) are authorised write seams ([ADR-0037](./adr/0037-write-seams.md)). `rm -rf /tmp` itself is not.
- **Native `WebFetch` is denied while web-research enforcement is on** with "use guardrail fetch": the native tool can't verify redirect targets; `guardrail fetch` can.
- **`curl` to a host you granted is still denied.** `guardrail egress grant` authorizes web hosts for `guardrail fetch`; shell network tools reach only the Overlay `egress_allowlist` the Operator config authorizes. The deny says so and names `guardrail fetch`.
- **A `printf` or heredoc containing a secret path is denied** (`P4.secret-in-text`) even though nothing was accessed: interpreter input is opaque to the static boundary (ADR-0012). The guidance says to use the editor tool; that is the fix.
- **A python heredoc that merely mentions the night control is denied** for the same reason.
- **Re-running an approved `egress grant` says "already authorized"** instead of asking again — the broker applied it the moment you approved; the command is never re-run.
- **`guardrail night on` / `off` from inside a session is denied**, and so is anything longer than the exact three-word `guardrail night status` (which is read-only and allowed). Changing the posture is an operator action: run on/off from a terminal.
- **`git push --delete <branch>` asks** (`P2.git-push-delete`) even for an unprotected branch, and any command that reaches a policy position through a shell variable asks (`P3.unresolved`). Both are the intended fail-closed shape: spell the names out and answer the prompt.
- **`git push origin v1.2.3` asks even when `v1.2.3` is a branch, not a tag** (`P2.git-push-protected`). A named-tag push and a branch push are the same command shape — which one it is depends on what exists in the repository, and the Engine is a pure function of the call it is handed: it never execs and never reads the repo, so it classifies a version-shaped destination on the name alone and errs toward asking (#218). A destination spelled `refs/tags/…` is unambiguous and asks exactly. Push the branch under a name that does not read as a release, or answer the prompt.
- **`plane enable` says `already enabled`** and a session still reports floor drift → the installed release predates the floor-drift check (#33); `guardrail update` to current.

## Tag lifecycle: creation asks, deletion is blocked, recovery is manual

The gate sits on creation and the ruleset sits on deletion, so a tag is easy to
publish by accident and hard to retract. Know the whole shape before you tag.

| step | what happens |
|---|---|
| `git push origin v1.2.3` | **asks** (`P2.git-push-protected`, #218) — a release pointer goes public, so it is an operator decision |
| `git push --tags` | asks (existing) |
| `git push origin :refs/tags/v1.2.3` | asks locally, then **the remote refuses**: `GH013: Cannot delete this tag` |
| retracting a pushed tag | **admin UI only** — GitHub → Releases/Tags → delete |

The failure this prevents: a tag pushed unasked starts a release build from that
exact tree. If the tree is missing a fix that merged afterwards, CI produces and
publishes assets built without it, and the tag cannot be deleted from the
command line to stop the cascade. That happened on 2026-09-21 with
`v0.21.8-dev` (#218) — the pointer was stranded until an admin deleted it by
hand, and an asset built from it had already been deployed.

So: **check what the tag will point at before answering the prompt.** `git log
--oneline -1 <ref>` and confirm the fixes you expect are ancestors
(`git merge-base --is-ancestor <fix-sha> <ref>`). Answering the ask is cheap;
un-publishing is not.

## Windows: engine unreachable (opencode `spawnSync ETIMEDOUT`)

The opencode plugin spawns the engine once per tool call and denies the call
when the spawn misses its budget — even with retries (v0.21.6+, #133), a
sustained latency storm (Defender real-time scan, NTFS, a CPU-bound process on
the machine) can lock an entire session out. Recovery, in order:

```powershell
# 1. Version floor: the retry fix must be in the installed binary
guardrail version                                  # need >= v0.21.6-dev

# 2. The deployed plugin must carry the retry. Plugins load from the FIRST
#    guardrail entry in opencode.json's "plugin" array — a stale copy there
#    silently wins over a fresh deploy (#145)
Select-String -Path "$env:USERPROFILE\.local\share\guardrail\guardrail.js" -Pattern SPAWN_RETRIES

# 3. Redeploy the plugin from the installed binary…
guardrail gen-config opencode -merge "$env:USERPROFILE\.config\opencode\opencode.json" -plugin-dir "$env:USERPROFILE\.local\share\guardrail"

# 4. …then RESTART the opencode host process. Plugins are cached at host
#    startup; restarting the session is not enough.

# 5. Still failing? It is load: find the CPU burner, check Defender state
Get-Process | Sort-Object CPU -Descending | Select-Object -First 5 Id,Name,CPU,StartTime
```

To see where the time went, read the plugin's two logs under
`%LOCALAPPDATA%\guardrail` (`~/.local/state/guardrail` elsewhere):
`plugin-failures.log` has one line per degraded allow, floor fallback or
fail-closed call; `plugin-timing.jsonl` (#427) has one JSON line per call that
took over a second or had a failed attempt, including retried calls that
stalled once and then succeeded. Each line gives the daemon dial time, every
spawn attempt's duration, timeout, pid and outcome, the envelope size and the
runtime (Bun or Node). An `ETIMEDOUT` whose `ms` is close to `timeout_ms`
is a real hang. An `ETIMEDOUT` after a few milliseconds, with a `pid` and no
output, is the Bun runtime misreporting (#452): the plugin retries it once at
once, so it shows as two attempts, the second answering. Any other error with
`ms` far below `timeout_ms` means the spawn itself failed.

```powershell
Get-Content "$env:LOCALAPPDATA\guardrail\plugin-timing.jsonl" -Tail 20
```

For every plane, each hook record in `audit.jsonl` carries `hook_ms` (how
long guardrail took to handle the call) and, for a spawned hook,
`startup_ms` (process start to handling) (#456); calls the engine daemon
served are tagged `transport: named-pipe-daemon`. `guardrail doctor` prints
per-plane p50/p95 over the latest 200 real calls. The host's cost of
creating the process is not visible from inside it; for OpenCode it is the
gap between an attempt's `ms` in `plugin-timing.jsonl` and the record's
`hook_ms`.

The agent itself cannot run any of this — the tool that would diagnose the
guard is gated by the guard. Recovery is an operator-terminal action by
necessity. Two standing cautions: the Defender exclusion for the binary path
must stay scoped to the exact file (#146), and never hand-copy a new binary
over the installed one except as a deliberate terminal recovery (#146) —
`guardrail update` is the only sanctioned replacement. A session may run it
to move to a **newer** release; a downgrade below the running release, and
`guardrail rollback`, are denied from sessions (`P5.self-config`, #512) and
run from your own terminal.

## Install, update, disable, uninstall

Installation is this repo's job ([ADR-0029](./adr/0029-installer-lives-in-this-repo.md)).
Every release ships `install.sh` (Linux, macOS, WSL; POSIX `sh`) and
`install.ps1` (Windows PowerShell 5.1 and PowerShell 7) next to the binaries,
listed in the same `SHA256SUMS`. Fetch the script for the exact tag, verify it
against that tag's `SHA256SUMS` (the README shows both OS blocks), then run the
file. Do not pipe the scripts into a shell or evaluate them in-process: they
`exit` on failure and hand the terminal to `guardrail setup` for its approval
(the `[y/N]`, or a passkey in passkey mode).

| Task | Unix | Windows |
|---|---|---|
| Install, or move to another tag | `sh install.sh --version <tag>` | `powershell -ExecutionPolicy Bypass -File .\install.ps1 -Version <tag>` |
| Disable every plane, keep the binary | `sh install.sh --version <tag> --state disabled` | `… install.ps1 -Version <tag> -State disabled` |
| Uninstall | `sh install.sh --uninstall` | `… install.ps1 -Uninstall` |
| Uninstall and delete all state | `sh install.sh --uninstall --purge` | `… install.ps1 -Uninstall -Purge` |

`--version` takes an exact tag (`latest` is refused, exit 2) and is required
except with `--uninstall`. `--dest <dir>` (`-Dest`) changes the install
directory from `~/.local/bin` (`%USERPROFILE%\.local\bin`); pass the same
`--dest` to `--uninstall`. `--base-url <url-or-dir>` (`-BaseUrl`) points at
another release base — an `http(s)` URL, a `file://` URL or a directory laid
out as `<base>/<tag>/<asset>`; CI uses it to install from `dist/`.
`--help` (`-Help`) prints the usage.

**Install / update.** With no guardrail at the destination, or one older than
`v0.19.2-dev`, the script downloads the asset and `SHA256SUMS`, verifies, and
places the binary; a mismatch exits 1 and leaves the destination untouched.
With one at or above that floor already installed it runs
`guardrail update <tag>` — the sanctioned replacement path (#146) — and it
replaces nothing if the installed binary already reports the tag. Either way it
then checks that `guardrail version` prints `guardrail <tag>`. On Windows a
fresh placement also runs `Unblock-File` and appends the destination to the
user PATH if absent, and every run ensures a Defender exclusion for the exact
`guardrail.exe` path (never a directory or a process name, #146); without an
elevated shell it prints the `Add-MpPreference` command and carries on. Last, it runs `guardrail setup`
and exits with setup's code.

**`guardrail setup`** is the reconcile step, and the thing to run after any
binary swap. For every detected plane (or `--planes claude,codex`), it
re-registers the plane when any of these hold: not registered; permissions
floor drifted; **registered handlers differ from what this binary generates**
(the hook command, the codex wrapper or the opencode plugin entry, #317).
Planes already consistent print `already enabled` and do not prompt; the rest
go through one approval together. It then runs `doctor --coverage
antigravity` when `agy` is on PATH and `selftest`. A selftest failure is always
a non-zero exit. Coverage failure is also non-zero when no plane changed; if
this run already enabled one or more planes, setup instead warns that coverage
is unknown, continues through selftest and the status block, and returns
success when selftest passes. That keeps an installer from reporting an armed
plane as uninstalled while preserving the coverage diagnostic and the
`guardrail doctor --coverage antigravity` hint. It ends with one status line
per plane. In prompt mode (the default, ADR-0033) `setup` asks
`Approve register guardrail on planes: …? [y/N]` before it changes anything,
and a host-approval ticket stands in for the terminal when an agent's host
asked you; the paragraph below describes the rules that hold in both modes,
with enrollment mattering only in passkey mode and for the bootstrap. `setup`
refuses to run
without an interactive terminal once an operator is enrolled (exit **3**,
operator action pending: it is the operator's to fix, and the message says
how) and refuses to register the
updater's staging or `.old` path (exit 2, usage); it prints the path it registers
before asking. When no operator authenticator is enrolled, an enable is a
**bootstrap** (ADR-0030): the planes are registered without an approval and
without a terminal, the audit log gets an `operator-action` record with
`transport: bootstrap`, the gates run, and the run ends with the one-time
instruction to `guardrail operator enroll`. The approval-less path can only
tighten: `setup --state disabled`, `plane disable` and `recover` on an
unenrolled machine stop before submitting anything, print `run 'guardrail
operator enroll' … then '<command>'`, and exit **3** (#326), distinct from 1
(a genuine failure) and 2 (usage, unsupported platform); installers pass the
code through. Exit **3** means *operator action pending* and nothing else
(#364): no authenticator enrolled, no interactive terminal for an enrolled
operator (`setup`, `plane enable|disable`), the approval daemon not running, or
the request denied or expired. `operator`, `recover`, `web-research` and
`approvals` are interactive by nature and still exit 2 without a terminal. The
binary is installed, what is registered keeps
enforcing, and only a passkey approval from an interactive terminal finishes
the change, so an unattended caller (a dotfiles apply, CI) can treat 3 as a
warning and 1 as a failure without matching log text. The message on stderr
says which cause and how to finish (`guardrail setup` from a real terminal,
approve, re-run whatever provisioned the machine). A run with nothing to
register or remove exits 0 in every state.

`guardrail next` prints the steps still owed to the operator, in order, and
nothing when nothing applies. It is read-only advice: it never changes a file
and never asks for an approval. `update` ends with it (run by the freshly
installed binary), `setup` ends with it for planes it was not asked about, and
the installers run it when setup is skipped (`--no-setup` / `-NoSetup`).
It never downloads, never touches PATH or Defender.

`guardrail update <tag>` on its own replaces the binary and runs `doctor` and
`selftest` on it, but leaves the registered handlers as they were. Follow it
with `guardrail setup`, or re-run the installer, which does both.

Exit codes of `update`: 0 healthy; 2 usage; 1 failure, of two kinds the
message tells apart. Before the swap (download, checksum, version check,
staging) the installed binary is untouched. After it, if `doctor` or `selftest`
on the new binary exits non-zero (3, operator action pending, is not a failure),
the binary **is already replaced**: `update` runs both, prints which failed,
skips the next-steps block, exits 1 and names the rollback,
`guardrail rollback` (or `guardrail update <previous version>`, the version of
the binary that ran the update; a dev build says `<previous version>` because
it has none). The installers pass that through: exit 1 with the same rollback
line. An updater older than #94 exits 0 on these failures, and the installer
cannot tell.

**`guardrail rollback`** restores the binary the last update replaced (#94).
`update` keeps it next to the installed one (`guardrail.previous`, or
`guardrail.previous.exe`) with a record (path, release, SHA-256) in
`~/.local/state/guardrail/previous.json`. Rollback first checks the kept file
against that record and that it runs as the recorded release; if either check
fails it exits 1 and changes nothing. It then swaps: the binary rolled back
from becomes the kept one, so `rollback` again returns to it. Finally it shuts
the approval daemon down and runs `doctor` and `selftest` like `update` (exit 1
if they fail, with the binary already restored). Exit 2 when nothing is kept
(the update ran on an updater older than #94). It is operator-only: sessions
are denied (#512). The kept binary and its record are protected like the binary
itself.

**`--no-setup` (`-NoSetup`)** stops once the binary is in place and verified,
exit 0. Use it in CI, or when you want to run `setup` yourself; a first
install no longer needs it (the bootstrap above arms the machine). With `--uninstall` it skips the disable step and only
removes files.

**Disable.** `--state disabled` never downloads. If a binary exists it runs
`guardrail setup --state disabled` — `plane disable` for every registered
plane under one approval, then a per-plane status line; with no binary it prints
`nothing to do` and exits 0. Running `guardrail setup --state disabled`
directly does the same.

**Uninstall.** `--uninstall` runs `guardrail setup --state disabled` first; if
that fails the uninstall stops with `planes are still registered` and removes
nothing. (A binary older than `setup` is disabled with `guardrail plane
disable --all` instead.) Then it removes the binary, the updater's
`guardrail.old` / `.guardrail-update` leftovers, and the opencode plugin file
(`${XDG_DATA_HOME:-~/.local/share}/guardrail/guardrail.js`,
`%USERPROFILE%\.local\share\guardrail\guardrail.js`). On Windows it also
removes the Defender exclusion (this needs an elevated shell; otherwise
it prints the `Remove-MpPreference` command) and the user PATH entry, but only
when `<dest>` is empty afterwards: `%USERPROFILE%\.local\bin` is shared with
other tools, so otherwise it prints `leaving <dest> on PATH (other tools live
there)`. A `guardrail.exe` still held by a running process is renamed to
`guardrail.exe.old` for you to delete after a reboot. Plane settings files
are only changed by `plane disable`, which restores them from the ownership
manifest. State and operator config are kept. A relative `XDG_*_HOME` is
ignored (the XDG spec calls it invalid); the `~/...` default is used.

**Purge.** `--uninstall --purge` also deletes every directory guardrail keeps
state, config or data in:

| Unix | Windows |
|---|---|
| `${XDG_STATE_HOME:-~/.local/state}/guardrail` | `%LOCALAPPDATA%\guardrail` |
| `${XDG_CONFIG_HOME:-~/.config}/guardrail` | `%APPDATA%\guardrail` |
| `${XDG_DATA_HOME:-~/.local/share}/guardrail` | `%USERPROFILE%\.local\state\guardrail` |
| | `%USERPROFILE%\.local\share\guardrail` |

That includes the audit log, the operator's enrolled passkeys, grants and
waivers — a later install starts from `guardrail operator enroll`. Windows
has three state roots, not one (see the note under
[Where things live](#where-things-live)); purge knows all of them.

## What a healthy update looks like

Captured from v0.20.26 → v0.20.27. Probe counts grow with each release; the two
tells are the doctor header naming the **new** release and the final line.

```
guardrail updated to v0.20.27-dev at /home/you/.local/bin/guardrail
guardrail v0.20.27-dev            ← doctor header names the NEW release
cwd: …
overlay: none
policy warnings: none
waivers: none
audit log: /home/you/.local/state/guardrail/audit.jsonl
approval mode: prompt (operator actions are approved in the agent host's ask or at a terminal [y/N]; …)
claude settings: guardrail hook registered
  ↑ on a plane not yet exercised this reads "… but NEVER OBSERVED FIRING"; that is
    expected, not a fault — see "Healthy looks like" above
opencode settings: guardrail integration registered
codex settings: guardrail hooks registered; …
antigravity settings: guardrail integration registered
claude: probes pass (7)
opencode: probes pass (3)
antigravity: probes pass (7)
codex: probes pass (2)
note: codex probes invoke the hook directly; live runtime mediation is evidenced by audit records
selftest: all probes passed
```

Current doctor ends its own block with a `verdict:` line (`verdict: healthy` on a
converged machine); the capture above predates it.

Afterwards `~/.local/state/guardrail/selftest-passed` reads the new version and the
next Claude session's posture has **no** selftest line and **no** coverage line.
If the doctor header still names the *old* release, the updater predates #58:
run `guardrail selftest` once by hand.

The update is run by the binary that was installed before it, so a change to
the updater only shows on the update *after* the release that contains it
(N+2, not N+1). Cutting a release, and that rule, are in
[release-checklist.md](release-checklist.md).

`update` does not touch the registered handlers. Run `guardrail setup` after it
(or re-run the installer, which does both): it re-registers any plane whose
handlers differ from what the new binary generates and prints `already
enabled` for the rest.

**What an update leaves beside the binary, and for how long (#522).**
Guardrail-owned names next to `guardrail`(`.exe`) and their retention:

| Name | What it is | Lifetime |
|---|---|---|
| `guardrail.old` | The update's rename-aside on Windows (the running image cannot be overwritten, only renamed); also the installer's locked-file aside. Its date is the **replaced** binary's, not the update's. | One slot. Unremovable while the updating process runs, so it outlives exactly one update; the next `guardrail update` removes it before making its own. |
| `guardrail.previous` | The #94 rollback keep: the binary the last update replaced, with a record under the state root. | One slot, replaced each update; consumed by `guardrail rollback`; removed by `--uninstall`. |
| `.guardrail-update` / `.guardrail.install.exe` | Update / install staging. | Removed on completion or by the next cycle. |
| `guardrail.old-<timestamp>` | Pre-#94 set-aside scheme, no longer produced. | Swept by the first `guardrail update` at or past this release, and by `--uninstall`. |
| `guardrail.before-*` and friends | Hand-made backups. Not guardrail's. | Never touched by guardrail or the installers. |

So a `guardrail.old` dated the day *before* yesterday's update is that update's
own aside (the mtime travels with the replaced file), and it disappears on the
next update — nothing is accumulating. `--uninstall` now removes every
guardrail-owned row above plus the opencode plugin directory under the data
root (`~/.local/share/guardrail`, whole tree: the V1 `guardrail.js` and the
OpenCode 2 `guardrail/index.js` artifact both live there).

## Where things live

| What | Path |
|---|---|
| Binary | `~/.local/bin/guardrail` |
| Installers | `install.sh`, `install.ps1` — release assets next to the binaries, listed in the release's `SHA256SUMS`; source at the repo root |
| Operator config (grants, waivers, night marker) | `~/.config/guardrail/` — `waivers.toml`, `night.toml` |
| Audit log (rotates at 20 MB, 3 segments) | `~/.local/state/guardrail/audit.jsonl` |
| Session state, coverage cache, selftest marker, last-passed session checks | `~/.local/state/guardrail/{sessions,coverage,selftest-passed,session-checks}` |
| Approval broker socket (on demand; dies with `update`) | `~/.local/state/guardrail/approval/broker.sock` |
| Repo overlay | `<repo>/guardrail.toml` — requests; only operator config grants |
| Claude hooks + floor | `~/.claude/settings.json` (owned groups carry `id: guardrail-*`) |
| Ownership manifests (what guardrail wrote into each plane's settings, and the prior values; `plane disable` restores from them) | `~/.local/state/guardrail/manifests/<plane>.json` |
| opencode plugin | `~/.local/share/guardrail/guardrail.js` |

Everything under `~/.config/guardrail` and `~/.local/state/guardrail` is
operator-owned: sessions are denied from editing or deleting it, on purpose.
The selftest marker is a trust record, not a cache — if you want a session to
re-prove a release, delete the marker yourself.

On Windows the paths differ: binary `~\.local\bin\guardrail.exe`, audit log
`%LOCALAPPDATA%\guardrail\audit.jsonl`, operator config `%APPDATA%\guardrail\`,
and the approval broker's private endpoint is a per-user named pipe rather
than a socket (ADR-0021 step a). Windows state is split across three roots, not
one: `%LOCALAPPDATA%\guardrail` (audit, sessions, manifests),
`%APPDATA%\guardrail` (operator config) and
`%USERPROFILE%\.local\state\guardrail` (enrolled operator credentials), plus
the plugin under `%USERPROFILE%\.local\share\guardrail`. `install.ps1
-Uninstall -Purge` removes all four ([Install, update, disable,
uninstall](#install-update-disable-uninstall)).

## Escalate when

- `selftest` fails on a release that passed yesterday and nothing local changed → open an issue with the FAILED lines and `guardrail version`.
- `doctor --coverage claude` lists a tool → open an issue with the output; until it is contracted that tool runs unguarded.
- `audit` shows `unclassified tools observed` you don't recognise → same.
- A deny has no usable next step in its guidance → that is a bug by definition (every deny must redirect, not stop); file it with the exact text.


## Opt-in hook phase timing (#530)

Timing is off by default. Set `GUARDRAIL_TIMING=1` **before starting the host**;
an existing OpenCode process or engine daemon does not inherit a later shell
environment change. Start any daemon used by the experiment with the same
opt-in. To opt out, unset the variable and restart those processes. No tracing
flag enables a host, changes a verdict or chooses the spawn/server architecture.

On Linux/WSL, for example, start a host with `GUARDRAIL_TIMING=1 opencode`, then
read results with `GUARDRAIL_TIMING=1 guardrail doctor`. In PowerShell set
`$env:GUARDRAIL_TIMING='1'` before launching the host and running doctor; remove
it afterwards with `Remove-Item Env:GUARDRAIL_TIMING`. Values other than the exact
string `1` leave timing disabled.

`hook-timing.jsonl` and `plugin-timing.jsonl` live beside the default audit log:
`$XDG_STATE_HOME/guardrail` (normally `~/.local/state/guardrail`) on Linux, and
`%LOCALAPPDATA%/guardrail` on Windows. Each retains only its latest 200 records,
each at most 4 KiB. Native writers drop a sample on lock contention; telemetry
failures never affect policy. Plugin writes are best-effort snapshots; concurrent
plugin processes can lose samples. These are bounded diagnostic windows, not
an exhaustive performance audit. Timing persistence itself is not timed and its
cost is included in an external process/wrapper measurement.

Records contain identities, versions, runtimes, transport and durations, never
command text, arguments or environment contents. The opted-in audit record's
`call_id` and `guardrail_version` correlate native records. Doctor joins a plugin
record only with an exact, unambiguous session/call match in retained native
samples; an absent or ambiguous match leaves engine version unmeasured. Native
tool IDs are preserved for Claude and Codex; OpenCode already supplies call IDs.
Host versions are unmeasured when the plugin/hook provides no trustworthy field.

Doctor keeps host/version/transport/runtime/sample-kind groups separate. Zero is
a measured zero; JSON null and `unmeasured` mean no measurement. Spans overlap:
do not add them. In particular:

| Phase | Observed boundary |
|---|---|
| `host_dispatch_ms` | Unmeasured: a child/plugin cannot observe the host's preceding dispatch or OS process creation. |
| `wrapper_dispatch_ms` | OpenCode callback entry through envelope construction, before invoking Guardrail. Unmeasured for external shell wrappers. |
| `adapter_parse_ms` | Native adapter parse, including any shell-proof transcript work. |
| `process_startup_ms` | Go package initialisation to hook entry; excludes OS process launch and earlier runtime startup. |
| `daemon_dial_ms` | Connect attempt to connection or failure; separate from evaluate roundtrip. |
| `daemon_roundtrip_ms` | Native client evaluate/write/read; plugin's existing daemon span includes its dial. Sample kind distinguishes these spans. |
| `spawn_attempt_N_ms` | Plugin spawnSync call through return, separately for every attempt, including immediate retries. It includes child startup/handling/persistence. |
| `policy_setup_ms` | Native night-state/base/overlay/operator-policy loading and merge; incomplete error paths remain unmeasured. |
| `engine_handling_ms` | Actual Engine.Evaluate calls only, summed if repeated; excludes adapter, policy loading, session/recipe/broker handling and audit I/O. |
| `audit_write_ms` | Native decision audit write. |
| `response_encode_write_ms` | Native verdict adapter emission, including response construction and stdout writes. |
| `response_write_ms` | Actual stdout/socket Write calls; excludes JSON construction. Daemon response samples are separate from its engine samples. |
| `hook_total_ms`, `plugin_total_ms`, `sample_total_ms` | Respective observed span; excludes persisting that sample. Not full host-to-tool latency. |
| `timing_persist_ms` | Unmeasured; instrumenting its own persistence would require another write. |

The former doctor summary pooled historical audit times and could mix binaries;
the phase report replaces that pooled display. Legacy `hook_ms`/`startup_ms`
remain available on opted-in audit records, with their original boundaries.
Default calls neither emit timing traces nor those audit latency fields.

For comparisons, record the engine build version, host version if measured,
runtime, tool/envelope shape, transport, sample count and external wall clock.
Use matched benign calls on an idle machine, reject invalid tool envelopes, and
report which phases remain unmeasured. Opt-in trace writes add overhead; measure
their control cost instead of assigning an unexplained residual to policy.

## Multi-agent worktree lifecycle and teardown

Concurrent agent sessions share one clone through linked git worktrees under
`.worktrees/<name>` (both `/.worktrees/` and `/.claude/worktrees/` are ignored
in `.gitignore`). Follow this lifecycle so stale checkouts do not accumulate or
corrupt repo-walking checks (#84):

1. **Create off `origin/main` only.** Check `git status` and
   `git log --oneline -1` first; never stack a new worktree on another PR's
   branch:
   ```
   git fetch origin
   git worktree add .worktrees/<name> -b <branch> origin/main
   ```
2. **Synchronize without force-pushing.** When `main` moves ahead of an active
   worktree branch, merge `origin/main` into the worktree branch (`git merge
   origin/main`) and push normally. `git push --force` is P1-denied.
3. **Retire on merge.**
   - **Same session (ADR-0039):** a session may run
     `git worktree remove [--force] <path>` on the exact worktree it created
     within 24 hours without an operator ask.
   - **Operator bulk cleanup:** run `make worktree-clean` (POSIX,
     `scripts/worktree-clean.sh`) or
     `pwsh -NoProfile -File scripts/worktree-clean.ps1` (Windows). Use
     `--dry-run` / `-DryRun` to preview, `--force` / `-Force` for dirty
     merged/detached worktrees, and `--base <ref>` / `-Base <ref>` to override
     the default `origin/main` (or `main`) merge check. Unmerged branches are
     always kept.
   - **Squash-merged branches:** `git branch -D` stays gated for agents; batch
     merged branch deletions for the operator terminal.
4. **Windows partial-removal recovery.** On Windows, a file handle briefly held
   by an exiting process can cause `git worktree remove` to unregister the
   worktree and delete its `.git` file while leaving tracked/untracked files
   behind (`Permission denied`). When that happens:
   - Both `scripts/worktree-clean.ps1` and `scripts/worktree-clean.sh` wait
     briefly and **retry removal once**, then detect any remaining directory
     and print the exact operator command (`Remove-Item -Recurse -Force '<path>'`
     on Windows, `rm -rf '<path>'` on POSIX) while exiting 1.
   - Re-running the cleanup script with `-PruneOrphans` / `--prune-orphans` from
     an operator terminal deletes `.git`-less remnants under `.worktrees/` and
     `.claude/worktrees/`.
   - While a partial remnant sits on disk awaiting operator cleanup,
     `testenv.IsNestedCheckout` treats every directory under `.worktrees/` and
     `.claude/worktrees/` as a nested checkout even without `.git`, so
     repo-walking guards stay green.
