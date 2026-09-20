# Operations runbook — when it's weird, run this

For the operator at a terminal, not for the agents. Every command here is safe to
run at any hour; the ones that change anything ask for your passkey first.

## First 60 seconds

```
guardrail doctor        # wiring: policy, overlay, hooks per plane, warnings
guardrail selftest      # behaviour: the installed binary still denies/asks as it should
guardrail audit         # what happened: decisions, top rules, unclassified tools
```

Healthy looks like: `policy warnings: none`, every plane `registered`,
`selftest: all probes passed`, and no rule in the audit top list you don't
recognise. If all three are clean, the problem is not Guardrail.

## Symptom → command

| You see | Run | Why |
|---|---|---|
| Agent says it was blocked and you don't know why | `guardrail audit` then `grep '"decision":"deny"' ~/.local/state/guardrail/audit.jsonl \| grep -v selftest \| tail -5` | Every verdict is a JSONL record with `rule_id` and `reason`. Selftest writes deny probes to the same log on every update — filter them out or you will be reading the last selftest. |
| doctor: `N unmarked guardrail-like hook entries in settings.json` | `guardrail plane enable claude` | Legacy pre-marker hook groups; enable absorbs them (ADR-0004). Passkey. |
| doctor: `present, hook NOT registered` / `no settings.json` | `guardrail plane enable <plane>` (or `--all`) | Re-registers the integration and merges the declarative floor. Passkey. |
| Claude session posture: `Claude plane lifecycle: … drift` or `permissions floor drifted` | `guardrail plane enable claude` | A release changed the floor; enable re-merges idempotently |
| Claude session posture: `claude coverage: Claude Code X — N uncontracted tool(s)` | `guardrail doctor --coverage claude` | Claude Code shipped a tool the contract doesn't know; it is **allow-by-default** until contracted. Open an issue with the doctor output. |
| Codex hook wiring or trust is uncertain | `guardrail doctor --codex-hooks` | Review registration, Codex-reported trust/hash, direct handler exit/stderr, runtime dispatch evidence, and observed capabilities separately. A green direct probe is not a coverage claim. |
| Claude session posture: `guardrail vX … run guardrail selftest` | `guardrail selftest` | Nothing has proven this release's enforcement on this machine yet. A pass records it and the line goes away. |
| settings.json / opencode.json / hooks.json corrupt or hand-edited | `guardrail recover claude-settings` (or `opencode-config`, `antigravity-hooks`) | Repairs Guardrail-protected machinery from a known-good shape. Passkey. Never edit these files by hand — sessions are P5-denied from doing so and so should you be. |
| An agent is waiting on an approval you never saw | `guardrail approvals list` then `guardrail approvals approve <id>` | Lists `<id>  <action>  expires <time>`; `approve` re-opens the ceremony and waits. `no approval daemon is running` means nothing is pending. |
| Approval page never opened / daemon looks stuck | `guardrail approvals list`; if that hangs, kill the `guardrail approvals daemon` process — the next request re-spawns it from the installed binary | The daemon is spawned on demand and shut down by every `update`, so it can never outlive a release |
| `guardrail update` says `release assets may still be publishing; retry in a minute` | wait 60 s, run it again | You raced the release uploader; nothing was changed |
| `update` printed `selftest failed on the new binary` | `guardrail selftest` (read the FAILED lines) then `guardrail update <previous version>` | The new release drifted on a probe. Roll back with the same command; it is checksum-verified either way |
| Agent needs a website | agent runs `guardrail egress grant --scope repo --host a.example.com,b.example.com` inside its session → you approve with passkey; or you run the same at a terminal (immediate, no passkey) | Grants live in `~/.config/guardrail/waivers.toml` plus the repo's `guardrail.toml`; **both** must agree. Native WebFetch is always denied; `guardrail fetch <url>` is the sanctioned path |
| Too many asks tonight | `guardrail night on --for 8h` (terminal only) | Relaxes routine asks to allow until then. External-tier asks (publishing, schedulers, unknown MCP) are never relaxed (ADR-0018). `guardrail night off` restores. `guardrail night status` works from anywhere and exits 1 when inactive — a state, not a failure. |
| Windows: an opencode agent reports *every* tool call failing `guardrail: could not run (spawnSync … ETIMEDOUT); failing closed` | see **Windows: engine unreachable** below | Per-spawn latency (Defender scan + NTFS `CreateProcess`, #132) exceeded the opencode plugin's budget; the plugin denies everything when the engine cannot run — fail-closed by design. Other planes have larger hook budgets and keep working; opencode failing alone is expected, not evidence of a binary bug. |

## Things that look like bugs and aren't

- **Writing `.env` inside the repo is denied.** `.env` is a File secret (definitive tier). Use `.env.example`, or an operator-authorised `secret_allow`.
- **`rm -rf /tmp/x` is allowed.** Strict descendants of a system temp root are an authorised write seam. `rm -rf /tmp` itself is not.
- **Native `WebFetch` is always denied** with "use guardrail fetch": the native tool can't verify redirect targets; `guardrail fetch` can.
- **A `printf` or heredoc containing a secret path is denied** (`P4.secret-in-text`) even though nothing was accessed: interpreter input is opaque to the static boundary (ADR-0012). The guidance says to use the editor tool; that is the fix.
- **A python heredoc that merely mentions the night control is denied** for the same reason.
- **Re-running an approved `egress grant` says "already authorized"** instead of asking again — the broker applied it the moment you approved; the command is never re-run.
- **`guardrail night on` / `off` from inside a session is denied**, and so is anything longer than the exact three-word `guardrail night status` (which is read-only and allowed). Changing the posture is an operator action: run on/off from a terminal.
- **`git push --delete <branch>` asks** (`P2.git-push-delete`) even for an unprotected branch, and any command that reaches a policy position through a shell variable asks (`P3.unresolved`). Both are the intended fail-closed shape: spell the names out and answer the prompt.
- **`plane enable` says `already enabled`** and a session still reports floor drift → the installed release predates the floor-drift check (#33); `guardrail update` to current.

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

The agent itself cannot run any of this — the tool that would diagnose the
guard is gated by the guard. Recovery is an operator-terminal action by
necessity. Two standing cautions: the Defender exclusion for the binary path
must stay scoped to the exact file (#146), and never hand-copy a new binary
over the installed one except as a deliberate terminal recovery (#146) —
`guardrail update` is the only sanctioned replacement.

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
operator approvals: WebAuthn
claude settings: guardrail hook registered
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

Afterwards `~/.local/state/guardrail/selftest-passed` reads the new version and the
next Claude session's posture has **no** selftest line and **no** coverage line.
If the doctor header still names the *old* release, the updater predates #58:
run `guardrail selftest` once by hand.

## Where things live

| What | Path |
|---|---|
| Binary | `~/.local/bin/guardrail` |
| Operator config (grants, waivers, night marker) | `~/.config/guardrail/` — `waivers.toml`, `night.toml` |
| Audit log (rotates at 20 MB, 3 segments) | `~/.local/state/guardrail/audit.jsonl` |
| Session state, coverage cache, selftest marker | `~/.local/state/guardrail/{sessions,coverage,selftest-passed}` |
| Approval broker socket (on demand; dies with `update`) | `~/.local/state/guardrail/approval/broker.sock` |
| Repo overlay | `<repo>/guardrail.toml` — requests; only operator config grants |
| Claude hooks + floor | `~/.claude/settings.json` (owned groups carry `id: guardrail-*`) |

Everything under `~/.config/guardrail` and `~/.local/state/guardrail` is
operator-owned: sessions are denied from editing or deleting it, on purpose.
The selftest marker is a trust record, not a cache — if you want a session to
re-prove a release, delete the marker yourself.

On Windows the paths differ: binary `~\.local\bin\guardrail.exe`, audit log
`%LOCALAPPDATA%\guardrail\audit.jsonl`, operator config `%APPDATA%\guardrail\`,
and the approval broker's private endpoint is a per-user named pipe rather
than a socket (ADR-0021 step a).

## Escalate when

- `selftest` fails on a release that passed yesterday and nothing local changed → open an issue with the FAILED lines and `guardrail version`.
- `doctor --coverage claude` lists a tool → open an issue with the output; until it is contracted that tool runs unguarded.
- `audit` shows `unclassified tools observed` you don't recognise → same.
- A deny has no usable next step in its guidance → that is a bug by definition (every deny must redirect, not stop); file it with the exact text.
