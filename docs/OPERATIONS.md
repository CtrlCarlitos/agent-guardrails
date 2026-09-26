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
the scan starts at the binary's mtime.

The line that *is* a fault names its own cause instead:

```
claude settings: guardrail hook registered but CANNOT SPAWN — <reason>. Nothing
is being enforced; re-run `guardrail plane enable claude` to rewrite the command
```

A command that cannot spawn has necessarily never fired, so doctor prints the
spawn fault and suppresses the never-observed caveat — cause, not consequence.
Neither is appended when nothing is registered at all. This is what #149 looked
like from the outside for four days: `registered`, green, enforcing nothing.

## Symptom → command

| You see | Run | Why |
|---|---|---|
| Agent says it was blocked and you don't know why | `guardrail audit` then `grep '"decision":"deny"' ~/.local/state/guardrail/audit.jsonl \| grep -v selftest \| tail -5` | Every verdict is a JSONL record with `rule_id` and `reason`. Selftest writes deny probes to the same log on every update — filter them out or you will be reading the last selftest. |
| `operator action pending: …` (exit 3) from `setup`, `plane enable` or `plane disable`: the approval daemon is not running, or the request was denied or expired | Run `guardrail setup` from an interactive terminal, approve with your passkey, then re-run what provisioned the machine | Nothing is broken: the binary is installed and what is registered keeps enforcing. Only the change waited on you (#364). `guardrail next` lists what is still owed. |
| `no operator authenticator is enrolled` from `setup --state disabled`, `plane disable` or `recover` (exit 3) | `guardrail operator enroll` from a real terminal, then re-run the command it named | No passkey is enrolled, so no approval ceremony can start, and loosening actions wait for one (ADR-0030). The daemon is fine; nothing was changed. `approval daemon unavailable` now means exactly that: nothing answered on the socket and none could be spawned (#326). |
| doctor: `operator approvals: disabled (no authenticator enrolled; planes armed by bootstrap; …)` | `guardrail operator enroll` | The first install armed the planes without an approval (ADR-0030). They are guarding; nothing can loosen them until a passkey exists. Enrolling puts every later change behind it. |
| doctor: `N unmarked guardrail-like hook entries in settings.json` | `guardrail plane enable claude` | Legacy pre-marker hook groups; enable absorbs them (ADR-0004). Passkey. |
| doctor: `guardrail hook registered but CANNOT SPAWN` | `guardrail plane enable claude`, or `guardrail gen-config claude --merge <settings.json> --binary <path>` where plane commands are gated | The registered command cannot be spawned by a shell — an unquoted path with a backslash or a space. Nothing is being enforced while it reads this. Re-merging rewrites it (#149). |
| doctor: `guardrail hook registered but NEVER OBSERVED FIRING` | `guardrail selftest --evidence claude` | Registered, spawnable, not yet exercised. Expected on a fresh enrolment or a freshly built binary; clears itself once a real session is mediated. Exit 1 until two pre-hook records from one real session exist. If it persists across real sessions, the hook is not being invoked — treat as #149's shape. |
| doctor: `claude allow list: … N broader than the baseline` | `guardrail allow-baseline --check`, then edit `permissions.allow` in your own settings | A rule of yours such as `Bash(graft:*)` also matches commands the baseline leaves out (`graft init`, `graft upgrade`; an `npx` or `node` blanket runs remote or arbitrary code). Advice only: the list is yours, guardrail writes nothing (#363, `docs/allow-baseline.md`). |
| doctor: `present, hook NOT registered` / `no settings.json` | `guardrail plane enable <plane>` (or `--all`) | Re-registers the integration (hooks, and for opencode the plugin). Passkey. |
| Claude session posture: `Claude plane lifecycle: … drift` or `permissions floor drifted` | `guardrail plane enable claude` | A release changed what guardrail writes; enable re-merges idempotently. It also removes the retired permissions floor an earlier release wrote (ADR-0028, #357), keeping your own entries |
| Claude session posture: `claude coverage: Claude Code X — N uncontracted tool(s)` | `guardrail doctor --coverage claude` | Claude Code shipped a tool the contract doesn't know; it is **allow-by-default** until contracted. Open an issue with the doctor output. |
| Codex hook wiring or trust is uncertain | `guardrail doctor --codex-hooks` | Review registration, Codex-reported trust/hash, direct handler exit/stderr, runtime dispatch evidence, and observed capabilities separately. A green direct probe is not a coverage claim. |
| Claude session posture: `guardrail vX … run guardrail selftest` | `guardrail selftest` | Nothing has proven this release's enforcement on this machine yet. A pass records it and the line goes away. |
| settings.json / opencode.json / hooks.json corrupt or hand-edited | `guardrail recover claude-settings` (or `opencode-config`, `antigravity-hooks`) | Repairs Guardrail-protected machinery from a known-good shape. Passkey. Never edit these files by hand — sessions are P5-denied from doing so and so should you be. |
| An agent is waiting on an approval you never saw | `guardrail approvals list` then `guardrail approvals approve <id>` | Lists `<id>  <action>  expires <time>`; `approve` re-opens the ceremony and waits. `no approval daemon is running` means nothing is pending. |
| Approval page never opened / daemon looks stuck | `guardrail approvals list`; if that hangs, kill the `guardrail approvals daemon` process — the next request re-spawns it from the installed binary | The daemon is spawned on demand and shut down by every `update`, so it can never outlive a release |
| `registered handlers differ from this binary` (printed by `setup`), or a plane still runs the previous release's hook command after `guardrail update` | `guardrail setup` | `update` swaps the binary but leaves registered handlers alone; `setup` compares each plane's registered hooks (and the codex wrapper / opencode plugin entry) with what this binary generates and re-merges any that differ, under one approval (#317). Seeing the line during `setup` means it is fixing it. |
| `guardrail update` says `release assets may still be publishing; retry in a minute` | wait 60 s, run it again | You raced the release uploader; nothing was changed |
| `update` (or the installer) exited 1 with `<step> failed on the new binary` / `already replaced` | `guardrail selftest` (read the FAILED lines) then `guardrail update <previous version>` (the message names it) | The new release drifted on a probe or doctor failed. The binary is already replaced, and the exit is 1 so automation does not read it as success (#94). Roll back with the same command; it is checksum-verified either way |
| Agent needs a website | agent runs `guardrail egress grant --scope repo --host a.example.com,b.example.com` inside its session → you approve with passkey; or you run the same at a terminal (immediate, no passkey) | Grants live in `~/.config/guardrail/waivers.toml` plus the repo's `guardrail.toml`; **both** must agree. Native WebFetch is always denied; `guardrail fetch <url>` is the sanctioned path |
| Too many asks tonight | `guardrail night on --for 8h` (terminal only) | Relaxes routine asks to allow until then. External-tier asks (publishing, schedulers, unknown MCP) are never relaxed (ADR-0018). `guardrail night off` restores. `guardrail night status` works from anywhere and exits 1 when inactive — a state, not a failure. |
| Windows: an opencode agent reports *every* tool call failing `guardrail: could not run (spawnSync … ETIMEDOUT); failing closed` | see **Windows: engine unreachable** below | Per-spawn latency (Defender scan + NTFS `CreateProcess`, #132) exceeded the opencode plugin's budget; the plugin denies everything when the engine cannot run — fail-closed by design. Other planes have larger hook budgets and keep working; opencode failing alone is expected, not evidence of a binary bug. |

## Native web research

From your own terminal, `guardrail web-research status` reports the setting.
`guardrail web-research off` requests authenticated approval to permit native
research; `guardrail web-research on` requests strict enforcement again. Here
**on means enforcement on**, not search enabled. Both changes require an
enrolled authenticator; a failed or denied approval does not authorize a change.
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

## Things that look like bugs and aren't

- **Writing `.env` inside the repo is denied.** `.env` is a File secret (definitive tier). Use `.env.example`, or an operator-authorised `secret_allow`.
- **`rm -rf /tmp/x` is allowed.** Strict descendants of a system temp root are an authorised write seam. `rm -rf /tmp` itself is not.
- **Native `WebFetch` is always denied** with "use guardrail fetch": the native tool can't verify redirect targets; `guardrail fetch` can.
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

The agent itself cannot run any of this — the tool that would diagnose the
guard is gated by the guard. Recovery is an operator-terminal action by
necessity. Two standing cautions: the Defender exclusion for the binary path
must stay scoped to the exact file (#146), and never hand-copy a new binary
over the installed one except as a deliberate terminal recovery (#146) —
`guardrail update` is the only sanctioned replacement.

## Install, update, disable, uninstall

Installation is this repo's job ([ADR-0029](./adr/0029-installer-lives-in-this-repo.md)).
Every release ships `install.sh` (Linux, macOS, WSL; POSIX `sh`) and
`install.ps1` (Windows PowerShell 5.1 and PowerShell 7) next to the binaries,
listed in the same `SHA256SUMS`. Fetch the script for the exact tag, verify it
against that tag's `SHA256SUMS` (the README shows both OS blocks), then run the
file. Do not pipe the scripts into a shell or evaluate them in-process: they
`exit` on failure and hand the terminal to `guardrail setup` for a passkey
approval.

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
per plane. `setup` refuses to run
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
`guardrail update <previous version>` (the version of the binary that ran the
update; a dev build says `<previous version>` because it has none). The
installers pass that through: exit 1 with the same rollback line. An updater
older than #94 exits 0 on these failures, and the installer cannot tell.

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
operator approvals: WebAuthn
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

Afterwards `~/.local/state/guardrail/selftest-passed` reads the new version and the
next Claude session's posture has **no** selftest line and **no** coverage line.
If the doctor header still names the *old* release, the updater predates #58:
run `guardrail selftest` once by hand.

`update` does not touch the registered handlers. Run `guardrail setup` after it
(or re-run the installer, which does both): it re-registers any plane whose
handlers differ from what the new binary generates and prints `already
enabled` for the rest.

## Where things live

| What | Path |
|---|---|
| Binary | `~/.local/bin/guardrail` |
| Installers | `install.sh`, `install.ps1` — release assets next to the binaries, listed in the release's `SHA256SUMS`; source at the repo root |
| Operator config (grants, waivers, night marker) | `~/.config/guardrail/` — `waivers.toml`, `night.toml` |
| Audit log (rotates at 20 MB, 3 segments) | `~/.local/state/guardrail/audit.jsonl` |
| Session state, coverage cache, selftest marker | `~/.local/state/guardrail/{sessions,coverage,selftest-passed}` |
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
