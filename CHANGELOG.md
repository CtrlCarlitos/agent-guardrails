# Changelog

All notable changes to agent-guardrails. Format: one section per release;
within a release, grouped by theme. Breaking changes are called out
explicitly in **Breaking** notes.

## v0.23.22-dev (2026-09-29)

### Audit
- **Feature (#456): every hook call records how long it took.** Hook
  records in `audit.jsonl` gain `hook_ms`, the in-process handling time for
  spawned and daemon-served calls alike, and, for a spawned hook,
  `startup_ms`, from process start to handling. Both are additive fields.
  `guardrail doctor` prints per-plane p50/p95 over the latest 200 real calls
  (selftest probes and older records without a measurement are excluded). It
  is data for deciding whether a long-running server is worth building;
  nothing acts on it. The host's own cost of creating the process is not
  visible from inside it.

## v0.23.21-dev (2026-09-29)

### OpenCode
- **Fix (#452, closes the #427 investigation): no more "engine unreachable;
  degraded allow for todowrite".** The #427 timing trace from a real session
  (Windows, OpenCode's `bun 1.3.14`) showed the first engine spawn of 115 of
  117 logged calls reporting `ETIMEDOUT` after 3-93 ms against a 15 s
  budget, with a process created and no output; the next spawn answered in
  ~120 ms, and no call ever timed out for real. `todowrite` and `question`,
  which get one attempt, degraded every time (and never reached the audit
  log); every other tool paid ~640 ms per call. An `ETIMEDOUT` that returns in
  under a second and under half its budget is now retried once, immediately,
  with no backoff. A repeated fast timeout still degrades or fails closed as
  before. Restart OpenCode after updating so it loads the new plugin.

## v0.23.20-dev (2026-09-29)

### Guidance
- **Fix (#449): agent-facing text audited after #446.** Every string an
  agent reads was checked against today's behaviour (prompt mode by default,
  the Windows broker, OpenCode's exact-retry approval). Changed:
  - The session-start posture (Claude, Codex) now says what to do: on an
    ask, tell the operator in one sentence what and why, wait, then retry the
    exact call on its own; on a deny, follow the message's next step.
  - The Claude plane lifecycle line tells the agent to run
    `guardrail plane enable claude` on its own (the host asks the operator)
    instead of handing the operator the command.
  - An ask naming an operator action no longer says "passkey, not through
    chat", which was true only in passkey mode.
  - The `P5.self-config` deny points at `guardrail doctor`, which prints the
    exact repair, instead of an unnamed "terminal recovery command".
  - The Codex ask (Codex cannot ask, #349) names the single-use grant and
    `guardrail explain` instead of "authorize the relevant policy".
  Unchanged because still accurate: passkey and WebAuthn texts (passkey
  mode only), Codex's "cannot request approval", the OpenCode degraded
  notices, and "ask the operator to run it manually" on destructive denies,
  which cannot be approved.

## v0.23.19-dev (2026-09-29)

### Dependencies
- `github.com/bmatcuk/doublestar/v4` 4.10.0 → 4.10.2 (#444): the glob
  matcher behind path rules, including the secret-path list. 4.10.1 fixes
  brace alternation when the pattern also has a character class (none of the
  shipped globs use either; an operator overlay could); 4.10.2 fixes Windows
  junction traversal in filesystem walks, which rule matching does not use.
- `github.com/go-webauthn/webauthn` 0.18.1 → 0.18.2 (#445): attestation
  verification fixes; affects only the opt-in `approval = "passkey"` mode.

### Guidance
- **Fix (#446): Windows asks no longer tell the agent approval is
  unavailable.** Every ask on Windows ended "in-session approval is not yet
  available: the operator can run this exact action from a terminal
  instead", a stopgap that was meant to go when the Windows approval broker
  landed, and never did. An OpenCode agent read it, sent the operator to a
  terminal instead of asking, and after "approved" retried a longer command,
  which asked again. The sentence is gone, and the approval path now says the
  retry must be the exact call on its own: adding or dropping a step makes it
  a new action.

## v0.23.18-dev (2026-09-28)

### Approvals
- **Fix (#441): concurrent grants no longer fail each other on Windows.**
  Before an operator action runs, recovery reads every other transaction's
  journal to finish ones a crash left behind. It also met journals that live
  sibling transactions were replacing or removing, and returned that as an
  error: on Windows a sharing violation, anywhere a journal removed between
  listing and reading. A journal that has vanished or is held open by
  another process now counts as a live transaction's and is skipped; a
  genuinely unreadable journal still fails recovery.

### Policy
- **Fix (#435): more credential stores are secret-tier.** With the shipped
  policy an agent could read these with `cat` or the Read tool, and whatever
  it reads goes to the model provider: gh's `hosts.yml` (the token lives there
  in plain text where there is no OS keyring, e.g. WSL), `~/.config/hub`,
  `_netrc`, cargo, Terraform Cloud and Vault tokens, fly's config, the Azure
  token caches (`~/.azure`), `pass` and 1Password CLI stores, and the agents'
  own login files (`~/.claude/.credentials.json`, `~/.codex/auth.json`,
  OpenCode's `auth.json`, `~/.gemini/oauth_creds.json`). All now deny as
  `P4.secret-path`, including inside `$()`. Their neighbouring config files
  (`gh/config.yml`, `.gitconfig`, `.cargo/config.toml`, agent settings) stay
  readable. `.yarnrc.yml` is left alone because repositories commit it.

### Engine
- **Fix (#438): substitutions inside declarations and arithmetic are
  evaluated.** `export X=$(rm -rf /)` allowed while `X=$(rm -rf /)` denied: the
  commands inside a substitution in `export`, `local`, `declare`, `readonly`,
  `typeset`, `let` or `(( ))` were never handed to any rule. They now get the
  same verdict they get anywhere else.
- **New (#436): credential-printing commands ask unless their output is
  captured** (`P4.credential-print`). Operator decision of 2026-09-28,
  reversing #289: everything a command prints is sent to the model provider.
  `gh auth token`, `gh auth status --show-token`, `git credential fill`,
  `security find-generic-password -w`, `secret-tool lookup`,
  `docker-credential-* get|list`, `az account get-access-token`, the aws
  token, secret and `configure get <key>` reads, `gcloud auth print-*-token`
  (which asked under `P6.cloud-mutate` before), `kubectl config view --raw`,
  `npm config get` of an auth key, `op read`, `vault kv get|read`, and their
  `.exe` spellings now ask when the value would reach the session: bare, piped
  into anything but a credential consumer, `echo $(…)`, redirected to a file,
  stored in a plain variable, or under `set -x`/`bash -x`. They stay allowed
  when a `$()` hands the value to a command that does not print it
  (`GH_TOKEN=$(gh auth token) gh pr list`, `docker login --password-stdin <<<
  "$(…)"`) or when piped into `--password-stdin`/`--with-token`. `env`, bare
  `printenv`, `printenv`/`echo`/`printf` of a secret-looking variable
  (`*TOKEN*`, `*SECRET*`, `*PASSWORD*`, `*API_KEY*`, …) and PowerShell's
  `gci env:` ask under the same rule. This checks command shape: a consuming
  program that prints its own arguments or environment can still leak the
  value. See OPERATIONS.md, "Passing credentials to commands".

## v0.23.17-dev (2026-09-28)

### Engine
- **Fix (#430): `gh auth login --with-token` asks** (`P2.gh-auth-scope`). It
  logs in as whatever account the supplied token belongs to, with no person
  involved: the same act as `gh auth switch`, which already asked. Plain
  interactive `gh auth login` and `gh auth status` stay allowed.

### Antigravity
- **Fix (#432): the `call_mcp_tool` deny gives the right next step.** It told
  the agent to "Register the MCP tool in ~/.gemini/config/mcp_config.json",
  which was wrong (the server was registered; Antigravity offered its tools
  only lazily, which it routes through `call_mcp_tool`) and asked an agent to
  edit its host's configuration. It now says to call the tool by its direct
  name `mcp_<server>_<tool>` when offered, not to retry through
  `call_mcp_tool` otherwise, and to tell the operator the server's tools must
  be loaded eagerly. The deny itself is unchanged (ADR-0019).

## v0.23.16-dev (2026-09-28)

### OpenCode
- **Diagnostics (#427): the plugin writes a timing trace.** On Windows every
  real `todowrite` and `question` call ends in `degraded allow … ETIMEDOUT`,
  and neither tool has ever reached the audit log, yet the same envelopes
  answer in ~70 ms when replayed. `plugin-failures.log` cannot say where the
  time goes. The plugin now appends one JSON line to `plugin-timing.jsonl`
  (next to `plugin-failures.log`) for every call slower than 1 s or with a
  failed attempt, including retried calls that stalled once and then
  succeeded: daemon dial time, each spawn attempt's duration, timeout, pid and
  outcome, envelope size, runtime and result. Fast calls write nothing. No
  verdict changes. Restart OpenCode after updating so it loads the new plugin.

## v0.23.15-dev (2026-09-28)

### Coverage
- **Fix (#423): `graft_check_freshness` is contracted.** graft 0.20 added the
  MCP tool (a read-only drift check, no arguments); `doctor --coverage
  antigravity` reported it uncontracted and `setup` ended with a coverage
  warning. It is now read-discovery like the other graft tools.

### Engine
- **Fix (#422): `2>$null` no longer asks.** Every command carrying PowerShell's
  discard asked `P3.unresolved`, even `ls 2>$null`, under the Bash and
  PowerShell tools alike; an OpenCode agent on Windows was stopped on
  `rg --files … 2>$null | Out-String` and worked around it. A redirect target
  spelled exactly `$null` (any case) is now a discard. A same-command
  assignment to `null` is still judged as the write it is, and look-alikes
  (`$nullx`, `${null}x`, `$null/x`) stay unresolved. `rg` and `grep` were
  already allowed; nothing changed for them.
- **Fix (#422): `rg --pre` asks** (`P1.rg-preprocessor`). `--pre` runs a program
  on every searched file, so `rg --pre rm x ~` deleted what a direct `rm` there
  would be asked about. `--pre-glob`, `--no-pre` and anything after `--` are
  unaffected.

## v0.23.14-dev (2026-09-27)

### Approvals
- **Fix (#419): the `[y/N]` question is written to the console, not stdout.**
  On Windows the dotfiles run the installer through `Tee-Object`, which shows
  only complete lines, so `Approve …? [y/N] ` never appeared and the install
  waited on a prompt nobody could see (WSL, unpiped, was fine). The question
  now goes to the console the answer is read from (`CONOUT$` on Windows,
  `/dev/tty` elsewhere), as `sudo` does, and stdout gets a complete line
  recording what was asked and the answer. With no console it falls back to
  stdout as before.

## v0.23.13-dev (2026-09-27)

### Approvals
- **Fix (#416): `guardrail approvals grant` and `approvals approve` work from
  the operator's terminal, and a session can no longer run them.** Since the
  first release the CLI passed "not a terminal" to both, so they refused even
  in the operator's own console, and the grant `guardrail explain` prints was
  unusable. The Engine had allowed the agent-run forms, including through
  `script`, `unbuffer` and `winpty`, so the broken check was the only barrier.
  The Engine now denies a session's `approvals grant|approve` as
  `P5.self-config` (direct, interpreter and terminal-wrapper spellings), and
  only then does the CLI honour a real terminal. `approvals list` and
  `revoke` stay allowed.
- **Feature (#413, ADR-0033): operator approvals default to a prompt; the
  passkey is opt-in.** Operator config gains a top-level key,
  `approval = "prompt" | "passkey"`. Missing means `prompt`, for everyone,
  including operators who already enrolled a passkey; an Overlay cannot set
  it; an unreadable Operator config means `passkey`. In prompt mode a terminal
  run of `setup`, `plane enable|disable`, `recover` or `web-research on|off`
  asks `Approve <summary>? [y/N]` (default No; a declined `setup`/`plane`
  exits 3). An agent's exact canonical operator command becomes its host's
  own ask (Claude `ask`, Antigravity `force_ask`, opencode's dialog where its
  permission settings ask); Codex, which cannot ask from a hook, is denied
  with the command for the operator to run in a terminal. When the human
  approves, the TTY-less run claims an **approval ticket** the hook recorded:
  bound to the exact command and working directory, ten minutes, single use
  under an exclusive lock, voided by the session's next call, stored in the
  P5-protected `guardrail/approval-tickets/` under the state root. Approved
  actions run the same handlers as the broker and are audited with
  `transport: host-ask` or `terminal-prompt`. `guardrail doctor` prints
  `approval mode: …`; `guardrail next` and the bootstrap message stop asking
  prompt-mode operators to enroll. **Breaking (default):** an operator who
  wants to keep WebAuthn must add `approval = "passkey"`. **Downgrade:** a
  binary older than this release reads a `waivers.toml` with the key as
  unreadable; remove the key before downgrading. Passkey mode is unchanged.
- **Fix: every rewrite of `waivers.toml` keeps the approval key.** Grant
  consumption (which runs inside the hook), web-host grants and the
  web-research switch re-serialise the file; without this they would have
  silently turned a passkey operator into a prompt one.
- **Fix: a canonical operator command is never answered by the engine
  daemon.** The hook used to hand every call to a running engine daemon
  first, whose evaluator has no broker path. Measured on `d274a8e` in a
  sandbox with `guardrail daemon start` running: the Claude hook answered
  `guardrail night off` with a `P5.self-config` deny (exit 2) instead of a
  broker request.

### Engine
- **Fix (#413): a pty wrapper can no longer fake the operator's terminal.**
  Measured on `d274a8e`: `script -qc "guardrail setup" /dev/null`,
  `expect -c 'spawn guardrail setup'`, `unbuffer guardrail setup`,
  `winpty guardrail setup`, `tmux new-session -d 'guardrail setup'` and
  `screen -dm guardrail setup` were allowed (only interpreters such as
  `python3 -c 'import pty; pty.spawn(…)'` were denied). `script`, `expect`,
  `unbuffer`, `winpty`, `tmux`, `screen`, `socat`, `dtach`, `abduco`,
  `empty`, `faketty`, `mintty`, `wt` and `conhost` are now read like
  interpreters by `P5.self-config`: command text naming guardrail and a
  self-control subcommand is denied. `egress` (non-canonical spellings only;
  the exact command is intercepted first) and `hook` (a session running the
  hook could forge its host's payload) join the self-control subcommands.
  Writes to `guardrail/approval-tickets/`, directly or named in interpreter
  code, are `P5.self-config`. New adversarial corpus rows pin each case.
- **Fix (#125): an egress deny leads to the fetch and the exact grant, and
  never back to a dead end.** Measured on all four planes before the fix: a
  `curl`/`wget` to an unapproved host told the agent to request a grant with
  placeholder hosts (`api.example.com,cdn.example.com`), and once that grant
  was approved the same `curl` was still denied with the same advice, because a
  web-host grant authorizes `guardrail fetch`, not shell network tools; a
  native web fetch said "complete the work by other means"; `guardrail fetch`
  to an unapproved host printed only "requires operator approval"; and the
  session posture never mentioned web access. Agents learned to stop trying.
  Now the `P6.egress` reason for a web client names the exact grant
  (`guardrail egress grant --scope repo --host <host>`), its next step says the
  grant authorizes `guardrail fetch` and not curl or wget, the native-fetch
  deny sends the agent to `guardrail fetch`, `guardrail fetch` names the host
  and the exact grant (also for an unapproved redirect), and the SessionStart
  posture says the path exists, to attempt the fetch rather than assume a
  deny, and that `guardrail explain` shows any deny's record and next step.
  Both denies end with "do not skip a fetch because an earlier one was
  denied", and the rule ID still fits in the 512-rune model-facing bound. No
  verdict changed.

### CLI
- **Feature (#106): `guardrail explain`, one command from an audit record to
  the fix.** With no argument it prints the newest ask or deny for the
  repository you are in (selftest probes excluded): what was evaluated, the
  verdict and `rule_id`, the reason, the next step the agent was given (the
  adapter's own text, so it cannot drift from the guidance), and what only the
  operator can do: the exact `guardrail approvals grant` line for a grantable
  ask, why an ask can never be granted, or `guardrail approvals approve <id>`
  and the latest status for a brokered action. `explain <session-id>`,
  `explain <request-id>`, `explain <timestamp>`, `--last N`, `--all` and
  `--path` select other records. Exit 0 explained, 1 nothing matched, 2 usage
  error or unreadable log. It reads the log only and never re-evaluates.

### Audit
- **Additive (#106): records carry `repo_root`, and a fail-closed hook deny is
  recorded.** A hook that could not parse its payload or load its policy denied
  the call with no audit record at all, so the deny the agent saw could not be
  found afterwards. It is now written with an empty `rule_id`, `audit_kind:
  hook-fail-closed` and the reason the agent saw. Hook records also name the
  repository they were evaluated for, which is what `explain` scopes by.

### Tests
- **Fix (#406): repo guard tests no longer read another checkout's files.**
  Three guards that walk the repository skipped nested checkouts only by the
  name `.worktrees`, so an agent's worktree under `.claude/worktrees/` made
  `go test ./...` fail for as long as the agent ran. They now skip any
  directory with its own `.git` (`testenv.IsNestedCheckout`).

### Installer
- **Test (#146): the Defender exclusion is locked to the one binary.** A repo
  guard test now fails if `install.ps1` excludes anything other than exactly
  `<dest>\guardrail.exe`: a directory, a process name, an extension, or a
  `Set-MpPreference` that would replace the operator's own exclusion list.
  The exclusion only ever runs elevated, which CI is not, so nothing checked
  its scope before.

### Docs
- **Docs (#91): host × OS × shell compatibility matrix.**
  `docs/compatibility-matrix.md` states, per plane, OS and shell, whether
  guardrail is enforced and observed, registered only, unenforced, CI-tested
  only or unknown, and cites the evidence for each cell (a dated Windows run,
  audit records, research notes, ADRs, doctor wording). The per-OS table in
  `docs/stability-policy.md` now links to it instead of repeating it; the
  Linux and WSL cells it marked Enforced had no recorded run and are now
  operator-reported. `docs/operator-approvals.md` no longer says Windows
  approvals are fail-closed.
- **Docs (#98): getting-started guide.** `docs/getting-started.md` walks a
  new user from the pinned-tag installers through `guardrail setup`, passkey
  enrollment and the first approval, to reading the `guardrail doctor`
  verdict line and `guardrail next`, the exit codes 0 to 3, what a deny and
  an ask look like, and `guardrail explain`. Linked from the README.

## v0.23.12-dev (2026-09-26)

### Engine
- **Fix (#251): the rest of the go toolchain is classified.** `go generate`
  now asks (`P1.go-generate`): it runs the command in every `//go:generate`
  directive, which the hook never sees; `go generate -n` (list only) stays
  allowed. `go tool` keeps the distribution's tools (`pprof`, `cover`, `trace`,
  `vet`, ...) allowed and asks (`P6.package-install`) for a tool declared by a
  go.mod `tool` directive, which builds and runs third-party module code.
  `go install` of a module path or version keeps the `P6.package-install` ask;
  `go install` of the repository's own packages now asks as
  `P1.out-of-repo-write` (it writes into GOBIN, on PATH) and names
  `go build -o` as the in-repo alternative. Every `go get` still asks. The
  global `go -C dir` flag no longer hides the subcommand: `go -C sub run
  example.com/x@latest`, `go -C sub install ...@latest`, `go -C sub env -w
  GOPROXY=...` and `go -C sub mod edit -replace` were allowed and now get the
  verdict their unprefixed form gets. `go.exe` spellings are covered.
- **Fix (#146): deleting or moving away the enforcement binary is
  `P5.self-config`, and so is naming it in interpreter input.** `Remove-Item`,
  `ri`, `del`, `erase` (also under `cmd /c`) on `guardrail.exe` were allowed;
  wildcards that match the binary (`Remove-Item ~\.local\bin\*.exe`,
  `rm ~/.local/bin/guardrail*`), a trailing-dot spelling, and a POSIX `mv`
  that takes the binary as its source were missed too. They now deny. A
  literal path to the installed binary (`.../bin/guardrail`,
  `.../bin/guardrail.exe`) inside `python -c`, `node -e`, `perl -e`,
  `powershell -Command` input, or in a PowerShell line the parser cannot read
  (`[IO.File]::WriteAllBytes(...)`), denies the same way the Operator config
  already did: Guardrail cannot tell a read or a run from a write there, so a
  hash or a `& '<path>' doctor` through an interpreter is denied too; run
  `guardrail <command>` directly. `guardrail update`, `doctor` and `selftest`,
  the staged `.old` name, and a repository's `bin/*` build output are
  unaffected.

### CLI
- **Fix (#395): `guardrail help` lists every subcommand it dispatches.**
  `allow-baseline`, `next`, `daemon` and `help` itself were accepted but not
  listed; the `operator` subcommand line sat under `approvals`. `daemon` is
  marked internal, not a stable surface. A test now reads the dispatcher's
  `case` labels from `run.go` and fails when one is neither in the usage text
  nor in an explicit hidden list with a reason.

### Policy
- **Fix (#397): an unknown key in `guardrail.toml` is a warning, not
  silence.** The Overlay parser dropped every key it did not know (only
  unknown `recipes` settings failed), so a typo such as `waiver`, `[slot]` or
  `[slots] safe_root` did nothing and `doctor` said `verdict: healthy`. Each
  unknown key (an unknown table once) is now a policy warning naming the key
  and the file: `doctor` lists it and counts it toward the verdict line, `sync`
  prints it, and the hook passes it on with the other policy warnings. The
  Overlay still loads, so existing overlays and overlays written for a newer
  binary keep working.

### Docs
- **Docs (#93): GitHub issue templates.** `.github/ISSUE_TEMPLATE/` has issue
  forms for a bug (plane, OS, shell, `guardrail version`, the `guardrail
  doctor` verdict line, the audit record), an engine verdict (false positive,
  false negative, or a denial with no next step: the command, the verdict and
  rule ID, the expected verdict), a tool not covered by a plane's contract,
  and a feature. `config.yml` keeps blank issues and sends bypass reports to
  the private security advisory form.
- **Docs (#108): `docs/release-checklist.md`.** The release flow as the
  `chore(release)` commits run it: `## Unreleased` becomes a dated section,
  the README install pin moves in its three places, one release PR squashed,
  an annotated tag on the squash commit, `release.yml` publishes nine assets,
  and the tag is reported for the dotfiles pin. Updater changes verify on N+2,
  not N+1 (#94's exit code is the current instance: it shows first on the
  update from v0.23.11-dev to its successor). Linked from `OPERATIONS.md` and
  `CONTRIBUTING.md`.

## v0.23.11-dev (2026-09-26)

### Docs
- **Docs (#89): `CONTRIBUTING.md`.** Build, gofmt, vet and test commands for
  Windows and Linux (the WSL recipe), how to run the adversarial corpus and the
  contract fixtures, the house rules (TDD, conventional commits, one PR per
  issue, no attribution trailers, `TestWindows...` naming, no force-push), the
  rules enforced on agents, where a rule, MCP family, plane or ADR goes, and how
  to file an issue. The README's stale "Go 1.25" now says 1.26 and links it.
- **Docs (#103): `docs/stability-policy.md`.** What is stable (verdict format,
  hook protocol, CLI surface with the 0/1/2/3 exit-code contract, Overlay and
  Operator config formats), what is not yet (internal Go APIs, adapter
  behaviour, MCP registry schema, audit log, additive-only), the
  breaking-change process, and a per-plane support table (Codex on Windows is
  registered, unenforced: openai/codex#24453). Documentation only: no version
  is tagged or renamed.

### Update
- **Fix (#94): a failed post-install verification is a failed update.**
  `guardrail update` ran `doctor` and `selftest` on the new binary but returned 0
  whatever they said, so automation read an unhealthy update as success. It now
  exits 1 when either exits non-zero (3, operator action pending, is not a
  failure), says the binary was already replaced, and names the rollback
  (`guardrail update <previous version>`). `install.sh` and `install.ps1` tell a
  refusal before replacement ("left as it was") from a failed verification after
  it, and name the same rollback. Only a binary that has this fix reports it: an
  older updater still exits 0.

### Doctor
- **Feat (#105): `doctor` ends with one verdict line.** `verdict: healthy`, or
  `verdict: N problems (see above)`, counting everything doctor already prints
  in a warning register: policy warnings, an overlay warning or parse error, an
  unreadable operator config, a plane present but not registered (or disabled,
  unparseable, `CANNOT SPAWN`), unmarked legacy hook groups, ownership drift,
  Antigravity floor warnings, an unreachable engine, a spawn latency warning,
  credential-posture warnings and, with `--coverage`, uncontracted tools. The
  soft `NEVER OBSERVED FIRING` caveat is not counted. Exit codes are unchanged:
  plain `doctor` exits 0, `--coverage` keeps its exit 1, and a run that fails
  (exit 2) prints no verdict. It follows the next-steps block, so it is the last
  line.

## v0.23.10-dev (2026-09-26)

### Engine
- **Fix (#381): installs and remote-code launchers are asked about under every
  spelling, not only `pip install` and `npm install`.** `python -m pip install`,
  `pipx install|run`, `uv pip install|sync`, `uv sync|add|tool install`,
  `poetry install|add|update`, `bun install|add`, bare `yarn`, and the
  fetch-and-run launchers `npx`, `npm exec`, `pnpm dlx`, `yarn dlx`, `bunx`,
  `uvx` were allowed silently. They now get the same `P6.package-install` ask
  (and `python -m pip` keeps the `P6.registry-redirect` deny). `graft init`,
  `uninstall`, `upgrade` and `build --deep` ask too. Read-only forms (`pip list`,
  `uv --version`, `poetry show`, `graft ask`), `--no-install` launches and
  launches of a local path stay allowed.
- **Fix (#146): a session could replace the enforcement binary with a plain
  copy.** `Copy-Item <asset> ~\.local\bin\guardrail.exe -Force` was allowed.
  Two causes: the `P5.self-config` globs named `guardrail` but not
  `guardrail.exe`, and the write-target reader only knew the POSIX spellings, so
  the Windows copy, move and content commands were invisible to the rule. It now
  reads the destination (and, for a move or rename, the source) of `Copy-Item`,
  `copy`, `cpi`, `Move-Item`, `move`, `Rename-Item`, `xcopy`, `robocopy`,
  `Set-Content`, `Add-Content`, `Out-File`, `Tee-Object` and `New-Item`, including
  directory destinations, wildcard sources and robocopy file lists, and denies
  them as `P5.self-config` on the installed binary in either spelling. The same
  cmdlets now also deny on the other self-config paths (`.claude/settings.json`,
  `guardrail.toml`, ...). `guardrail update` and the installer replace the binary
  themselves and are unaffected; `guardrail.exe.old` staging names stay clear.

### Setup
- **Fix (#322): a hook event a newer release stops generating no longer leaves
  its old guardrail group on disk.** The merge only visited events the new
  fragment still emits, so a registration written by an older release kept its
  owned group under the dropped event and `guardrail setup` failed its
  convergence check ("still differs after approval") on every run. The merge now
  also removes guardrail-owned (and legacy unmarked guardrail) groups under an
  event the fragment dropped, keeps the operator's own groups and every
  untouched event, and retires the ownership record so `plane disable` and
  drift stay exact.

### Approvals
- **Fix (#126): the canonical egress grant/revoke action is recognised in any flag
  order.** `guardrail egress grant --host x --scope repo` and the `--flag=value`
  spellings fell past the operator-action guard, which only matched
  `--scope` first, so the agent got no approval request for a command the CLI
  accepts. The guard now parses the arguments (each of `--scope` and `--host`
  exactly once, clean values, no shell syntax) instead of matching one fixed
  spelling; extra, unknown, missing or duplicated flags and anything chained
  stay non-canonical.
- **Fix (#383): the approval ceremony no longer leaves an operator guessing which
  authenticator to use.** On a machine with a Windows and a WSL instance, the
  page fired its WebAuthn request the moment it loaded, so an operator met a
  small system dialog with no context, chose "iPhone or Android device", scanned
  the QR code (which "linked"), and the phone answered "No passkeys available":
  a passkey for the rpId `localhost` lives only where it was enrolled. Cause: the
  enrollment page never sent the authenticator's transports, though the store
  records them when they arrive, so every stored credential had `transports:
  null` and the browser, told nothing, offered every option including a phone.
  Enrollment now sends `getTransports()` (guarded for browsers without it), so
  credentials enrolled from now on narrow the prompt. The approval page now says
  which guardrail instance is asking (`WSL Ubuntu-24.04 on <host>`), explains
  that passkeys for localhost cannot live on a phone, and, when the ceremony
  fails, names what to do next (`guardrail operator recover-reset`, then
  `guardrail operator enroll`, choosing this device). `doctor` prints
  `operator authenticators: N authenticators: X synced, Y device-bound;
  transports recorded for Z of N`, so "which device can approve" has an answer.
  `docs/operator-approvals.md` documents the WSL topology. Credentials enrolled
  before this change still have no transports; the doc says how to replace them.

### Policy
- **Feature (#363): `guardrail allow-baseline`, a reviewed list of Claude Code
  allow rules that are safe to put in your own settings.** It replaces the
  explicit-allow channel first proposed on that issue, which is withdrawn: the
  Engine blocks and never approves, and Claude Code's permission prompts are its
  own, driven by an allow list in a file the operator owns (ADR-0028). The
  baseline is documentation for that file, and guardrail writes none of it.
  "Safe" is a definition the operator already accepted: the verification
  commands guardrail runs for them at session end, taken from the recipe registry
  so the two cannot disagree (`go build|test|vet`, `pytest`, `ruff check`, `mypy`,
  `tsc`, `eslint`, `npm test`, `cargo test`, ...), plus read-only package queries
  and graft's read-only subcommands, allowed **by subcommand**. Installs and
  adds, remote launchers (`npx`, `dlx`, `uvx`), arbitrary code (`node <file>`,
  `python -c`, `npm run <any>`) and graft's mutating subcommands (`init` writes
  agent config and Claude hooks, `upgrade` runs `npm install -g`, `uninstall`,
  `build --deep`) are deliberately outside it, and a test fails if a rule that
  could match one is ever added. `guardrail allow-baseline` lists the rules with
  the reason for each, `--json` prints them as a `permissions.allow` block (the
  same block is in `docs/allow-baseline.md`, and a test fails if the two
  disagree), and `--check` compares your list with it: which rules you lack, and
  which of yours are broader than the baseline with the reason (a blanket
  `Bash(graft:*)` also runs `graft init` and `graft upgrade`). `doctor` gains one
  advisory line. There is deliberately no apply.

## v0.23.9-dev (2026-09-26)

### Policy
- **Fix (#377): a recursive delete outside the repository is denied when its
  path is a tracked variable followed by a literal glob.** `T=/etc; rm -rf
  $T/x*` was only asked about (`P3.unresolved`) while `rm -rf /etc/x*` and
  `rm -rf "$T"/x*` were `P1.rm-rf` denials. A literal glob after an unquoted
  variable is left unresolved on purpose (NF5b: a glob expands to many
  arguments, so a judgement about one path does not cover it), and the
  recursive-delete check skipped every unresolved operand. It now asks the one
  question it needs, whether the target can be outside the repository, using the
  operand as it would be typed out, and denies exactly when the literal would be
  denied. The word stays unresolved for every other rule, so `T=/etc; cat
  $T/*.conf` and `S=/tmp/scripts; bash $S/*.sh` still ask, and a glob that
  arrives in a variable's value, several fields, a substitution, an unknown
  variable and an extglob opener formed across the boundary are still not
  resolved. It also holds through `command` and `env` wrappers. A note on
  measurement: deleting a specific path under the system temp directory is
  allowed by design, and `$HOME/x` was already a denial.

### Installation
- **Fix (#374): the first update onto a release that has `guardrail next` now
  shows the next-steps block too.** `update` is run by the binary being
  replaced, and only `v0.23.6-dev` and later call `next` from it, so an operator
  updating from an older release saw doctor and selftest and no steps, exactly
  when they were needed most. Every updater does run the *new* binary's
  `doctor`, so `doctor` now ends with the same block (only when something is
  owed, computed by the same `nextSteps()` as `guardrail next`). A current updater
  marks the verification runs it starts (`GUARDRAIL_UPDATE_RUN`, cleared when
  `update` returns) and prints the block itself, last, after selftest, so it is
  not shown twice.

### Tests
- **Fix (#367): the adversarial suite no longer leaves a 20 MB build directory
  and an approval daemon behind on Windows.** A test that runs the real binary
  can make it spawn the detached approval daemon, and on Windows a running image
  cannot be deleted, so `TestMain`'s `RemoveAll` of the build directory failed
  and its error was discarded: 133 directories (2.7 GB) accumulated in `%TEMP%`
  on one machine, and finished test worktrees could not be removed
  (`Device or resource busy`). Measured: one full run left exactly one daemon and
  one directory; after this change a full run leaves none. Every child
  environment in the suite is now built by `adversarialChildEnv`, which registers
  a cleanup that finds the daemon serving that test's pipe and terminates it, but
  only after confirming the process is this suite's own binary. `TestMain` now
  retries the removal and reports a failure instead of swallowing it, and sweeps
  `guardrail-adversarial-*` directories older than a day that hold nothing but a
  built binary (leftovers of killed runs). The client's refusal to talk to a
  daemon that is a different program (ADR-0021) is unchanged; the test asks the
  OS which process serves the pipe. New `approval.EndpointFor(stateRoot)` names
  the endpoint a process with a given state root would use.

## v0.23.8-dev (2026-09-26)

### Hooks
- **Fix (#372, #335, #357): `plane enable` of an already-registered plane can
  be approved again.** Re-enabling a registered plane sends more than the plane
  list: `reconcile_ownership` (#335) and, while the retired settings floor is
  still on disk, `prune_floor` (#357). The approval broker accepted exactly one
  parameter, so it refused every such request and the daemon answered with the
  opaque `approval request unavailable`; the operator saw
  `approval request failed: approval request unavailable` and the change could
  not be approved. That blocked applying the Antigravity hook fix (#353/#354) and
  the floor prune to any machine that already had the plane registered. The
  command tests stub the transport and call the approved handler directly, so
  they never met the broker's validation or its store; new tests go through both.
  The broker now accepts exactly `planes`, `reconcile_ownership` and `prune_floor`
  for a plane enable (the last two only there, each bound to the planes in the
  request; `prune_floor` only for claude and opencode) and rejects every other
  key. It also persists them: the store kept only `planes`, so an approved enable
  would have run without its reconcile or its prune. The approval summary the
  passkey covers now says when an enable also removes retired floor entries.
  A rejected request is reported as `approval request malformed`, not as the
  same words as a failed browser start.

## v0.23.7-dev (2026-09-26)

### Installation
- **Change (#364 follow-up): `setup` and `plane enable|disable` exit 3, not 2,
  when an enrolled operator has no interactive terminal.** A change that needs a
  passkey approval needs a terminal to host it, so with none attached the work
  is waiting on the operator, which is what exit 3 means ("operator action
  pending"), not a usage error. Exit 2 goes back to meaning only usage and
  unsupported platform, so an installer, CI or a dotfiles apply can treat every
  "waiting on a human" outcome the same way and no longer has to avoid `setup`
  with `--no-setup` to keep the two apart. The refusal text is unchanged and is
  followed by the same `operator action pending: …` remedy the other pending
  cases print. `setup` now validates its arguments before the terminal check, so
  a mistyped flag is still exit 2 whether or not a terminal is attached.
  `operator`, `recover`, `web-research` and `approvals` are interactive by nature
  and keep exit 2. The first-install bootstrap still needs no terminal and exits
  0. The installers' `setup` probe is unaffected: it treats a binary as lacking
  `setup` only for exit 2 plus "unknown subcommand". **Behaviour change:**
  callers that matched exit 2 for "no terminal" must match 3.

## v0.23.6-dev (2026-09-25)

### Installation
- **Feature (#364): `update`, `setup` and the installers end with the steps
  still owed to the operator, and exit 3 now means "operator action
  pending".** New read-only `guardrail next` prints an ordered block computed
  from the current state (a plane whose handlers or hook spelling changed, the
  retired settings floor `plane enable` will remove, an operator who is not
  enrolled, restarting the agents) and prints nothing when nothing applies. It
  shares `setupEnableReason` with `setup` and `plane enable`, so the three never
  disagree, and it never changes a file or opens an approval. `update` runs it
  last through the freshly installed binary, `setup` ends with it for planes it
  was not asked about (bootstrap keeps its own instruction), and `install.sh` /
  `install.ps1` run it when setup is skipped, tolerating a release that predates
  it.
  Exit code 3, previously only "no authenticator enrolled", now covers every
  case where the work waits on the operator: the approval daemon not running,
  and a request that was denied or expired. Each prints an `operator action
  pending: <cause>` message that says what is still true (what is registered
  keeps enforcing, nothing was loosened) and how to finish (`guardrail setup`
  from an interactive terminal, approve, re-run the provisioning). A genuine
  failure still exits 1, so an unattended caller no longer has to match log text
  such as "approval request" to tell them apart. **Behaviour change:** denied,
  expired and daemon-unavailable outcomes of `setup` and `plane enable|disable`
  exit 3 instead of 1. The installer headers document the code.

### Tests
- **Fix: the linked-worktree engine tests no longer collide when two test runs
  share a checkout.** They built their repository under one fixed directory
  (`internal/engine/guardrail-worktree-tests`) and removed it on cleanup, so
  overlapping runs (Stop hooks from parallel sessions, agents sharing a
  checkout) deleted each other's repositories and failed with `could not lock
  config file: File exists` and `cannot lock ref 'HEAD'`. Reproduced with three
  concurrent runs before the change and clean after. Each test now takes its own
  `guardrail-worktree-tests-*` directory.
- **Fix: the linked-worktree fixtures can no longer commit into the checkout
  that encloses them.** Their git commands relied on git discovering the
  repository from the working directory, so a fixture whose `.git` vanished (a
  racing cleanup) made git climb to the real repository and commit the test's
  `init` there, which is how an unsigned empty commit landed on a real PR
  branch. The helpers now pin `--git-dir` to the fixture's own `.git`, so a
  missing one is an error. A regression test reproduces the leak (the enclosing
  repository gained a commit) and passes with the pin.

## v0.23.5-dev (2026-09-25)

### Policy
- **Feature (#357, ADR-0028 phases B and C): guardrail stops writing a
  permissions floor into Claude and OpenCode settings, and `plane enable`
  removes the one it wrote earlier.** The Engine enforces everything the floor
  mirrored, and a second copy in a file you own drifts and cannot be told apart
  from your own entries. `ClaudeConfig` now writes hook registration and the
  one `Bash(guardrail fetch:*)` allow; `OpencodeConfig` writes the plugin entry.
  Codex keeps its native floor (ADR-0028's exception plane); Antigravity never
  had one.
  `guardrail plane enable <plane>` (and `setup`) now also removes every entry
  that is exactly something guardrail generated, in this or an earlier release,
  including the retired `dd` / `git clean` / `rm -rf` globs and the pre-#270
  untranslated OpenCode globs. It keeps your own entries, any value you edited,
  OpenCode's `bash "*"` base rule, and every other key. It announces the count
  first, the operator's passkey covers it (the approved request names
  `prune_floor`), it retires the ownership records, and it is idempotent.
  The approval-less first-install bootstrap never prunes: it can only tighten
  (ADR-0030). Measured on a copy of one operator's real files: Claude 247
  permission entries and 11,185 bytes down to 5 allows and 3,598 bytes;
  OpenCode 18,239 bytes down to 609.
  **Behaviour change:** `sync` and `gen-config` no longer copy an overlay's
  `secret_globs` into the repo's Claude `permissions`; the Engine applies the
  overlay at hook time. If the Engine is unreachable a Claude session is
  unguarded, the exposure ADR-0028 accepts and `doctor` reports (#151).
- **Fix (#355): `P3.unresolved` no longer holds a path-free builtin after an
  uncertain `cd`, and says what is actually uncertain.** After a command that
  changes the filesystem (`mkdir`, `git worktree add`), a `cd` may or may not
  succeed, so the working directory after a following `;` has two possible
  values, and every later command was held as "unresolved" even when nothing in
  it was: `mkdir -p out && cd out; echo done` asked. `:`, `true`, `false`,
  `echo`, `printf` (without options) and `pwd`, written literally on a plain
  call with no redirect, assignment, wrapper or function/eval body, are no
  longer held for that reason alone. Everything else asks exactly as before:
  relative paths and programs, redirects, `printf -v`, `eval`, `command`/`env`/
  `sudo` wrappers, command substitution, and functions or aliases shadowing a
  builtin. When the hold is about the working directory, the reason now says so
  and names the way out (join with `&&`, use `git -C <dir>` or absolute paths,
  or split into separate calls) instead of blaming an unresolved value that is
  not there. Real unresolved values keep the old wording.

### Hooks
- **Fix (#353): the Antigravity hook command no longer breaks under agy's
  `cmd /C` spawn.** agy passes the command line through Go's exec, which turns
  every `"` into `\"`; `cmd.exe` then looked for a program named
  `\"C:/…/guardrail.exe\"` and denied every tool call. A Windows binary path
  that needs no quoting is now written bare, with forward slashes, which both
  `cmd.exe` and a POSIX shell accept. A path with a space keeps its quotes
  (no quote-free spelling exists for it). Claude's spelling is unchanged.
- **Fix (#353): `doctor` now spawns each Antigravity hook command the way agy
  does.** It previously read `hooks.json` and reported "guardrail integration
  registered" while every tool call was denied. Each guardrail-owned command's
  executable is run as `cmd /C <exe> version` through Go's exec (which writes no
  audit record); one that cannot be reached is a WARNING naming the hook, the
  cause and the fix (`guardrail plane enable antigravity`). Windows only; a
  no-op elsewhere.
- **Fix (#358): a binary path containing a space now works under agy when the
  volume has 8.3 short names.** Such a path needs quotes, which agy's `cmd /C`
  spawn cannot deliver, so the Antigravity hook command is written with the
  path's 8.3 short name (`C:/PROGRA~1/…`) instead. When no usable short name
  exists the quoted spelling stays, `doctor` reports it as before, and `setup`
  now warns before arming Antigravity for a path agy cannot spawn.

## v0.23.4-dev (2026-09-25)

### Policy
- **Feature (#351): operator-controlled native web-research enforcement.**
  `guardrail web-research on|off|status` separates strict web controls from
  unrelated protections. Off permits recognized native research, including
  Codex batches and result references, and explicitly disclaims outbound-data
  enforcement. Changes require authenticated operator approval. Verified fresh
  setup records off; existing, missing or invalid configuration stays strict.

### Tests
- Add a read-only Codex execution-contract probe for native Windows and
  WSL/Linux. It records shell/directory requests, actual hook payloads and
  execution evidence separately, including code-mode calls. A successful
  observation never claims Guardrail enforcement or trusted shell metadata.

### Hooks
- **Fix (#349, partial): Codex post-tool policy feedback now states that the
  tool already ran.** It no longer presents an after-the-fact finding as a
  prevented action or pending approval. Policy decisions and blocking feedback
  are unchanged; actionable pre-execution approval remains separate work.
- **Fix (#342): Codex Windows hook commands no longer die in the configured
  shell before reaching Guardrail.** `commandWindows` is now a quote-free,
  encoded PowerShell launcher, so it parses correctly whether Codex is using
  PowerShell or `cmd.exe`. The launcher leaves Codex's stdin inherited instead
  of piping it through Windows PowerShell, which preserves the JSON input
  without a UTF-8 byte-order mark. The evaluator returns documented
  event-specific JSON for Windows policy blocks—including the fail-closed
  refusal when Codex does not identify its command shell—avoiding PowerShell's
  conversion of a nested exit 2 into exit 1. Installed hooks retain the owned,
  inspectable batch wrapper.

### Installation
- **Fix (#324): unattended Windows installs can explicitly defer a disable.**
  `install.ps1 -State disabled -SetupIfInteractive` now installs or updates
  the requested binary but, when stdin is redirected, leaves the current plane
  state unchanged, exits successfully and prints the interactive
  `guardrail setup --state disabled` command needed to finish. Without the new
  switch, the terminal refusal and exit code 2 remain unchanged.
- **Fix (#323): a later Windows uninstall now removes rename-aside leftovers.**
  When `guardrail.exe` is already gone but the install directory contains an
  owned `guardrail.exe.old`, update staging file or install staging file,
  `install.ps1 -Uninstall` sweeps those remnants, removes an empty destination
  from the user PATH and drops the stale Defender exclusion before reporting
  that nothing is installed. A destination that was genuinely empty remains
  untouched, and a shared destination keeps its PATH entry.

## v0.23.3-dev (2026-09-24)

### Installation
- **Fix (#334): Antigravity coverage follows its effective MCP configuration.**
  An absent or empty global `~/.gemini/config/mcp_config.json` now means no
  servers from that source, not a parse/install failure. Default discovery
  merges the global (or legacy CLI) file with every
  `~/.gemini/config/plugins/*/mcp_config.json` bundle, including duplicate
  server declarations, so live plugin-provided tools reach the coverage gate.
  An explicit missing `--config` remains an error. If coverage fails only
  after this setup run already enabled planes, setup reports coverage as
  unknown, continues through selftest and status, and exits success when those
  checks pass; an already-consistent run still treats coverage failure as an
  error.
- **Fix (#335): the ownership-drift reconcile hint now converges.** `setup`
  and `plane enable` include manifest `Missing` and `Stale` entries in their
  shared re-enable rule, and carry that exact repair intent through the
  approval daemon. The approved merge retires records for entries no longer
  present and adopts exact current generated entries that predate the manifest,
  while an ordinary merge still never claims an identical operator-owned rule.
  Doctor now calls a missing manifest entry ownership drift rather than floor
  drift: Codex has no declarative floor, and Claude's current floor can be
  complete while an older recorded hook entry is absent.

### Tests & CI Portability
- **Test: `TestSetupReenablesOnHandlerDrift` asserts the generator's hook
  spelling, not the raw path.** On Windows `HookCommand` writes the binary
  quoted with forward slashes so the hook survives a POSIX shell (#149); the
  test looked for the JSON-escaped backslash path and failed on every Windows
  host while CI's Windows filter never ran it. It now compares against
  `genconfig.HookCommand`, and `TestWindowsSetupReenableWritesTheCrossShellSpelling`
  runs the same re-merge on the Windows CI slice and pins that every hook a
  setup re-enable writes there is quoted and backslash-free.

## v0.23.2-dev (2026-09-24)

### Grants & Approvals
- **Feature (#326, ADR-0030): a first install arms the planes before the
  operator enrolls.** With no operator authenticator enrolled there is nothing
  to approve against, so `guardrail setup` and `guardrail plane enable`
  register the hooks and the permissions floor **without an approval and
  without a terminal**, run the coverage gate and `selftest`, write one
  `operator-action` audit record with `transport: bootstrap`, and end with the
  one-time instruction to `guardrail operator enroll`. The installer therefore
  arms a fresh machine in one unattended run (`chezmoi apply` included), and
  `--no-setup` becomes optional. **The approval-less path can only tighten:**
  `setup --state disabled`, `plane disable`, `recover`, grants, waivers and
  credential management keep exit 3 until a passkey exists, so a deleted
  `authenticators.json` unlocks more guarding and nothing else. No marker, no
  elevation check: the rule is "not enrolled, and the action is enable".
  `doctor` reports `planes armed by bootstrap` until enrollment.
- **Fix (#326): a machine with no enrolled operator now says so instead of
  "approval daemon unavailable".** `approval.Submit` propagates the daemon's
  reply error; `ErrDaemonUnavailable` now means exactly that (nothing answered
  on the socket and none could be spawned), and `SubmitOnDemand` no longer
  respawns a daemon that is live but refused the request. The daemon replies
  `no operator authenticator is enrolled` (`approval.ErrNotEnrolled`, raised by
  the credential store's `BeginAssertion`) when no ceremony can begin.
- **Fix (#326): `setup --state disabled`, `plane disable` and `recover` preflight
  enrollment.** When something needs an approval and no authenticator is
  enrolled they stop before submitting, print `run 'guardrail operator enroll'
  … then '<the command to re-run>'`, and exit **3** — distinct from 1
  (denied/expired/failed) and 2 (usage/no terminal) so installers and dotfiles
  runs can tell "needs enrollment" from a failure. A run with nothing to
  register or remove never needs enrollment and stays exit 0. `install.sh` and
  `install.ps1` pass the code through.
- **Change (#326): `doctor` names the reason.** `operator approvals: disabled
  (no authenticator enrolled; run guardrail operator enroll)` replaces the bare
  `disabled`, which read like a setting.

### Engine Enforcement & Policy
- **Change (ADR-0030): a mediated session cannot invoke guardrail's own
  lifecycle commands.** `P5.self-config`, which already denied the
  after-hours posture switch from a session (directly and through opaque
  interpreter input, ADR-0012), now also denies `guardrail setup`,
  `plane enable|disable`, `operator …` and `recover …`. With the bootstrap no
  longer needing a terminal, this is what keeps an armed plane from
  re-arming, disarming or re-enrolling itself, or registering a different
  binary's hooks. Read-only subcommands (`plane status`, `doctor`,
  `selftest`, `audit`, `version`) stay allowed. The adapters give the same
  "put it in a file" guidance for an opaque mention as they already did.

## v0.23.1-dev (2026-09-23)

### Installation
- **Feature (ADR-0029): `install.sh`, the installer for Linux, macOS and WSL.**
  POSIX `sh`. `sh install.sh --version <tag>` resolves the asset for this
  OS/arch, downloads it with the tag's `SHA256SUMS`, verifies it
  (`sha256sum`, `gsha256sum` or `shasum -a 256`) and installs it to
  `~/.local/bin/guardrail`; any failure leaves the destination untouched.
  An existing binary at or above the `v0.19.2-dev` self-update floor is moved
  with `guardrail update <tag>` instead, and one already at the tag is left
  alone. It then runs `guardrail setup` and exits with its code. Flags:
  `--version` (exact tag, required except with `--uninstall`; `latest` exits 2), `--state
  enabled|disabled`, `--dest`, `--base-url` (URL, `file://` or a directory),
  `--no-setup`, `--uninstall`, `--purge`, `--help`.
- **Feature (ADR-0029): `install.ps1`, the Windows twin.** Windows PowerShell
  5.1 and PowerShell 7, same flags spelled `-Version`, `-State`, … . Adds
  `Unblock-File`, the user-PATH entry, and a Microsoft Defender exclusion for
  the exact `guardrail.exe` path (#146); without elevation it prints the
  `Add-MpPreference` command and continues. `-Uninstall` also removes the
  exclusion, and the PATH entry only when the install directory is empty
  afterwards (it is shared with other tools); a `guardrail.exe` still in use
  is renamed to `guardrail.exe.old`; `-Purge` removes all three Windows state roots
  plus `%USERPROFILE%\.local\share\guardrail`.
- **Feature (ADR-0029): `guardrail setup [--state enabled|disabled] [--planes
  <list>]`, the post-install reconcile.** Re-registers every detected plane
  that is not registered, whose permissions floor drifted, or whose
  registered handlers differ from what this binary generates; consistent
  planes print `already enabled`. One approval for the batch, then
  `doctor --coverage antigravity` (when `agy` is on PATH) and `selftest`, then
  a per-plane status line. `--state disabled` disables every registered plane.
  Needs an interactive terminal (exit 2 otherwise) and refuses to register the
  updater's staging or `.old` path.
- **Fix (#317): a binary swap no longer leaves stale handlers registered.**
  `plane enable` skipped any already-registered plane unless its floor had
  drifted, so an upgrade that changed the hook command shape kept the old
  handlers. `setup` and `plane enable` now share one reconcile rule: they
  compare every owned hook group (event, matcher, handler command and
  timeout) against this binary's and re-merge on any difference. `setup`
  restarts the approval daemon first, so the merge runs in this binary, and
  checks afterwards that the plane converged. Run it after `guardrail
  update` (the installer does).
- **Release: the installers are release assets.** `scripts/build-dist.sh`
  copies `install.sh` and `install.ps1` into `dist/` and lists them in
  `SHA256SUMS`; `release.yml` uploads them and includes them in the build
  provenance attestation.
- **Release: `SHA256SUMS` is normalized to text-mode lines.** Tools that emit
  `<hash> *<file>` (binary mode) are rewritten to `<hash>  <file>`, so every
  line has one shape whichever OS built `dist/`.
- **CI: new `installer` job on ubuntu, macos and windows.** Builds `dist/` and
  runs the `test/installer/` harnesses against it with `--base-url`, no network:
  clean install, already-at-version, tampered and missing checksums,
  `latest` rejected, self-update above and bootstrap below the floor,
  uninstall and purge; `shellcheck -s sh install.sh` on ubuntu; `install.ps1`
  under both PowerShell 7 and Windows PowerShell 5.1.
- **Docs.** README Install is now download → verify → run the installer;
  OPERATIONS.md gains "Install, update, disable, uninstall"; ADR-0029 records
  the contract with the dotfiles. The README's four `gen-config --merge` lines
  are gone.

## v0.23.0-dev (2026-09-23)

### Engine Enforcement & Policy
- **Fix (#282 M1, #288): deny working-tree and repository root deletion.** Semantic
  containment previously allowed recursive/forced deletion of the current working
  directory (`.`), parent (`..`), and repository root (`$PWD`) because they
  resolved inside the repository. `isWorkingTreeDeletion` now checks deletion
  targets against session CWD and repo root; matching targets deny under
  `P1.rm-rf`. Unresolvable operands fail closed to `P3.unresolved`. Deletions of
  subdirectories within CWD and safe-root siblings remain permitted; non-recursive
  `rmdir` retains `P1.rmdir` ask. Honors operand classification: uses effective
  directory from cd tracking (`NF-6`), skips find callbacks (`NF-9`), and respects
  chroot re-rooting (`P3.unresolved`).
- **Fix (#255, #269): judge POSIX paths in POSIX coordinates, denying `rm -rf /`
  on Windows.** Bash command path tokens are POSIX while Windows host paths are Win32.
  `authorizedPath` previously used `filepath`, which treats `/etc` and `/` as
  Win32 relative paths, causing absolute POSIX paths to be misclassified as
  inside the repository. Paths are now evaluated in their source dialect before
  explicit translation, closing 29 adversarial cases (`bash -c`, `busybox`,
  `chroot`, `setsid`, `docker`, `ssh`). `/c/repo` translates to `C:\repo`; `/tmp`
  maps to the host temp root with system temp containment. `mv` source path dialect
  preserved (#283).
- **Fix (#228, #275, #289 M2/M3): classify GitHub CLI porcelain commands.** The
  Engine previously mediated only `gh api` calls while ordinary porcelain commands
  were allowed:
  - `gh repo delete`: **denied** (`P2.gh-repo-delete`).
  - `gh secret set/delete`, `gh variable set/delete`, `gh repo edit`,
    `gh ruleset ...`: ask (`P2.gh-protection`, shared with `gh api` protections).
  - `gh repo archive/rename/transfer`: ask (`P2.gh-repo-admin`).
  - `gh pr merge`: ask (`P2.gh-pr-merge`).
  - `gh release create/delete/edit/upload`: ask (`P6.publish`).
  - `gh workflow run/enable/disable`: ask (`P2.gh-workflow-dispatch`).
  - `gh auth refresh -s ...`, `gh auth login --scopes ...`, `gh auth switch`:
    ask (`P2.gh-auth-scope`).
  - `gh auth logout`: asks (`P2.gh-auth-logout`, M3).
  - `gh ssh-key add/delete`, `gh gpg-key add/delete`: ask (`P2.gh-account-key`, M2).
  - Reads (`gh secret list`, `gh release view`, `gh pr checks`, `gh run view`,
    `gh auth status`, `gh ssh-key list`) and unscoped `gh auth login/refresh`
    remain allowed. Command assignment prefixes (`GH_TOKEN=...`, `env`) are
    stripped before classification (`NF-5b`/`NF-19`).
- **Fix (#228, #252): mutating GitHub repository protections via `gh api` asks.**
  `gh api` calls that create, update, or delete branch rulesets, repository
  bypass actors, actions permissions, or release immutability ask under
  `P2.gh-protection`. Parses HTTP method flags (`-X`, `--method`) and infers
  mutations from body flags (`-f`, `-F`, `--field`, `--raw-field`, `--input`).
  `gh api graphql` containing `mutation` queries asks. Reads stay allowed.
- **Fix (#235, #264): classify credentialed CLIs before they publish, deploy, or bill.**
  `npm publish`, `docker push`, `kubectl apply`, `terraform apply`, `vercel --prod`
  and their mutating operations ask under dedicated family IDs (`P6.publish`,
  `P6.cluster-mutate`, `P6.cloud-mutate`, `P6.deploy`). Reads (`kubectl get`,
  `docker pull`, `terraform plan`, `npm view`) and `--dry-run` remain allowed.
  Known-local Kubernetes contexts (`kind-`, `minikube`, `docker-desktop`,
  `k3d-`, `rancher-desktop`) remain allowed; unstated contexts ask. Cloud CLIs
  enforce unknown-means-ask for mutating commands.
- **Fix (#251, #262): classify the Go toolchain per subcommand.** `go run <remote>`
  and `go mod download` ask as network fetchers; fetcher environment levers
  (`GOPROXY`, `GONOSUMDB`, `GOFLAGS`, `GOSUMDB`, `GOINSECURE`, `GOPRIVATE`) and
  `go mod edit -replace` deny; `go mod edit` asks; `-toolexec`/`-vettool` ask.
  Tokenizer captures shell assignment prefixes for Go fetcher variables.
  `go build` and `go test` remain allowed.
- **Feature (#140, #280): machine power control asks in every shell, never night-relaxed.**
  `shutdown`, `reboot`, `systemctl poweroff` and PowerShell equivalents ask under
  `P1.power-control` and are excluded from overnight relaxation.
- **Feature (#267, ADR-0026): pin built-in and overlay verdict combination by severity.**
  Overlay rules can tighten a built-in rule but never loosen it; equal verdicts
  report the built-in rule attribution.

### Grants & Approvals
- **Feature (#173, #272, #273, ADR-0027): operator-issued grants for one exact command.**
  `guardrail approvals grant --repo <path> --rule <id> --command '<exact-command>'`
  authorizes an exact command string without wildcarding or normalization. Single-use
  by default (`--uses N` raises), 30-minute default TTL (capped at 24h). Interactive
  terminal issuance only, showing verbatim quoted command text. Cannot relax
  outward reach (`capability-external`, `capability-web-search`, `unknown-native-tool`)
  or fail-closed backstops. Both issuance and consumption are audited under
  `ask-allowed-by-operator-grant`; revocable via `guardrail approvals revoke`,
  inspectable via `guardrail approvals list --grants`.
- **Fix (#129, #265): an Ask verdict now specifies which approval path applies.**
  Policy asks explicitly state that no approval URL, daemon, or `approvals` command
  exists for the rule and direct the agent to prompt the operator. Broker asks surface
  the approval URL. Prevents models from hunting for non-existent approval machinery.
- **Feature (#242): machine-readable guidance metadata for deny verdicts.**
  Deny verdicts carry structured metadata for downstream integration tooling.

### Windows Transport & Session
- **Feature (#253, ADR-0025): resident daemon and named-pipe transport on Windows.**
  Persistent resident daemon/broker serves hook evaluations over Windows named pipes
  (`\\.\pipe\`), reducing per-call evaluation latency from process-startup and AV
  scanning overhead to sub-millisecond speeds.
- **Feature (#248, ADR-0024): Windows agent experience improvements.**
  MSYS mount handling, inspectable Codex wrappers, and degraded UX advisories.
- **Fix (#266, #279): serialize local lock contention and separate lock budgets.**
  Local session lock contention is serialized under concurrency, and local vs. OS
  lock budgets are separated to eliminate spurious contention timeouts.
- **Chore (#237, #238): dependency updates.**
  Bumped `mvdan.cc/sh/v3` from 3.10.0 to 3.14.1 and `github.com/gofrs/flock` from 0.12.1
  to 0.13.1.

### Declarative Floor & Reset Work
- **Fix (#278, #282, ADR-0028 Amendment 1): guardrail-owned settings entries are
  precisely removable.** Permission entries are bare strings and bare keys sharing a
  container with the operator's own, so nothing in the file said whose was whose.
  Three consequences: `plane disable claude` removed nothing (its branch handled
  `hooks` only, leaving all 243 floor entries in a file the operator had just asked
  guardrail to stop writing to); `plane disable opencode` removed everything,
  deleting the whole `permission` block *and* the whole `plugin` array — which on a
  real machine **unregisters the operator's own plugins**, live user-data
  destruction independent of the reset; and drift was invisible, 24 entries behind
  on Claude and 42 on OpenCode, discoverable only by regenerating and diffing by
  hand.
  A sidecar manifest in `$XDG_STATE_HOME/guardrail/manifests/<plane>.json`
  (`%LOCALAPPDATA%` on Windows) now records what guardrail wrote. It is the **diff
  of the target document across a merge**, which makes one mechanism cover a string
  in Claude's `permissions.deny[]`, a key in OpenCode's `permission.bash{}` and a
  group in `hooks{}` rather than a schema per config shape.
  The record stores the **prior value**, not just ownership, and that is the
  load-bearing part. Merging does not simply write guardrail's entries: where both
  sides name a pattern the stricter verdict wins, so guardrail *overwrites* an
  operator value that was looser. A manifest recording only ownership would make
  removal delete the key and the operator's setting would be gone — the same harm
  the manifest exists to prevent, reintroduced by the fix for it. Removal restores.
  The diff shape earns a second property: an entry guardrail generated but did not
  actually change, because the operator already had it, produces no diff, so
  guardrail does not claim it and removal leaves it alone.
  The record accumulates across merges. Merging is idempotent and gets run
  repeatedly, so a second merge's diff is empty; writing that would erase the record
  of everything the first wrote and leave the entries orphaned in the settings file.
  Where both describe the same slot the recorded prior wins, since on a re-merge the
  value guardrail sees as prior is its own first write.
  Operator edits are left and reported, never reverted — the value is theirs now.
  Absent manifests are ordinary (every installation predating this has none, and
  state directories get cleared), so removal falls back to hooks by their
  `guardrail-` id, the opencode plugin by basename — the identification the merge
  path already had and the removal path never used — and permission entries by
  regenerating current output and removing only exact matches. The fallback reports
  that it was one, because a degraded removal must not look like a clean one.
  `guardrail doctor` gains an ownership line per installed plane, naming the three
  drift conditions separately since each means something different: entries missing
  from settings, entries present but unclaimed (older output nothing would otherwise
  clean up), and operator-edited entries. A plane with no manifest says so rather
  than reporting clean, because absence of knowledge is not absence of drift.
  This is why the manifest is a precondition and not a follow-up: without it phase 1
  does not remove the floor from anyone's settings file, it only stops generating
  it, and the entries already on disk stay forever.
- **Docs (#282, #287, ADR-0028): settings files are user-owned; enforcement moves to Engine.**
  Four-seat audit confirmed declarative floor rules in plane settings files were a
  drifting, redundant copy of Engine policy. Settings files return to user-owned
  content plus hook registrations only. OpenCode (Phase B: 218 entries) and Claude
  Code (Phase C: 243 entries) scheduled for floor retirement; Antigravity (Phase A: 0
  floor entries) confirmed at target since ADR-0008.
- **Policy (#282, ADR-0028, openai/codex#24453): Codex established as named exception plane.**
  Codex pre-hooks do not dispatch on Windows; its 32 native rules in
  `~/.codex/rules/guardrail.rules` are retained as primary enforcement. Retirement
  is gated on a measurable condition (`guardrail doctor --codex-hooks` observing
  live runtime dispatch), not a calendar date.
- **Feature (#282, #291): engine outage posture is loud instead of silent.**
  SessionStart hook inspects engine self-spawn health and emits a loud warning banner
  when the engine is unreachable, explicitly withdrawing autonomy instructions.
  `guardrail doctor` reports engine reachability.
- **Fix (#282 M4/C1, #297): retire no-op floor classes from Claude and OpenCode.**
  Retired false-positive prefix globs `Bash(dd *)` (blocked harmless file copies)
  and `Bash(git clean -f*)` (blocked `--dry-run`) from Claude and OpenCode generators;
  retained in `CodexRules()`.
- **Test (#249, #256, #271, #274): floor generator verifies glob matches.**
  Generator pairs all floor globs with canonical dangerous commands, failing the
  build on non-matching patterns (#249); caught 23 broken globs (#244). Floor
  mediates GitHub CLI porcelain endpoints (#256), aligns globs with host
  matchers (#271), and translates OpenCode command globs (#274).
- **Fix (#246, #258, #259, #263): Codex diagnostics, tools, and schema drift.**
  Separated Codex hook failure diagnostics from policy denials (#246), retained
  raw hook diagnostics (#258), classified collaboration tools (#259), and gated
  runtime schema drift (#263).

### Recipes (P8)
- **New (#290, #302, #305, #306): the recipe system ships with four recipes.** A
  `[recipes]` schema in `guardrail.toml` enables per-language format-and-lint
  command sets: automatic extension matching for Elixir, and explicit opt-in
  composition for Odoo with project-configured module, test database, and Relax
  NG path (ADR-0009's composition model). Session-completion recipes run on
  Claude's Stop/SubagentStop hooks only; doctor reports other planes as
  explicitly unsupported rather than claiming coverage. Doctor shows recipe
  coverage per plane, and generator output that adds recipe visibility without
  the matching host hook and goldens fails an ADR-0009 invariant test -
  registry visibility is not coverage.

### Tests & CI Portability
- **CI (#312, closes #174): the portable engine suite is mandatory on Windows.**
  The #174 ledger is closed: every Windows-suite failure is fixed, explained, or
  explicitly platform-bounded. The two genuinely host-semantic families (exact
  POSIX CDPATH/`cd -P` behavior, POSIX permission-bit reachability) are
  documented conditional skips; Windows symlink privilege error 1314 is treated
  as an unavailable test capability with assertions retained on hosted Windows
  and POSIX. No tests were deleted. The unfiltered portable engine package now
  blocks Windows CI, so future portability regressions fail loudly instead of
  accumulating as residue.
- **Test (#310): genconfig tests no longer write into the real state directory.**
  `MergePlaneInto` writes an ownership manifest to the state root (#309), so merge
  tests that did not redirect that root wrote manifests onto whatever machine ran
  them -- three turned up on a developer host with `t.TempDir()` targets, found
  while capturing the phase-1 baseline rather than by CI, because runners are
  disposable and never inspect their own state directory afterwards.
  Nothing was mis-enforced: a manifest whose recorded target is not the file being
  operated on is rejected, so `doctor` still reported no manifest for the real
  settings files and removal still used the documented fallback. The guard held;
  the suite simply should not write outside its own temp space.
  Fixed with a package-level `TestMain` redirecting the state root for the whole
  package, rather than adding isolation to each merge test. The manifest tests
  already isolated themselves; the merge tests predate manifests and had no reason
  to, and a test added tomorrow would have the same no reason -- so hermeticity is
  enforced structurally instead of being something each test has to remember. Two
  guards come with it: one that the manifest directory resolves inside the
  redirected root, and one that a real merge actually writes there.
- **Test (#240, #241, #254, #260, #268, #281, #285, #294): host coordinate & child-env isolation.**
  Materialized host-native contract paths (#240, #285, #294); isolated adversarial child
  roots (#241, #260); expected host filesystem root on Windows (#254); toleration for
  concurrent repo walks in child-env guard (#268); enrolled adversarial broker on
  Windows (#281).
- **Test (#284): bound POSIX cd semantics on Windows.**
  Bounded shell-lexical vs host-probing cd resolution under the ADR-0023 seam.
- **CI (#261): expose full portability suite on Windows.**
  Exposed full portability test suite on Windows CI runners.

### Documentation & Operator Guidance
- **Docs (#292): operator release notes for v0.23.0-dev.**
  Added `docs/release-notes/v0.23.0-dev.md` detailing operational policy changes,
  credentialed CLIs, operator grants, and Windows performance.
- **Docs (#282, #296): reset Phase 1 execution & verification checklist.**
  Added `docs/reset-phase-1-checklist.md` providing step-by-step operator runbooks
  for OpenCode and Claude Code floor retirement, doctor verification, and rollback paths.
- **Feature (#236, #276): doctor reports credential posture and operator hardening guide.**
  `guardrail doctor` inspects GitHub scopes, account count, kubectl contexts, and
  credential environment variable names without exposing values; added
  `docs/operator-hardening.md` on token minimization and provider-side boundaries.
- **Feature (#243): audit verdict reporting and ask pressure metrics.**
  `guardrail audit --verdicts` reports policy decisions by rule (deny/ask/allow counts,
  session concentration) and identifies ask fatigue.
- **Docs (#247): error-message discipline.**
  Added documentation on actionable error messages and failure mode prevention.

## v0.22.0-dev
- **Fix (#218): publishing a tag now asks.** The floor and the Engine asked for
  `git push --tags`, `git push * main` and a deletion refspec, but a *named*
  tag push matched none of them: `git push origin v0.21.8-dev` allowed, and a
  premature release pointer went public from a guarded session. The cascade is
  the reason this matters — CI built release assets from the tagged tree, the
  asset was deployed, and cleanup was then blocked, because tag-deletion
  rulesets correctly refuse `git push origin :refs/tags/…` (`GH013`). The gate
  held at deletion and missed at creation, so the wrong pointer was stranded
  until an admin deleted it by hand.
  The Engine now classifies the push *destination*. A destination under
  `refs/tags/` is unambiguous — it says what it is in the command text — so it
  asks exactly, with no false positive to trade away; that case allowed before
  and was the larger hole, since `git push origin HEAD:refs/tags/v1.0.0` states
  its intent plainly and still sailed through.
  A bare destination is genuinely ambiguous: `git push origin v0.21.8-dev` and
  `git push origin some-branch` are the same command shape, and which one it is
  depends on what exists in the repository. The Engine cannot find out — it is
  a pure function of the call it is handed, it never execs and never reads the
  repo — so a version-shaped name is classified on its own shape and the error
  is taken on the asking side. **A branch named `v2.0.0` therefore also asks**,
  which is pinned by a test named for the trade rather than left to be
  discovered. Resolving the name properly would mean running `git rev-parse`
  from a rule that runs on every tool call: a subprocess on the hot path, a
  verdict that depends on state which can change between check and push, and
  the end of "the same call always produces the same verdict".
  The floor gains `git push * v[0-9]*` as an ADR-0022 backstop for when the
  Engine is unreachable, crude by construction since a glob cannot tell a tag
  from a branch. `docs/OPERATIONS.md` gains the tag lifecycle: creation asks,
  deletion is ruleset-blocked, the admin UI is the only retraction path — and
  therefore to check what the tag points at before answering the prompt.
- **One place names the executable suffix, and a guard keeps it that way.**
  Closing out the caution filed with #198: three test files had each
  open-coded `if runtime.GOOS == "windows" { name += ".exe" }` for a helper
  binary they build and then run. The hazard itself is gone repo-wide — a full
  Windows suite now reports zero `executable file not found in %PATH%`, the
  signature of the defect #198 described — so this is consistency rather than
  correctness. It still matters, because the failure mode is neither a compile
  error nor an obviously wrong assertion: a fourth hand-rolled copy works on
  its author's machine and silently misbehaves on the other platform, which is
  exactly how the adversarial corpus went unrun on Windows for so long. All
  three now call `testenv.ExecutableName`, and
  `TestNoTestRollsItsOwnExecutableSuffix` fails if a new copy appears.
  One documented exemption: `update_test.go` asserts the *release asset* name
  the updater downloads, which is part of the published artifact contract
  rather than the host's executable-naming rule.
- **Fix (#174 family K): the output-sanitization fixtures now run on Windows.**
  Tests that assert guardrail neutralizes hostile bytes in its own reports
  build real files whose names carry newlines, tabs and escapes, so a path can
  try to forge an extra status line. Windows cannot create those names, so the
  fixtures failed at `os.Mkdir` long before reaching the assertion and the
  sanitizer went unexercised on the platform whose console rendering differs
  most. Measured on NTFS: `\n`, `\r`, `\t` and ESC are rejected outright, and
  so are the reserved `: < > " | ? *`; `\x7f`, the C1 controls, U+2028, U+2029,
  U+0085 and U+00A0 are all accepted. `testenv.HostilePathSegment` adapts a
  segment to what the host will accept without softening it: the hostile
  characters map to hostile substitutes the sanitizer must still neutralize
  (`\n` to U+2028, ESC to U+009B, which *is* the C1 control sequence
  introducer), and the reserved punctuation maps to inert look-alikes that were
  never the subject. POSIX keeps the canonical bytes, and a path that is never
  created keeps them on every host — there is no filesystem constraint to work
  around, and substituting there would weaken the test. Gating these off on
  Windows would have been the cheaper fix and the wrong one: the property is
  that the *product* neutralizes hostile output, which does not require those
  bytes to survive a round trip through the filesystem.
- **A Windows-reachable sanitizer path is now pinned.** `safetext.SingleLine`
  neutralizes U+2028/U+2029 through its `strings.Fields` join rather than its
  `unicode.IsControl` branch, because those are category Zl/Zp and not Cc. That
  distinction is load-bearing on Windows and nowhere else: `\n` cannot appear
  in an NTFS filename but U+2028 can, so the line-forging attack is reachable
  there *only* through the separators the control branch misses. A refactor
  dropping the join would have reopened it with every C0/C1 test still green.
- **Fix (#191): the approval client now authenticates the pipe server.**
  ADR-0021 promises the OS authenticates the peer, and the owner-only DACL
  delivered that in one direction only: no other user can connect to our pipe,
  but the client never checked who owned the pipe it dialled. On Windows
  `\\.\pipe\` is a flat, world-creatable namespace — the DACL protects the
  object once created but does not reserve the name — so any local process
  could hold the broker's name first and answer in our place. Measured before
  the fix: the client connected to a squatter and a forged
  `status: "approved"` reached the caller's reply struct. `dialPrivate` now
  asks the OS which executable serves the other end
  (`GetNamedPipeServerProcessId` → `QueryFullProcessImageName`) and refuses
  anything that is not this binary, which is the right comparand because the
  daemon is spawned as `os.Args[0] approvals daemon`. The liveness probe uses
  the same answer, so a squatted name is now a named `ErrForeignServer` failure
  instead of being misreported as "approval daemon is already running" — the
  operator could not previously tell an impersonator from their own daemon.
  Image paths are resolved before a mismatch is believed, since the same
  executable has a case-insensitive and an 8.3 spelling and a false mismatch
  would refuse our own daemon.
  **Deliberately not closed, and unchanged by this fix:** a process running as
  the same user can copy the binary and pass the check. That cell is open on
  Unix too — a same-user process can bind the socket path first there, measured
  and recorded on #191 — and it is the cell guardrail's own threat model lives
  in, so it wants an operator decision rather than a check here.
  FILE_FLAG_FIRST_PIPE_INSTANCE was the intended listen-side mechanism but
  go-winio does not expose it; measurement showed a second `ListenPipe` over a
  held name is refused anyway, so the defect was never silent acceptance but
  the misdiagnosis, which is what changed. The probe-to-create window remains
  open and is documented at the call site.
- **Fix (#198): the adversarial corpus now actually runs on Windows.** The
  harness built its probe binary as `guardrail` on every platform. Go does not
  append the executable suffix when `-o` names a file, and Windows resolves
  executables through PATHEXT, so the build produced a file that existed and
  could not be started. Every case failed with `executable file not found in
  %PATH%` quoting an absolute path that was right there on disk, which reads as
  an environment fault rather than a missing suffix — and the 322-case hostile
  corpus had therefore never executed on Windows at all, in CI or locally. A
  second defect was hiding behind it: the harness passed `XDG_STATE_HOME` to
  the spawned binary but not `LOCALAPPDATA`, so the child wrote its audit log
  into the operator's real profile while the assertion read an empty temp
  directory. Both suffix and root handling now come from `internal/testenv`
  (`ExecutableName`, `ChildRootEnv`) rather than a local convention, which is
  the shared helper #174 group D wants across the four packages with this
  shape. `ExecutableName` is idempotent, because `guardrail.exe.exe` is a
  different filename Windows will not run (measured in #178).
  Result: **322 cases execute and 286 pass**, the first real Windows judgement
  of the hostile spellings. The remaining 36 are *not* guardrail gaps — every
  one traces to a corpus fixture whose paths are POSIX-absolute (`cwd: /repo`,
  targets like `/etc` and `/`), which Windows reads as repo-relative, so a
  delete that should land outside the repo lands inside it and is correctly
  allowed. That is #174 group B fixture work and is deliberately not attempted
  here: rewriting a 322-case security corpus alongside a harness fix is how a
  verdict assertion gets quietly weakened. The package stays out of the Windows
  CI job only because those POSIX-shaped fixtures still carry different path
  semantics on Windows.
- **Fix (#199): the browser loopback test no longer hangs the approval
  package.** `TestBrowserLoopbackFailurePath` drives a real browser through the
  `agent-browser` CLI, and none of its four steps was bounded. `CombinedOutput`
  waits for the output pipes to close rather than for the process to exit, and
  `agent-browser open` launches a browser that inherits those handles and keeps
  running — so the wait never ended. The package died on the default
  ten-minute test timeout with a goroutine dump instead of a named failure,
  which is the single largest contributor to Windows full-suite runtime and the
  reason a full run reads as hung. It also masked 30 entries in the #174
  inventory: those were a timed-out package, not 30 portability defects.
  Output now goes to a file rather than a pipe — a file handle is inherited
  just as happily and has nothing to wait on — with a per-step deadline and a
  `WaitDelay` behind it so no route outlives the timeout. The test **passes in
  about three seconds on Windows**, where it had never passed at all, and the
  whole `internal/approval` package now completes in seven.
  The test was also *green where watched and destructive where not*: no CI
  runner has `agent-browser`, so it skipped everywhere it was observed and hung
  only on developer machines. Both skips now say what they leave uncovered, and
  "the CLI is installed but no browser is" — the Linux case, which previously
  failed — is reported as the missing precondition it is rather than as a
  defect.
- **Fix (#139): cmd.exe destructive builtins are now judged.** cmd spells its
  switches with a forward slash, so `del /s /q <dir>` reached the rules as an
  unrecognised command with three path operands and P1 never saw a recursive
  delete; `rd /s /q C:\Windows\System32` allowed. Worse, `cmd /c "<command>"`
  was not unwrapped the way `sh -c` already was, so the wrapper laundered every
  verdict a plane could otherwise trip: `sh -c "rm -rf X"` denied while
  `cmd /c "rm -rf X"` allowed. The cmd builtins are now projected onto the
  POSIX command they stand for and handed to the rule that already owns it, so
  `rm -rf`, `Remove-Item -Recurse` and `del /s` share one containment decision
  and one waiver, and `cmd /c` / `cmd /k` unwrap alongside the POSIX shells.
  `format` and `diskpart` join `P1.mkfs`. Semantics were measured on disposable
  trees rather than assumed, and two measurements narrowed the rule: `rd <dir>`
  without `/s` fails on a non-empty directory, so it keeps the existing
  `P1.rmdir` ask instead of being read as a tree delete, and cmd rejects dash
  switches outright, so `del -s -q` is not a shape to model. Switch names are
  enumerated per command rather than accepting any `/token`, because a leading
  slash is an absolute path on POSIX — reading `/etc` as an unknown switch
  would have consumed the operand and left the delete with nothing to judge.
  A `format` call counts only with a drive-letter operand or one of format's
  own switches, so a POSIX code formatter of the same name is untouched.
- **doctor's unquoted-space detection is structural, not a guess.** It asked
  whether the token after the first space carried a separator, which read
  `/home/u/my file hook claude` as safe — a gap #155 shipped with, named at
  review. `UnquotedShellHazard` only ever sees guardrail's own floor commands,
  and those have a known shape (`<binary> hook <plane> …`), so the question is
  no longer the unanswerable "is `a b` one path or a command and an argument"
  but "is `hook` the word right after the executable". Two boundaries stay
  deliberate and are pinned by tests: a command with no `hook` word falls back
  to the older signal rather than inventing a hazard, and a path whose final
  component is literally `hook` is known residue.
- **Fix (#178): a trailing dot or space no longer hides a command from its
  rule.** Win32 strips both while resolving a path, so a binary spelled with
  either still runs, while `head()` stripped one `.exe` and nothing else,
  compared the remaining name, matched nothing, and allowed. Every family keyed
  on a command name was affected: `P1.rm-rf`, `P1.privesc`, `P1.mkfs`,
  `P6.egress`, and `P5.self-config`, the last of which let a plane turn off its
  own night mode. The trim is applied only where Win32 resolution applies — a
  drive-lettered or backslash path anywhere, or any path on a Windows host — so
  a POSIX file legitimately named `rm.` is still judged as itself. Deliberately
  *not* denied, because they do not execute: a bare `rm.` or `Remove-Item.`
  (PATH and cmdlet lookup do not strip), and `rm.exe.exe` (a different
  filename). Operand-keyed families were never affected.
- **PowerShell `$env:NAME` no longer forces an ask on an ordinary read.** The
  bash tokenizer splits the reference at the wrong place — `$env` is an unset
  variable to it and everything after is literal — so every read through one
  asked, however ordinary. The Engine still does not learn what the variable
  holds (ADR-0012 rules out simulating an environment); it stops raising
  `P3.unresolved` for the prefix alone and lets the path families judge the
  literal tail. `$env:USERPROFILE\.ssh\id_ed25519` still denies
  `P4.secret-path`, a write or delete through `$env:` keeps its ask because
  containment needs the root the variable withholds, and a redirect is never
  forgiven. A read now reaches the same verdict as the literal path it stands
  for, which it did not before.
- **CI's windows job can no longer hide a Windows test.** That job runs a fixed
  package list filtered by `-run 'Windows|BOM|ReadJSONObject'`, not the full
  suite, so a Windows test is invisible there unless its name matches *and* its
  package is listed. Both halves had been missed: eight PowerShell tests for
  #111 would have run only on ubuntu and macos until they were renamed, and
  `internal/policy` has carried two Windows-named tests the job never ran.
  Two guards now read `ci.yml` itself — so they cannot drift from what CI does
  — and assert that every Windows-named test file contributes a selected test,
  and that every selected test lives in a package the job runs.
  The guards respect build constraints, and a package deliberately outside
  the job is exempted with a written reason rather than silently skipped —
  `test/adversarial` is POSIX-shaped and its harness builds the probe binary
  without a `.exe` suffix.
- **`internal/policy` joins the Windows job, and its tests stop reading the
  operator's real config.** `writeOperatorConfig` and three merge tests
  sandboxed only `XDG_CONFIG_HOME`, but `operatorConfigDir` reads `APPDATA`
  on Windows — so on a Windows host these tests were loading
  `%APPDATA%\guardrail\waivers.toml`, the machine's actual operator grants.
  Non-hermetic, and the reason the package could not join the job. With both
  roots sandboxed and four grant paths spelled host-absolutely (grant matching
  requires `filepath.IsAbs`, and `/repo` is absolute only on POSIX), all seven
  filter-selected policy tests pass on Windows.
- **Fix: `guardrail selftest` passes on a Windows host.** Both codex probes
  carried a hardcoded `/tmp` cwd, which is a relative path on Windows, so
  codex's fail-closed adapter rejected them as unparseable — the plane's
  selftest reported nothing about enforcement either way. Their cwd is now
  `os.TempDir()` and the destructive probe spells the filesystem root the way
  the host does (`rm -rf /` is a cwd-relative delete on Windows). The claude
  probe count is read from the matrix instead of hardcoded at 7, which a
  Windows host exceeds. Six Windows test failures fixed; the whole matrix now
  has a `Windows`-named regression guard, because CI's windows job selects
  tests by name and could not see any of this.
- **PowerShell destructive cmdlets are covered (#111, P1)**: `Remove-Item`
  and its aliases project onto the `rm` rule — one containment decision,
  one waiver, both spellings — honouring `-WhatIf`, parameter prefixes
  (`-rec`, `-fo`), `-Path`/`-LiteralPath` binding, and leaving POSIX
  `rmdir` to `P1.rmdir`. `Format-Volume`/`Clear-Disk`/`Remove-Partition`/
  `Initialize-Disk` join the `P1.mkfs` family; `Set-ExecutionPolicy
  Bypass|Unrestricted` asks. Measured before: every one allowed.
  P4's secret tier already covered cmdlets — it keys on operands, not
  command names — so #111's P4 premise was wrong.
- **PowerShell egress and dynamic eval are covered (#111, P6)**:
  `Invoke-WebRequest`/`Invoke-RestMethod` and their aliases join the
  egress allowlist, the download-pipe-shell walk (`iwr … | iex` is
  `curl … | sh`), and P7's network signal; `-Uri` binds the destination
  and every other value-taking parameter consumes its own argument, so
  `-OutFile payload.exe` is a file and not a host. Bare
  `Invoke-Expression` asks under a new `P6.dynamic-eval`: its argument is
  PowerShell source, and reading it with a POSIX shell parser would be a
  guess. Parity with `curl` is asserted, including for destinations the
  analyser cannot read. **#111's enforcement gap is closed.**
- **`guardrail selftest --evidence claude`**: registration is a claim, an audit
  record is evidence. ADR-0020 built this gate for codex; #149 showed claude
  needed it just as badly — a hook that registered and could not spawn read as
  green in `doctor` for four days while nothing was enforced. The gate opens on
  two distinct pre-hook records from one real session, and `doctor`'s claude
  line now reads "registered but NEVER OBSERVED FIRING" until it does. On the
  machine that found #149 it reports `claude=2774 synthetic=2774 eligible=0` —
  every claude record in the log was a fixture or a probe.
  Unlike codex's explicit prefix denylist, the claude gate requires a
  UUID-shaped session id: claude's fixture ids are ad-hoc (`night-claude`,
  `trifecta-sess-1`, `../unsafe`, `c1`), a denylist that misses one opens the
  gate falsely, and that is the failure class the gate exists to catch. The
  caveat is operator-facing only — it stays out of the lifecycle's ownership
  string and the SessionStart line, because a newly enrolled plane has no
  records yet and is not drifted. The scanner is shared with codex's gate,
  which keeps every count, the exact-session filter and the expected-tool
  assertions #165 added.
- **Fix (P0, #149): claude and antigravity hooks could not spawn on Windows.**
  `gen-config` concatenated the bare binary path, so the floor registered
  `C:\Users\u\.local\bin\guardrail.exe hook claude`. A POSIX shell reads every
  backslash as an escape, the spawn failed as `command not found`, and a
  PreToolUse hook that cannot spawn is a silent no-op — registered, green in
  `doctor`, enforcing nothing. Measured on a Windows host: **not one real
  Claude Code session in 3,896 audit records across four days**, while
  opencode and antigravity (which spawn the binary directly, with no shell)
  were mediated normally. All hooked planes now render through one
  `HookCommand`: Windows paths as `"C:/…/guardrail.exe"` (double quotes and
  forward slashes, the spelling cmd.exe and POSIX shells both accept), and a
  POSIX word quoted only when a shell would act on it. **POSIX output is
  unchanged** — `guardrail hook claude` and `/usr/local/bin/guardrail hook
  claude` still render exactly as before, so no existing floor drifts and the
  distinction that only opencode pins an absolute binary is preserved. codex
  is untouched: it already quoted correctly, and its Windows spelling goes
  through the `commandWindows` key its runtime supports.
- **`doctor` no longer reports green for a hook it cannot spawn.** Registration
  and execution are different claims, and only the first was ever checked. A
  floor whose command is an unquoted path containing a backslash or a space now
  reads "guardrail hook registered but CANNOT SPAWN — … Nothing is being
  enforced".
- **macOS is a first-class platform**: CI runs the full POSIX suite on
  ubuntu, windows, and macos. Two real engine bugs fixed (temp-root
  symlink divergence, operator-config grant matching); symlink-escape
  detection now file-identity-based and spelling-tolerant; concurrent
  grant fixtures stress-verified (100 runs).

## v0.20.26-dev
- Read-only guardrail status is allowed from sessions (exact three-word
  command, everything adjacent still denied); ADR-0021 records the Windows
  approval broker design (named pipe, owner-only DACL, lift order a-d).

## v0.20.25-dev
- ADR-0019 updated with the REPL/JavaScript mediation probe (Deny stands,
  upgrade condition recorded); claude selftest probes expanded to 7
  (serena MCP deny, delegation allow, external ask); docs/OPERATIONS.md
  runbook born.

## v0.20.24-dev
- Antigravity selftest probes expanded to 7: delegation, timer typing,
  MCP registry projection, meta-dispatch. Every ADR invariant is now
  behaviorally pinned (0013/0017/0018/0019).

## v0.20.23-dev
- guardrail selftest --evidence codex: live-mediation evidence gate
  (ADR-0020) — two distinct post-binary records in one non-synthetic
  session opens the approval-flow ADR precondition.

## v0.20.21-dev
- CHANGELOG catch-up (this release's actual change).

## v0.20.20-dev
- **Fix:** post-update verification (doctor + selftest) execs the freshly
  installed binary instead of running in-process — the running process is
  still the superseded release and recorded passes for the wrong version.
  Same hazard class as the daemon shutdown fix in v0.19.11.

## v0.20.19-dev
- `guardrail update` names the release-asset race: a 404 right after tagging
  says "assets may still be publishing; retry in a minute".

## v0.20.18-dev
- SessionStart asks for a selftest until one passes on the installed release
  (marker records the release that passed, operator-owned); `guardrail update`
  runs doctor + selftest on the new binary.

## v0.20.17-dev
- `guardrail audit`: whole-history summary across rotated segments; audit
  rotation at 20MB keeping 3; selftest idempotent across repeated runs
  (unique session IDs); hygiene bundle (gitignore graft/.serena, CI sows
  /tmp/.git, package test HOME sandbox, CHANGELOG born).

## v0.20.16-dev
- `guardrail selftest`: embedded probe matrix verifies installed enforcement
  behavior per plane (allow/deny/night-preserved asks, MCP projection).

## v0.20.15-dev
- `doctor --coverage codex --schema <path>`: schema-driven coverage inventory
  (codex plane).

## v0.20.14-dev
_(skipped; tag reused during integration)_

## v0.20.13-dev
- **Fix (P0):** genconfig emits `planecontract` hook matchers, not stale
  copies — `plane enable` can no longer regress live `*` matchers.
- `doctor --coverage antigravity`: MCP config + session declaration inventory.
- ADR-0019: static boundary verification vs dynamic meta-dispatch.

## v0.20.12-dev
- `doctor --coverage claude`: scans the installed Claude Code bundle;
  surfaced and contracted `SendUserMessage` (SafeControl) and
  `JavaScript`/`REPL` (Deny, unverified mediation).

## v0.20.11-dev
- `guardrail approvals list|approve <id>`; request TTL 5→15 minutes. The
  socket can present a ceremony but never complete one (invariant preserved).

## v0.20.10-dev
- **Fix (P0):** night mode never relaxes outward-reach asks
  (`capability-external`, `capability-web-search`, `unknown-native-tool`).
- Claude unknown-tool posture: allow → ask. ADR-0018 (External tier).

## v0.20.9-dev
- MCP registry: pathless read queries scope to the working directory;
  mutations keep required-path fail-closed.

## v0.20.8-dev
- MCP family registry (serena, graft) with argument projection; opencode
  unknown tools ask instead of allowing. ADR-0017. Closes the coverage-audit
  finding that MCP mutations ran with zero path evaluation.

## v0.20.7-dev
- Antigravity `schedule` typing: one-shot timers allow, cron/ambiguous ask.

## v0.20.6-dev
- Text-mention taxonomy (`P4.secret-in-text`, NightMentionReason): Deny with
  Write/Edit redirection instead of dead-end guidance.

## v0.20.5-dev
- **Fix:** plane enable treats a stale permissions floor as drift and
  re-merges (ground-truth comparison).

## v0.20.4-dev
- Approved grants are applied by the broker and never re-run;
  `operator-action-satisfied` short-circuit. Codex mediation probes.

## v0.20.3-dev
- **Fix:** repo discovery stops at the System temp root boundary
  (`GIT_CEILING_DIRECTORIES` + engine walk); the `/tmp/.git` lesson.

## v0.20.2-dev
- Antigravity native parity: typed paths, drift hardening, delegation
  allowed with runtime evidence (ADR-0013).

## v0.20.1-dev
- Claude parity: MultiEdit/NotebookEdit evaluate every path;
  `CapabilityExternal` for blanket-denied tools; egress terminal command.

## v0.20.0-dev
- **Codex becomes a Guardrail plane**: contract, adapter, native escalation
  floor (ADR-0016), lifecycle, diagnostics. Unknown tools fail closed.

## v0.19.13-dev
- `guardrail recover <repair>`: predefined, WebAuthn-gated repairs for
  protected machinery with timestamped backups.

## v0.19.12-dev
- OpenCode asks answered by the host permission dialog (ADR-0015); retry
  inference demoted to fallback.

## v0.19.11-dev
- Help alignment; `guardrail update` retires a live approval daemon (no
  superseded-code window).

## v0.19.10-dev
- Help decluttering; plane lifecycle absorbs unmarked legacy hook groups.

## v0.19.9-dev
- **Fix:** unmarked-entry detection matches every guardrail binary form
  (`.test`, `.exe`, absolute paths); structural test HOME sandbox for plane
  tests.

## v0.19.8-dev
- **Fix:** enable absorbs unmarked legacy Claude hook groups; reconciliation
  treats their presence as drift.

## v0.19.7-dev
- **Fix:** plane CLI observes the broker's `completed` terminal status (the
  hang); help column alignment.

## v0.19.6-dev
- Batched egress grants: one passkey for an exact domain list, all-or-nothing
  application.

## v0.19.5-dev
- Delegation allowed on planes with in-process enforcement (ADR-0013);
  typed `apply_patch` path extraction; `guardrail update`.

## v0.19.4-dev
- Same-version `guardrail update` is a verified no-op.

## v0.19.3-dev
- Plane lifecycle batches into one approval; steady state prompts nobody.

## v0.19.2-dev
- Actionable per-rule Deny guidance across all planes.

## v0.19.1-dev
- `guardrail plane status|enable|disable` lifecycle (WebAuthn-gated,
  ownership-safe removal).

## v0.19.0-dev
- WebAuthn operator approvals: broker, browser ceremony, audit attribution.
