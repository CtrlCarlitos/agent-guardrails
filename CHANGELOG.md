# Changelog

All notable changes to agent-guardrails. Format: one section per release;
within a release, grouped by theme. Breaking changes are called out
explicitly in **Breaking** notes.

## v0.20.27-dev
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
