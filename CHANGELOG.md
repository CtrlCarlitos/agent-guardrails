# Changelog

All notable changes to agent-guardrails. Format: one section per release;
within a release, grouped by theme. Breaking changes are called out
explicitly in **Breaking** notes.

## Unreleased

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
