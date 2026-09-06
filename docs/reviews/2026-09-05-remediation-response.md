# Remediation Response to the 2026-09-04 Adversarial Review

## Scope and answer

This response answers the complete finding index in the
[2026-09-04 adversarial review](./2026-09-04-adversarial-review.md), whose build
under test was `b109b33`+ and whose scope also included the separate chezmoi
installer. The latest reviewed and published Engine source boundary is clean
commit
[`a2965681e4ea552f8b29b329fd8b6a2ee513a395`](https://github.com/CtrlCarlitos/agent-guardrails/commit/a2965681e4ea552f8b29b329fd8b6a2ee513a395):
the local and remote `v0.11.0-dev` tags resolve to that hash, and the GitHub
Release for `v0.11.0-dev` publishes six platform binaries plus `SHA256SUMS`.
Phase 2 is complete on `main` after that published boundary. `v0.12.0-dev` is
planned for the Phase 2 publication, but it has not been created or pushed; no
Phase 2 publication is claimed by this response. Phase 1 is published at
`v0.9.0-dev` (`aa66b99615a4ba3384ffb5a661bcfebe03f7c181`).

The honest executive answer is **not all findings are addressed**. Phase 1
closed the normalization and self-protection fixes assigned to it. Phase 3 and
its whole-review hardening repaired the Overlay trust model and related
cross-plane failures. Phase 2 closed its token normalization, git, Docker,
egress, wrapper, destructive-primitive, working-directory, and regression-lock
work. Only Phase 4 findings remain outstanding in this repository. M-9 remains
partially fixed because its external chezmoi deployment work is not merged,
applied, or pushed. The current ledger is 27 fixed, 1 partially fixed, and 11
outstanding across 39 indexed entries.

The protection described here is at the static plane tool-call boundary. The
Engine evaluates operations visible in an attempted tool call, including
resolved or visibly named targets. It is **not an operating-system sandbox**.
Arbitrary same-user code can still construct a target dynamically so that the
target is absent from the command text; that limitation is explicit in
[ADR-0010](../adr/0010-operator-scoped-loosening.md#L50-L55) and the
[hardening design](../superpowers/specs/2026-09-05-phase3-whole-review-hardening-design.md#L8-L17).

## Status summary

The CRITICAL count includes the 16 numbered CR findings and all three addendum
bullets as distinct ledger entries.

| Severity | Fixed | Partially fixed | Outstanding | Total ledger entries |
|---|---:|---:|---:|---:|
| CRITICAL | 18 | 0 | 1 | 19 (16 numbered findings plus 3 addendum bullets) |
| HIGH | 7 | 0 | 4 | 11 |
| MEDIUM | 2 | 1 | 6 | 9 |
| **Total** | **27** | **1** | **11** | **39** |

## CRITICAL ledger

| Finding | Status | Remediation | Current source and regression evidence | Residual risk |
|---|---|---|---|---|
| **CR-1 Absolute-path invocation bypasses every rule — RC2** | **Fixed** | Phase 1, `v0.9.0-dev` | Command heads are reduced with `path.Base` in [`rules_bash.go:12-17`](../../internal/engine/rules_bash.go#L12-L17) and used across the Bash, git, Docker, and egress checks. Exact `/bin/rm`, `/usr/bin/sudo`, `/sbin/mkfs.ext4`, git, and curl locks are in [`rules_bash_test.go:18-47`](../../internal/engine/rules_bash_test.go#L18-L47); BusyBox and absolute launcher coverage is at [lines 50-85](../../internal/engine/rules_bash_test.go#L50-L85). | - |
| **CR-2 Quoting any operand defeats matching — RC1** | **Fixed** | Phase 1, `v0.9.0-dev` | `extractSimples` stores literal argv and redirect text and marks unresolved words in [`tokenize.go:49-125`](../../internal/engine/tokenize.go#L49-L125); unresolved words ask without masking stronger Verdicts in [`rules_bash.go:29-60`](../../internal/engine/rules_bash.go#L29-L60). Quoted argv and redirect regressions start in [`tokenize_test.go:44-87`](../../internal/engine/tokenize_test.go#L44-L87), with complete end-to-end reproductions in the adversarial corpus. | - |
| **CR-3 `cd` is not tracked — relative operands resolve against the hook's cwd** | **Fixed** | Phase 2; `v0.12.0-dev` planned, not published | `Normalize(command, cwd)` records the effective cwd on each `Simple` and conservatively marks unresolved directory state ([`tokenize.go:15-25`](../../internal/engine/tokenize.go#L15-L25), [lines 1683-1696](../../internal/engine/tokenize.go#L1683-L1696)); Bash and path checks consume the statement cwd through [`simpleCwd`](../../internal/engine/rules_bash.go#L763-L784). Same-shell, isolated-scope, path-effect, and normalization locks start in [`rules_bash_test.go:103-223`](../../internal/engine/rules_bash_test.go#L103-L223) and [`tokenize_test.go:1114-1209`](../../internal/engine/tokenize_test.go#L1114-L1209). | - |
| **CR-4 Redirect-only statements are discarded** | **Fixed** | Phase 2; `v0.12.0-dev` planned, not published | `extractSimples` retains statements that have redirects without call arguments and classifies read/write directions ([`tokenize.go:49-95`](../../internal/engine/tokenize.go#L49-L95)); `checkBash` sends empty-argv simples through redirect policy ([`rules_bash.go:41-58`](../../internal/engine/rules_bash.go#L41-L58)). Bare, descriptor, append, sibling-deny, and normalization locks are in [`rules_bash_test.go:368-407`](../../internal/engine/rules_bash_test.go#L368-L407) and [`tokenize_test.go:132-181`](../../internal/engine/tokenize_test.go#L132-L181). | - |
| **CR-5 `git --git-dir <path>` (space form) bypasses every git rule** | **Fixed** | Phase 2; `v0.12.0-dev` planned, not published | Both git subcommand helpers share the complete reviewed value-global table, and unknown long globals fail closed after stronger subcommand Verdicts are evaluated ([`rules_bash.go:316-404`](../../internal/engine/rules_bash.go#L316-L404), [`rules_git.go:9-15`](../../internal/engine/rules_git.go#L9-L15), [lines 130-134](../../internal/engine/rules_git.go#L130-L134)). Space, attached, valueless, unknown, and read-only controls are locked from [`rules_git_test.go:411`](../../internal/engine/rules_git_test.go#L411). | - |
| **CR-6 Force-push and remote-branch-delete via refspec** | **Fixed** | Phase 2; `v0.12.0-dev` planned, not published | Push argument parsing consumes option values, always classifies the first positional operand as the repository, and evaluates only later positional operands as refspecs. `--repo` supplies a fallback repository only when no positional operand exists; a positional repository takes precedence regardless of option ordering. Leading `+`, empty-source deletion, and destination-side protected refspecs receive the required Verdicts ([`rules_git.go`](../../internal/engine/rules_git.go)). Attached, split, abbreviated, mixed-order, end-of-options, negation, positional-precedence, and benign controls are in [`rules_git_test.go`](../../internal/engine/rules_git_test.go). | - |
| **CR-7 Path dot-segments defeat every leaf-literal glob — RC3** | **Fixed** | Phase 1, `v0.9.0-dev` | Glob input is slash-normalized and `path.Clean`ed before full-path and basename matching in [`rules_path.go:676-687`](../../internal/engine/rules_path.go#L676-L687). Dot, repeated-separator, and parent-segment cases are locked in [`rules_path_test.go:52-66`](../../internal/engine/rules_path_test.go#L52-L66) and the adversarial corpus. | - |
| **CR-8 Write channels other than redirects are invisible — RC4** | **Fixed** | Phase 1, `v0.9.0-dev` | Known destination-taking mutators, all-target mutators, `dd of=`, and `sed -i` feed path checks through [`rules_path.go:396-428`](../../internal/engine/rules_path.go#L396-L428). Phase 2 added strict destination parsing and safe-root enforcement for the reviewed mv/cp/ln/tee/install/rsync channels ([`rules_bash.go:64-108`](../../internal/engine/rules_bash.go#L64-L108)). | -; CR-9's unlisted readers and H-10's unknown tools remain separate Phase 4 gaps. |
| **CR-9 Secret reads via any command outside the 14-name `pathReaders` list — RC4** | **Outstanding** | Phase 4 | Bash read candidates are still collected only when the command basename is in the closed `pathReaders` map ([`rules_path.go:15-19`](../../internal/engine/rules_path.go#L15-L19), [lines 73-97](../../internal/engine/rules_path.go#L73-L97)). There is no closing regression for cp/base64/tar/dd/openssl/jq/python reads. | Any unlisted reader or encoded argument channel can still read a secret path without P4 seeing it. |
| **CR-10 Scheme-less URL fails host extraction open → egress bypass** | **Fixed** | Phase 2; `v0.12.0-dev` planned, not published | Network option parsing identifies curl/wget targets, host extraction retries scheme-less operands as URL authorities, and malformed, ambiguous, or missing hosts deny rather than skip ([`rules_net.go:98-119`](../../internal/engine/rules_net.go#L98-L119), [lines 504-597](../../internal/engine/rules_net.go#L504-L597)). Scheme-less, option-value, fail-closed, localhost, and allowlist locks are in [`rules_net_test.go:469-519`](../../internal/engine/rules_net_test.go#L469-L519) and [lines 754-778](../../internal/engine/rules_net_test.go#L754-L778). | - |
| **CR-11 Fetch-then-execute with a stage in between — and CR-10 makes it unauthenticated** | **Fixed** | Phase 2; `v0.12.0-dev` planned, not published | Fetch-to-interpreter detection compares AST-derived pipeline IDs and stage order across all later simples, not adjacency ([`rules_net.go:24-49`](../../internal/engine/rules_net.go#L24-L49)). Intermediate-stage and pipeline-boundary controls are locked in [`rules_net_test.go:50-114`](../../internal/engine/rules_net_test.go#L50-L114), with nested control-flow coverage following in the same file. | - |
| **CR-12 Session-id path traversal writes outside the state dir** | **Fixed** | Phase 1, `v0.9.0-dev` | `Path`, `Load`, and `Save` reject empty, dot, separator, and `..` IDs in [`session.go:35-75`](../../internal/session/session.go#L35-L75). The exact traversal is contained and checked for both write and read in [`session_test.go:50-109`](../../internal/session/session_test.go#L50-L109). | - |
| **CR-13 `docker compose -f` and the whole prune family** | **Fixed** | Phase 2; `v0.12.0-dev` planned, not published | Docker-family option parsing derives command-word chains for Docker, docker-compose, Podman, and nerdctl before matching compose down and prune families; parsed run options retain an explicit `--entrypoint`, which is prepended to post-image arguments before nested Bash checks ([`rules_bash.go`](../../internal/engine/rules_bash.go), [`tokenize.go`](../../internal/engine/tokenize.go)). Global, Compose, alternate-frontend, prune, run/exec, entrypoint, and malformed-value locks are in [`rules_bash_test.go`](../../internal/engine/rules_bash_test.go) and [`tokenize_test.go`](../../internal/engine/tokenize_test.go). | - |
| **CR-3 addendum: `waive` was unbounded.** | **Fixed** | Phase 3, `v0.11.0-dev` | Operator config grants are exact per cleaned absolute repository and the three fail-closed backstops are immutable ([`operator.go:13-31`](../../internal/policy/operator.go#L13-L31), [lines 97-126](../../internal/policy/operator.go#L97-L126)); Merge drops unauthorized Waiver requests ([`merge.go:96-108`](../../internal/policy/merge.go#L96-L108)). Unit locks are in [`merge_test.go:86-163`](../../internal/policy/merge_test.go#L86-L163) and [`operator_test.go:289-309`](../../internal/policy/operator_test.go#L289-L309); hostile-Overlay end-to-end evidence is in [`overlay_test.go:15-120`](../../test/adversarial/overlay_test.go#L15-L120). | - |
| **Slots widened globally, not repo-scoped.** | **Fixed** | Phase 3 implementation at `v0.11.0-dev`; evidence completed in Phase 2 | `secret_allow` and `audit_log` require exact-repository Boolean grants, while each egress entry requires an exact-repository, exact-entry grant ([`operator.go:21-31`](../../internal/policy/operator.go#L21-L31), [`operator.go:97-126`](../../internal/policy/operator.go#L97-L126), [`merge.go:65-94`](../../internal/policy/merge.go#L65-L94)). Safe roots require lexical and resolved repository containment ([`merge.go:41-63`](../../internal/policy/merge.go#L41-L63)), and secret allowance does not bypass the following symlink check ([`rules_path.go:41-51`](../../internal/engine/rules_path.go#L41-L51)). Exact authorization and containment unit locks remain in [`merge_test.go:132-426`](../../internal/policy/merge_test.go#L132-L426); [`TestAuthorizedSecretAllowStillBlocksSymlinkEscape`](../../test/adversarial/overlay_test.go#L211-L296) now proves the authorized `secret_allow = ["**"]` plus escaping-symlink combination denies with `P4.symlink-escape` and a matching audit record. | - |
| **"Logged" did not mean visible.** | **Fixed** | Phase 3, `v0.11.0-dev` | Merge warnings are included in Claude's SessionStart posture ([`hook.go:77-96`](../../cmd/guardrail/hook.go#L77-L96)) and universally in `guardrail doctor` ([`doctor.go:59-85`](../../cmd/guardrail/doctor.go#L59-L85)). Visibility and sanitization are locked in [`hook_test.go:717-766`](../../cmd/guardrail/hook_test.go#L717-L766) and [`doctor_test.go:79-145`](../../cmd/guardrail/doctor_test.go#L79-L145). OpenCode and Antigravity have no SessionStart posture; their generated integrations expose only pre-tool, or pre/post, events ([`opencode_plugin.js:43-55`](../../internal/genconfig/opencode_plugin.js#L43-L55), [`antigravity.go:7-31`](../../internal/genconfig/antigravity.go#L7-L31)). | - |
| **CR-14 The agent can write the file that configures its own guard** | **Fixed** | Phase 1, `v0.9.0-dev` | Engine self-config globs include `guardrail.toml`, `.guardrail`, OpenCode, Antigravity, and installed-binary paths in [`rules_path.go:468-497`](../../internal/engine/rules_path.go#L468-L497). Read/write behavior is locked in [`rules_path_test.go:232-286`](../../internal/engine/rules_path_test.go#L232-L286), with corresponding Claude/OpenCode Declarative floor tests in [`claude_test.go:99-134`](../../internal/genconfig/claude_test.go#L99-L134) and [`opencode_test.go:343-378`](../../internal/genconfig/opencode_test.go#L343-L378). | - |
| **CR-15 One Bash call removes the guard permanently — RC4** | **Fixed** | Phase 1, `v0.9.0-dev` | Argument-based mutator destinations flow into protected-path checks through [`rules_path.go:396-447`](../../internal/engine/rules_path.go#L396-L447); guard machinery and the installed binary are protected at [lines 468-497](../../internal/engine/rules_path.go#L468-L497). Exact settings removal and binary replacement families are locked in [`rules_path_test.go:793-947`](../../internal/engine/rules_path_test.go#L793-L947) and the adversarial corpus. | - |
| **CR-16 opencode: `$GUARDRAIL_BIN`/`$PATH` bypass, and `--binary` is silently discarded** | **Fixed** | Phase 1, `v0.9.0-dev` | The generated Adapter receives a JSON-escaped absolute binary path and accepts only an explicit allow response in [`opencode_plugin.js:8-40`](../../internal/genconfig/opencode_plugin.js#L8-L40). Exact-path execution and empty/malformed/unknown response locks are in [`opencode_test.go:180-309`](../../internal/genconfig/opencode_test.go#L180-L309). | - |

The root-cause picture is therefore narrowed: RC1, RC2, and RC3 are fixed. RC4
is split into fixed reviewed mutator and destructive-primitive channels
(CR-8/CR-15/H-4) and still-open reader/unknown-channel coverage (CR-9/H-10),
which is assigned to Phase 4.

## HIGH ledger

| Finding | Status | Remediation | Current source and regression evidence | Residual risk |
|---|---|---|---|---|
| **H-1 A junk wrapper flag downgrades DENY to ASK** | **Fixed** | Phase 2; `v0.12.0-dev` planned, not published | Wrapper-normalization errors now retain only the affected statement as unresolved while siblings continue ([`tokenize.go:1739-1767`](../../internal/engine/tokenize.go#L1739-L1767)); `checkBash` aggregates the strongest unwaived Verdict, so deny outranks ask ([`rules_bash.go:29-60`](../../internal/engine/rules_bash.go#L29-L60)). Both statement orders, standalone unresolved input, and redirect preservation are locked in [`rules_bash_test.go:92-101`](../../internal/engine/rules_bash_test.go#L92-L101), [lines 354-366](../../internal/engine/rules_bash_test.go#L354-L366), and [`tokenize_test.go:565-605`](../../internal/engine/tokenize_test.go#L565-L605). | - |
| **H-2 `.env.example` basename-matching neutralizes the strongest globs** | **Outstanding** | Phase 4 | `SecretAllow` uses the same matcher as deny globs ([`rules_path.go:100-109`](../../internal/engine/rules_path.go#L100-L109)), and that matcher still falls back to basename at [lines 676-687](../../internal/engine/rules_path.go#L676-L687). Current tests explicitly allow `.env.example` but do not prohibit the reviewed cross-directory laundering ([`rules_path_test.go:12-49`](../../internal/engine/rules_path_test.go#L12-L49)). | A permitted basename can still override a stronger full-path secret classification, including through a symlink. |
| **H-3 Wrapper strip-list holes** | **Fixed** | Phase 2; `v0.12.0-dev` planned, not published | Normalization unwraps option-aware `setsid`, `stdbuf`, `ionice`, `watch`, and `chroot`, with unknown/missing values degrading only that statement ([`tokenize.go:1792-1839`](../../internal/engine/tokenize.go#L1792-L1839), [lines 2052-2104](../../internal/engine/tokenize.go#L2052-L2104)). Additional privilege launchers and deliberately unparsed `parallel` deny in [`rules_bash.go:709-713`](../../internal/engine/rules_bash.go#L709-L713). Wrapper, shell, malformed-option, and safe controls begin at [`rules_bash_test.go:1016`](../../internal/engine/rules_bash_test.go#L1016) and [`tokenize_test.go:363`](../../internal/engine/tokenize_test.go#L363). | - |
| **H-4 Uncovered destructive primitives** | **Fixed** | Phase 2; `v0.12.0-dev` planned, not published | Option-aware destination checks cover mv/cp/ln/tee/install and deletion-mode rsync, including move sources and remote destinations ([`rules_bash.go`](../../internal/engine/rules_bash.go), [`rules_path.go`](../../internal/engine/rules_path.go)). Find destructive exec families, update-ref, worktree remove, switch discard, and git rm are covered; option-aware SSH remote commands and enabled visible `LocalCommand` settings remain subject to host and nested Bash checks ([`rules_git.go`](../../internal/engine/rules_git.go), [`rules_net.go`](../../internal/engine/rules_net.go)). Destination, rsync, find, git, SSH remote-command, local-command, malformed-setting, and control locks are in [`rules_bash_test.go`](../../internal/engine/rules_bash_test.go), [`rules_git_test.go`](../../internal/engine/rules_git_test.go), and [`rules_net_test.go`](../../internal/engine/rules_net_test.go). | -; CR-9's unlisted secret readers and H-10's unknown tools remain separate Phase 4 gaps. |
| **H-5 Symlink laundering outside the repo** | **Fixed** | Phase 3 whole-review hardening at `v0.11.0-dev`; evidence completed in Phase 2 | Every visible path candidate proceeds from secret classification to resolved-target escape enforcement ([`rules_path.go:41-51`](../../internal/engine/rules_path.go#L41-L51), [`rules_path.go:690-717`](../../internal/engine/rules_path.go#L690-L717)). Existing outside aliases are locked by [`rules_path_test.go:188-229`](../../internal/engine/rules_path_test.go#L188-L229), with missing-leaf and symlink/`..` resolution in [`resolve_test.go:61-104`](../../internal/pathutil/resolve_test.go#L61-L104). The completed live gate [`TestAuthorizedSecretAllowStillBlocksSymlinkEscape`](../../test/adversarial/overlay_test.go#L211-L296) authorizes `secret_allow = ["**"]`, verifies denial, and requires the matching audit rule `P4.symlink-escape`. | -; dynamically assembled targets remain outside the documented static boundary. |
| **H-6 WebFetch / WebSearch / Task / NotebookEdit are entirely ungated** | **Outstanding** | Phase 4 | Claude parsing retains only `command` and `file_path`, not native URL/query/notebook fields ([`claude.go:14-22`](../../internal/adapter/claude.go#L14-L22)); network signaling explicitly returns false for non-Bash calls ([`trifecta_signals.go:21-37`](../../internal/engine/trifecta_signals.go#L21-L37)). No native-tool egress/trifecta regression closes the finding. | Native network tools can bypass P6 and the trifecta network leg; unknown native write tools can bypass path protection. |
| **H-7 Case-sensitive globs** | **Outstanding** | Phase 4 | Secret matching still calls case-sensitive `doublestar.Match` without filesystem-aware folding ([`rules_path.go:676-687`](../../internal/engine/rules_path.go#L676-L687)). No APFS/NTFS case variant regression exists. | Case variants can reach the same protected file on case-insensitive filesystems. |
| **H-8 `audit_log` overlay = silencing + arbitrary append.** | **Fixed** | Phase 3, `v0.11.0-dev` | Operator config exposes an exact-repository Boolean grant ([`operator.go:97-121`](../../internal/policy/operator.go#L97-L121)); Merge retains the Base audit path unless granted ([`merge.go:87-94`](../../internal/policy/merge.go#L87-L94)). Exact-boundary and no-authorization locks are in [`merge_test.go:132-192`](../../internal/policy/merge_test.go#L132-L192), with hostile `/dev/null` integration in [`overlay_test.go:15-120`](../../test/adversarial/overlay_test.go#L15-L120). | - |
| **H-9 Claude SessionStart `additionalContext` was an unbounded prompt-injection channel.** | **Fixed** | Phase 3, `v0.11.0-dev` | Waiver IDs are format-filtered and model-facing warnings are sanitized/capped in [`sanitize.go:11-51`](../../internal/adapter/sanitize.go#L11-L51); `PostureText` uses both at [`claude.go:89-102`](../../internal/adapter/claude.go#L89-L102). Unicode/control, rune-boundary, ID-format, and posture-cap locks are in [`sanitize_test.go:12-105`](../../internal/adapter/sanitize_test.go#L12-L105). | - |
| **H-10 Unknown tool names fail OPEN on all three planes.** | **Outstanding** | Phase 4 | All Adapter normalizers preserve unknown names ([`opencode.go:48-62`](../../internal/adapter/opencode.go#L48-L62), [`antigravity.go:70-82`](../../internal/adapter/antigravity.go#L70-L82)); `Evaluate` returns allow when no specialized check hits ([`evaluate.go:18-35`](../../internal/engine/evaluate.go#L18-L35)). OpenCode also forwards arbitrary tool names and only recognized path fields ([`opencode_plugin.js:43-55`](../../internal/genconfig/opencode_plugin.js#L43-L55)). There is no unknown-pre-tool deny regression. | New, missing, or misspelled tool names, including real write/network primitives, still fail open. |
| **H-11 No overlay size limit → hook timeout → guard skipped.** | **Fixed** | Phase 3, `v0.11.0-dev` | `LoadOverlay` rejects over 1 MiB both before opening and through a bounded reader in [`config.go:14-15`](../../internal/policy/config.go#L14-L15) and [lines 58-76](../../internal/policy/config.go#L58-L76). Boundary and malformed-oversize tests are in [`config_test.go:253-303`](../../internal/policy/config_test.go#L253-L303); Antigravity oversized-failure protocol coverage is in [`hook_test.go:644-674`](../../cmd/guardrail/hook_test.go#L644-L674). | - |

## MEDIUM ledger

| Finding | Status | Remediation | Current source and regression evidence | Residual risk |
|---|---|---|---|---|
| **M-1 `checkSelfConfig` and `checkGitProtectedPaths` fire on Read** | **Fixed** | Phase 1, `v0.9.0-dev` | Both checks return early for non-writing file calls in [`rules_path.go:450-465`](../../internal/engine/rules_path.go#L450-L465) and [lines 483-497](../../internal/engine/rules_path.go#L483-L497). The exact instruction, global Claude, and git reads are allowed while writes remain denied in [`rules_path_test.go:620-690`](../../internal/engine/rules_path_test.go#L620-L690). | - |
| **M-2 `*.key` basename fallback denies ordinary source** | **Outstanding** | Phase 4 | `*.key` remains a Base secret glob ([`base.toml:9-21`](../../internal/policy/base.toml#L9-L21)), and matching still includes basename fallback ([`rules_path.go:676-687`](../../internal/engine/rules_path.go#L676-L687)). Current matcher tests exercise the Base-shaped glob at [`rules_path_test.go:12-49`](../../internal/engine/rules_path_test.go#L12-L49), but no ordinary-source `.key` allow regression exists. | Common translation/config source files still receive false denials. |
| **M-3 Test fixtures blocked** | **Outstanding** | Phase 4 | Base secret globs still include `id_rsa*`, `*.pem`, `*.key`, and `service-account*.json`, while Base allowances do not cover public keys, testdata, or fixtures ([`base.toml:9-21`](../../internal/policy/base.toml#L9-L21)). The matcher tests only demonstrate the current narrow allowance behavior ([`rules_path_test.go:12-49`](../../internal/engine/rules_path_test.go#L12-L49)); no fixture allowance is implemented or tested. | Public keys and intentionally fake fixture credentials still create routine false positives. |
| **M-4 `ciInfraLockGlobs` basename matching gates routine work** | **Outstanding** | Phase 4 | Broad basename patterns remain in [`rules_path.go:628-635`](../../internal/engine/rules_path.go#L628-L635), and `checkCIInfraLockfile` still uses the basename-fallback matcher ([lines 637-656](../../internal/engine/rules_path.go#L637-L656)). Current tests assert asks for root examples only ([`rules_path_test.go:984-1000`](../../internal/engine/rules_path_test.go#L984-L1000)). | Nested Makefiles, Dockerfiles, `conftest.py`, `setup.py`, and Terraform files continue to prompt and create fatigue. |
| **M-5 `selfConfigGlobs` basename fallback blocks agent-doc repos** | **Outstanding** | Phase 4 | `CLAUDE.md` and `AGENTS.md` remain basename patterns ([`rules_path.go:468-481`](../../internal/engine/rules_path.go#L468-L481)) evaluated with basename fallback ([lines 676-687](../../internal/engine/rules_path.go#L676-L687)). No fixture/template path allowance is tested. | Repositories that author agent documentation still cannot write nested fixtures without a deny. |
| **M-6 `git clean -n` dry-runs are denied** | **Outstanding** | Phase 4 | `git clean` denies if any of `f`, `x`, or `d` is present and does not short-circuit on `-n`/`--dry-run` ([`rules_bash.go:295-313`](../../internal/engine/rules_bash.go#L295-L313)). The existing allow lock covers only `git clean -n`, not the reviewed `git clean -nxd` ([`rules_bash_test.go:536-553`](../../internal/engine/rules_bash_test.go#L536-L553)). | Canonical dry-run previews with selection flags remain false denials. |
| **M-7 Trifecta: session state is deletable and racy** | **Outstanding** | Phase 4 | Session persistence remains unlocked `ReadFile`/`WriteFile` ([`session.go:53-90`](../../internal/session/session.go#L53-L90)); empty IDs still disable state ([lines 35-50](../../internal/session/session.go#L35-L50)); flagless `rm` receives no P1 Verdict ([`rules_bash.go:269-293`](../../internal/engine/rules_bash.go#L269-L293)). No concurrency/deletion regression exists. | State legs can still be lost to races, deleted by the plane, or disabled by an empty session ID. |
| **M-8 Deny `Reason` was `Fprintf`'d unescaped into Claude's model-facing block channel.** | **Fixed** | Phase 3, `v0.11.0-dev` | Every Adapter sanitizes model-facing reasons; Claude applies it before both stderr and ask JSON ([`claude.go:64-86`](../../internal/adapter/claude.go#L64-L86)), with common Unicode-safe control normalization and rune capping in [`sanitize.go:11-21`](../../internal/adapter/sanitize.go#L11-L21) and [`safetext.go:9-20`](../../internal/safetext/safetext.go#L9-L20). Per-plane reason regressions are in [`claude_emit_test.go:19-47`](../../internal/adapter/claude_emit_test.go#L19-L47), [`opencode_test.go:44-68`](../../internal/adapter/opencode_test.go#L44-L68), and [`antigravity_test.go:65-81`](../../internal/adapter/antigravity_test.go#L65-L81). | - |
| **M-9 macOS installs no guard at all.** | **Partially fixed** | Phase 1 chezmoi branch only; **not in either Engine tag** | The separate chezmoi branch `guardrail-remediation-phase1` contains commit `6b882d0` and current branch source resolves `sha256sum`, `gsha256sum`, or `shasum -a 256` in `run_onchange_install_packages.sh.tmpl:340-348` and `scripts/update_ai_tools.sh:78-90`. The installer pin remains `v0.7.0-dev`, and the remediation branch remains unmerged, unapplied, and unpushed, as recorded in [`README.md:15-22`](../../README.md#L15-L22). The Phase 1 plan explicitly prohibited advancing the pin ([`2026-09-04-remediation-phase1.md:955-963`](../superpowers/plans/2026-09-04-remediation-phase1.md#L955-L963)). No regression test in this repository can prove deployment of that external patch. | The patch is unmerged, unapplied, and unpushed, so stock-macOS installation remains unfixed in the deployed chezmoi path. |

## Phase 2 completion and remaining work

The original report's Phase 2 set is fully reconciled. CR-3, CR-4, CR-5, CR-6,
CR-10, CR-11, CR-13, H-1, H-3, and H-4 now have current source and focused unit
evidence in their ledger rows. Task 9 added every required end-to-end
reproduction without removing, reordering, or relaxing the previous 147-case
prefix. The follow-up fix wave retains entries 1-178 in order with identical
commands and outcomes; its sole schema-only edit renames the opt-in fixture flag
to describe logical-repository path rewriting. The corrective Git semantics
round preserves the first 178 entries exactly, retains the nine Docker and SSH
locks, and replaces eight invalid Git locks after that boundary with valid
repository-precedence and refspec controls. The resulting adversarial corpus is
**195 cases: 43 allow, 14 ask, and 138 deny**. Its harness validates the plane response and matching audit record
rather than classifying exit status alone
([`adversarial_test.go:95-173`](../../test/adversarial/adversarial_test.go#L95-L173)).

The first meaningful H-5 live gate passed. The exact authorized
`secret_allow = ["**"]` scenario now proves that an in-repository symlink to an
external secret still denies as `P4.symlink-escape`, with the corresponding
audit record
([`overlay_test.go:211-296`](../../test/adversarial/overlay_test.go#L211-L296)).
That completed lock moves the CRITICAL addendum “Slots widened globally, not
repo-scoped” from partially fixed to fixed; it does not widen the static
tool-call boundary.

Only Phase 4 findings remain outstanding in this repository:

- **CR-9**: the secret-reader closed list remains.
- **H-2, H-6, H-7, H-10**: basename laundering, native tool gating,
  case-sensitive matching, and unknown-tool fail-open behavior remain.
- **M-2 through M-7**: the matching false positives and trifecta state defects
  remain.

M-9 is not part of that repository implementation list. It remains partially
fixed external chezmoi deployment work: the patch is not merged, applied, or
pushed, and the installer pin remains unchanged.

## Phase 3 whole-review corrections

The first Phase 3 landing at `3d884e7` was not the publication boundary. The
whole-phase review produced the following corrections before `v0.11.0-dev`:

- **Exact egress grants.** An Overlay `egress_allowlist` entry now activates
  only when the exact entry is granted for the exact cleaned absolute repository
  in Operator config; `*` and `**` remain forbidden
  ([`operator.go:21-31`](../../internal/policy/operator.go#L21-L31),
  [`operator.go:123-126`](../../internal/policy/operator.go#L123-L126),
  [`merge.go:65-76`](../../internal/policy/merge.go#L65-L76)). Unit and
  audit-backed integration locks are in
  [`merge_test.go:347-426`](../../internal/policy/merge_test.go#L347-L426) and
  [`overlay_test.go:122-208`](../../test/adversarial/overlay_test.go#L122-L208).
- **Antigravity failure contracts.** Setup failures route through the plane's
  native contract: pre emits sanitized deny JSON with exit 0; post emits exactly
  `{}` with exit 0; Claude/OpenCode retain sanitized stderr plus exit 2
  ([`hook.go:22-40`](../../cmd/guardrail/hook.go#L22-L40),
  [`hook.go:55-84`](../../cmd/guardrail/hook.go#L55-L84),
  [`hook_test.go:631-692`](../../cmd/guardrail/hook_test.go#L631-L692)).
- **Resolved, missing-leaf, and symlink/`..` targets.** Resolution walks to the
  nearest existing ancestor before appending missing suffixes, without cleaning
  away traversal order before symlink evaluation
  ([`resolve.go:8-40`](../../internal/pathutil/resolve.go#L8-L40)). Existing,
  absent-leaf, and symlink-parent traversal locks are in
  [`resolve_test.go:33-104`](../../internal/pathutil/resolve_test.go#L33-L104) and
  [`rules_path_test.go:277-350`](../../internal/engine/rules_path_test.go#L277-L350).
- **Visible opaque Operator config writes.** Known opaque executors are denied
  when literal code exposes an Operator config path, including normalized,
  quoted, file-URL, case, and Windows-drive forms
  ([`rules_path.go:516-607`](../../internal/engine/rules_path.go#L516-L607),
  [`rules_path_test.go:437-619`](../../internal/engine/rules_path_test.go#L437-L619)).
  The controls deliberately show dynamically assembled path fragments still
  allow ([`rules_path_test.go:497-518`](../../internal/engine/rules_path_test.go#L497-L518));
  that is the documented static-boundary limit, not a sandbox claim.
- **OpenCode monotonic ordering and unknown scalars.** Permission objects are
  emitted in increasing Verdict strength with exact collisions retaining the
  stricter recognized value; retained scalar/global fallbacks and unknown
  values do not erase the generated floor
  ([`merge.go:70-195`](../../internal/genconfig/merge.go#L70-L195)). Precedence,
  collision, idempotence, scalar, global-fallback, and unknown-scalar tests are
  in [`merge_test.go:191-529`](../../internal/genconfig/merge_test.go#L191-L529)
  and [`opencode_test.go:465-500`](../../internal/genconfig/opencode_test.go#L465-L500).
- **Safe-root coordinates.** Accepted relative safe roots are stored as cleaned
  absolute paths under the repository; lexical and resolved containment must
  both pass, and external or unresolved roots are dropped
  ([`policy/merge.go:41-63`](../../internal/policy/merge.go#L41-L63),
  [`merge_test.go:194-345`](../../internal/policy/merge_test.go#L194-L345)). An
  end-to-end Engine consumption check is in
  [`sync_test.go:270-291`](../../cmd/guardrail/sync_test.go#L270-L291).
- **Complete Unicode-safe sync output.** Every dynamic sync path, warning, and
  error uses uncapped one-line Unicode control normalization
  ([`sync.go:28-147`](../../cmd/guardrail/sync.go#L28-L147),
  [`safetext.go:9-20`](../../internal/safetext/safetext.go#L9-L20)). Tests prove
  all warnings and long dispositions survive without forged lines in
  [`sync_test.go:294-509`](../../cmd/guardrail/sync_test.go#L294-L509).
- **Docs, example, and hygiene.** ADR-0010 and
  [`docs/operator-config.md`](../operator-config.md) document the two-file
  authorization handshake and static boundary; the shipped
  [`guardrail.toml.example`](../../guardrail.toml.example) describes exact
  grants and forbidden total wildcards and is parsed/merged by
  [`config_test.go:112-151`](../../internal/policy/config_test.go#L112-L151).
  Accidentally tracked `.superpowers/sdd` reports were removed; `git ls-files
  '.superpowers/**'` is empty at the reviewed hash.

## Verification and publication evidence

- The coordinator's publication record reports a two-axis review of
  `aa66b99...a296568` against `CONTEXT.md`, ADR-0010, the Phase 3 plan, and the
  whole-review hardening design, with **Standards PASS; Spec PASS**. This
  response does not claim a separately persisted review artifact.
- The coordinator-recorded publication gate reports **PASS** for `make check`
  and the uncached `/usr/local/go/bin/go test ./... -count=1` at the published
  boundary.
- The Phase 2 closeout pre-edit gate passed the exact command `make check &&
  /usr/local/go/bin/go test ./... -count=1`. Fresh post-edit verification also
  passed `make check`, the uncached full test command, documentation/content
  scans, and `git diff --check`.
- GitHub Actions independently passed the final-hash
  [Linux/Windows CI run](https://github.com/CtrlCarlitos/agent-guardrails/actions/runs/33964721003),
  including build/vet on both systems and the full test plus gofmt checks on
  Linux. The
  [release run](https://github.com/CtrlCarlitos/agent-guardrails/actions/runs/33964730547)
  published six platform binaries and checksums.
- The adversarial corpus is exactly **195 cases: 43 allow, 14 ask, 138 deny**.
  The harness validates the plane response and matching audit record rather than
  classifying an exit status alone
  ([`adversarial_test.go:95-173`](../../test/adversarial/adversarial_test.go#L95-L173)).
- Fresh publication checks confirmed that local and remote `v0.11.0-dev` both
  resolve to **`a2965681e4ea552f8b29b329fd8b6a2ee513a395`** and that its GitHub
  Release contains six platform binaries plus `SHA256SUMS`. Phase 2 and this
  response were authored later and are not in that tagged snapshot. Local and
  remote `v0.12.0-dev` were both absent at closeout; that tag remains planned.

## Explicit non-claims

- `v0.12.0-dev` has not been created or pushed, and no Phase 2 release has been
  published. The controller owns tagging and publication after branch review.
- Phase 4 remains open for CR-9; H-2, H-6, H-7, H-10; and M-2 through M-7.
- The installer pin is still `v0.7.0-dev`; the chezmoi M-9 branch has not been
  merged, applied, or pushed. Phase 2 completion did not advance the pin.
- This is static Guardrail Policy enforcement at plane tool-call boundaries,
  not an operating-system sandbox and not containment against arbitrary
  same-user code with dynamically concealed effects.

## Heading audit

The authoritative report headings were audited before writing this ledger.
Covered CRITICAL headings: **CR-1 through CR-16**, plus all three addendum
bullets: **CR-3 addendum: `waive` was unbounded.**, **Slots widened globally,
not repo-scoped.**, and **"Logged" did not mean visible.** Covered HIGH
headings: **H-1 through H-11**. Covered MEDIUM headings: **M-1 through M-9**.
No numbered CRITICAL, HIGH, MEDIUM, or addendum finding is omitted.
