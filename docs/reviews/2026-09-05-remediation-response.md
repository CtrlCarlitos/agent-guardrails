# Remediation Response to the 2026-09-04 Adversarial Review

## Scope and answer

This response answers the complete finding index in the
[2026-09-04 adversarial review](./2026-09-04-adversarial-review.md), whose build
under test was `b109b33`+ and whose scope also included the separate chezmoi
installer. Phase 3's published Engine source boundary is clean commit
[`a2965681e4ea552f8b29b329fd8b6a2ee513a395`](https://github.com/CtrlCarlitos/agent-guardrails/commit/a2965681e4ea552f8b29b329fd8b6a2ee513a395):
the local and remote `v0.11.0-dev` tags resolve to that hash, and the GitHub
Release for `v0.11.0-dev` publishes six platform binaries plus `SHA256SUMS`.
Phase 2 is complete and published: local and remote `v0.12.0-dev` both resolve to
[`d4e43e814564785c28ea8d84023c60f60d72af2e`](https://github.com/CtrlCarlitos/agent-guardrails/commit/d4e43e814564785c28ea8d84023c60f60d72af2e),
and its GitHub Release carries six platform binaries plus `SHA256SUMS`.
**`v0.12.0-dev` is the deployed binary** as of 2026-09-06: the chezmoi
installer pin is `v0.12.0-dev` in all four locations (`3205860`), and
`~/.local/bin/guardrail --version` reports it. Phase 1 is published at
`v0.9.0-dev` (`aa66b99615a4ba3384ffb5a661bcfebe03f7c181`). Phase 4 is
complete in source through `9484388`, but is not tagged, published, deployed,
or reflected in the installer pin.

*Status updated 2026-09-06 for the Phase 4 source closeout. Publication and
deployment claims remain scoped to the tags named below.*

The honest executive answer is **not all findings are addressed**. Phase 1
closed the normalization and self-protection fixes assigned to it. Phase 3 and
its whole-review hardening repaired the Overlay trust model and related
cross-plane failures. Phase 2 closed its token normalization, git, Docker,
egress, wrapper, destructive-primitive, working-directory, and regression-lock
work. Phase 4 closed path-matching correctness, secret tiers, command-operand
coverage, scoped self-configuration, and executable identity for CR-9, H-2,
H-7, M-2 through M-6, NF-1, and NF-2. M-9 is fully fixed: the chezmoi branch
`guardrail-remediation-phase1` is merged into chezmoi `main`, the `shasum`
fallback is live (`run_onchange_install_packages.sh.tmpl:344`), and the pin
advanced to `v0.12.0-dev`. **Phase 5** retains H-6, H-10, and M-7. The current
ledger is 38 fixed, 0 partially fixed, and 3 outstanding across 41 indexed
findings.

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
| CRITICAL | 19 | 0 | 0 | 19 (16 numbered findings plus 3 addendum bullets) |
| HIGH | 9 | 0 | 2 | 11 |
| MEDIUM | 8 | 0 | 1 | 9 |
| NEW FINDINGS | 2 | 0 | 0 | 2 |
| **Total** | **38** | **0** | **3** | **41** |

## CRITICAL ledger

| Finding | Status | Remediation | Current source and regression evidence | Residual risk |
|---|---|---|---|---|
| **CR-1 Absolute-path invocation bypasses every rule — RC2** | **Fixed** | Phase 1, `v0.9.0-dev`; identity hardening in Phase 4, `98b7f8f` | Command heads normalize separators and case, take the basename, and strip `.exe` once in [`rules_bash.go`](../../internal/engine/rules_bash.go), then feed the Bash, git, Docker, egress, path-operand, and opaque-executor checks. Absolute Unix and Windows-style command identities are locked in Engine tests and the adversarial corpus. | - |
| **CR-2 Quoting any operand defeats matching — RC1** | **Fixed** | Phase 1, `v0.9.0-dev` | `extractSimples` stores literal argv and redirect text and marks unresolved words in [`tokenize.go:49-125`](../../internal/engine/tokenize.go#L49-L125); unresolved words ask without masking stronger Verdicts in [`rules_bash.go:29-60`](../../internal/engine/rules_bash.go#L29-L60). Quoted argv and redirect regressions start in [`tokenize_test.go:44-87`](../../internal/engine/tokenize_test.go#L44-L87), with complete end-to-end reproductions in the adversarial corpus. | - |
| **CR-3 `cd` is not tracked — relative operands resolve against the hook's cwd** | **Fixed** | Phase 2, `v0.12.0-dev` (published 2026-09-06, deployed) | `Normalize(command, cwd)` records the effective cwd on each `Simple` and conservatively marks unresolved directory state ([`tokenize.go:15-25`](../../internal/engine/tokenize.go#L15-L25), [lines 1683-1696](../../internal/engine/tokenize.go#L1683-L1696)); Bash and path checks consume the statement cwd through [`simpleCwd`](../../internal/engine/rules_bash.go#L763-L784). Same-shell, isolated-scope, path-effect, and normalization locks start in [`rules_bash_test.go:103-223`](../../internal/engine/rules_bash_test.go#L103-L223) and [`tokenize_test.go:1114-1209`](../../internal/engine/tokenize_test.go#L1114-L1209). | - |
| **CR-4 Redirect-only statements are discarded** | **Fixed** | Phase 2, `v0.12.0-dev` (published 2026-09-06, deployed) | `extractSimples` retains statements that have redirects without call arguments and classifies read/write directions ([`tokenize.go:49-95`](../../internal/engine/tokenize.go#L49-L95)); `checkBash` sends empty-argv simples through redirect policy ([`rules_bash.go:41-58`](../../internal/engine/rules_bash.go#L41-L58)). Bare, descriptor, append, sibling-deny, and normalization locks are in [`rules_bash_test.go:368-407`](../../internal/engine/rules_bash_test.go#L368-L407) and [`tokenize_test.go:132-181`](../../internal/engine/tokenize_test.go#L132-L181). | - |
| **CR-5 `git --git-dir <path>` (space form) bypasses every git rule** | **Fixed** | Phase 2, `v0.12.0-dev` (published 2026-09-06, deployed) | Both git subcommand helpers share the complete reviewed value-global table, and unknown long globals fail closed after stronger subcommand Verdicts are evaluated ([`rules_bash.go:316-404`](../../internal/engine/rules_bash.go#L316-L404), [`rules_git.go:9-15`](../../internal/engine/rules_git.go#L9-L15), [lines 130-134](../../internal/engine/rules_git.go#L130-L134)). Space, attached, valueless, unknown, and read-only controls are locked from [`rules_git_test.go:411`](../../internal/engine/rules_git_test.go#L411). | - |
| **CR-6 Force-push and remote-branch-delete via refspec** | **Fixed** | Phase 2, `v0.12.0-dev` (published 2026-09-06, deployed) | Push argument parsing consumes option values, always classifies the first positional operand as the repository, and evaluates only later positional operands as refspecs. `--repo` supplies a fallback repository only when no positional operand exists; a positional repository takes precedence regardless of option ordering. Leading `+`, empty-source deletion, and destination-side protected refspecs receive the required Verdicts ([`rules_git.go`](../../internal/engine/rules_git.go)). Attached, split, abbreviated, mixed-order, end-of-options, negation, positional-precedence, and benign controls are in [`rules_git_test.go`](../../internal/engine/rules_git_test.go). | - |
| **CR-7 Path dot-segments defeat every leaf-literal glob — RC3** | **Fixed** | Phase 1, `v0.9.0-dev`; matcher scoping in Phase 4, `b29ce8d` | Glob input is slash-normalized and `path.Clean`ed before case-insensitive full-path matching in [`rules_path.go`](../../internal/engine/rules_path.go); Phase 4 removed basename fallback and gave root-only lists explicit repository-relative matching. Dot, repeated-separator, parent-segment, root, and nested cases are locked in [`rules_path_test.go`](../../internal/engine/rules_path_test.go), [`rules_scope_test.go`](../../internal/engine/rules_scope_test.go), and the corpus. | - |
| **CR-8 Write channels other than redirects are invisible — RC4** | **Fixed** | Phase 1, `v0.9.0-dev` | Known destination-taking mutators, all-target mutators, `dd of=`, and `sed -i` feed path checks through [`rules_path.go`](../../internal/engine/rules_path.go). Phase 2 added strict destination parsing and safe-root enforcement for the reviewed mv/cp/ln/tee/install/rsync channels ([`rules_bash.go`](../../internal/engine/rules_bash.go)). | -; H-10's unknown tools remain a separate Phase 5 gap. |
| **CR-9 Secret reads via any command outside the 14-name `pathReaders` list — RC4** | **Fixed** | Phase 4, `057867c` | Operand-role parsing classifies path-bearing values for known commands and path-shaped operands for unlisted commands, while excluding grep/sed/awk/jq/yq programs and filters ([`operands.go`](../../internal/engine/operands.go), [`rules_path.go`](../../internal/engine/rules_path.go)). Opaque executors expose visible literal paths under the documented mention-equals-access boundary. Command, attached-flag, terminator, role-order, opaque-source, and false-positive locks are in [`rules_path_test.go`](../../internal/engine/rules_path_test.go) and the adversarial corpus. | A bare filename passed to an unlisted command is not a candidate; opaque-source matching cannot distinguish access from mention. H-10 remains separate. |
| **CR-10 Scheme-less URL fails host extraction open → egress bypass** | **Fixed** | Phase 2, `v0.12.0-dev` (published 2026-09-06, deployed) | Network option parsing identifies curl/wget targets, host extraction retries scheme-less operands as URL authorities, and malformed, ambiguous, or missing hosts deny rather than skip ([`rules_net.go:98-119`](../../internal/engine/rules_net.go#L98-L119), [lines 504-597](../../internal/engine/rules_net.go#L504-L597)). Scheme-less, option-value, fail-closed, localhost, and allowlist locks are in [`rules_net_test.go:469-519`](../../internal/engine/rules_net_test.go#L469-L519) and [lines 754-778](../../internal/engine/rules_net_test.go#L754-L778). | - |
| **CR-11 Fetch-then-execute with a stage in between — and CR-10 makes it unauthenticated** | **Fixed** | Phase 2, `v0.12.0-dev` (published 2026-09-06, deployed) | Fetch-to-interpreter detection compares AST-derived pipeline IDs and stage order across all later simples, not adjacency ([`rules_net.go:24-49`](../../internal/engine/rules_net.go#L24-L49)). Intermediate-stage and pipeline-boundary controls are locked in [`rules_net_test.go:50-114`](../../internal/engine/rules_net_test.go#L50-L114), with nested control-flow coverage following in the same file. | - |
| **CR-12 Session-id path traversal writes outside the state dir** | **Fixed** | Phase 1, `v0.9.0-dev` | `Path`, `Load`, and `Save` reject empty, dot, separator, and `..` IDs in [`session.go:35-75`](../../internal/session/session.go#L35-L75). The exact traversal is contained and checked for both write and read in [`session_test.go:50-109`](../../internal/session/session_test.go#L50-L109). | - |
| **CR-13 `docker compose -f` and the whole prune family** | **Fixed** | Phase 2, `v0.12.0-dev` (published 2026-09-06, deployed) | Docker-family option parsing derives command-word chains for Docker, docker-compose, Podman, and nerdctl before matching compose down and prune families; parsed run options retain an explicit `--entrypoint`, which is prepended to post-image arguments before nested Bash checks ([`rules_bash.go`](../../internal/engine/rules_bash.go), [`tokenize.go`](../../internal/engine/tokenize.go)). Global, Compose, alternate-frontend, prune, run/exec, entrypoint, and malformed-value locks are in [`rules_bash_test.go`](../../internal/engine/rules_bash_test.go) and [`tokenize_test.go`](../../internal/engine/tokenize_test.go). | - |
| **CR-3 addendum: `waive` was unbounded.** | **Fixed** | Phase 3, `v0.11.0-dev` | Operator config grants are exact per cleaned absolute repository and the three fail-closed backstops are immutable ([`operator.go:13-31`](../../internal/policy/operator.go#L13-L31), [lines 97-126](../../internal/policy/operator.go#L97-L126)); Merge drops unauthorized Waiver requests ([`merge.go:96-108`](../../internal/policy/merge.go#L96-L108)). Unit locks are in [`merge_test.go:86-163`](../../internal/policy/merge_test.go#L86-L163) and [`operator_test.go:289-309`](../../internal/policy/operator_test.go#L289-L309); hostile-Overlay end-to-end evidence is in [`overlay_test.go:15-120`](../../test/adversarial/overlay_test.go#L15-L120). | - |
| **Slots widened globally, not repo-scoped.** | **Fixed** | Phase 3 implementation at `v0.11.0-dev`; evidence completed in Phase 2 | `secret_allow` and `audit_log` require exact-repository Boolean grants, while each egress entry requires an exact-repository, exact-entry grant ([`operator.go:21-31`](../../internal/policy/operator.go#L21-L31), [`operator.go:97-126`](../../internal/policy/operator.go#L97-L126), [`merge.go:65-94`](../../internal/policy/merge.go#L65-L94)). Safe roots require lexical and resolved repository containment ([`merge.go:41-63`](../../internal/policy/merge.go#L41-L63)), and secret allowance does not bypass the following symlink check ([`rules_path.go:41-51`](../../internal/engine/rules_path.go#L41-L51)). Exact authorization and containment unit locks remain in [`merge_test.go:132-426`](../../internal/policy/merge_test.go#L132-L426); [`TestAuthorizedSecretAllowStillBlocksSymlinkEscape`](../../test/adversarial/overlay_test.go#L211-L296) now proves the authorized `secret_allow = ["**"]` plus escaping-symlink combination denies with `P4.symlink-escape` and a matching audit record. | - |
| **"Logged" did not mean visible.** | **Fixed** | Phase 3, `v0.11.0-dev` | Merge warnings are included in Claude's SessionStart posture ([`hook.go:77-96`](../../cmd/guardrail/hook.go#L77-L96)) and universally in `guardrail doctor` ([`doctor.go:59-85`](../../cmd/guardrail/doctor.go#L59-L85)). Visibility and sanitization are locked in [`hook_test.go:717-766`](../../cmd/guardrail/hook_test.go#L717-L766) and [`doctor_test.go:79-145`](../../cmd/guardrail/doctor_test.go#L79-L145). OpenCode and Antigravity have no SessionStart posture; their generated integrations expose only pre-tool, or pre/post, events ([`opencode_plugin.js:43-55`](../../internal/genconfig/opencode_plugin.js#L43-L55), [`antigravity.go:7-31`](../../internal/genconfig/antigravity.go#L7-L31)). | - |
| **CR-14 The agent can write the file that configures its own guard** | **Fixed** | Phase 1, `v0.9.0-dev`; Claude scoping in Phase 4, `d13f4af` | Engine self-configuration globs include the Overlay, Adapter, plane configuration, hooks, and installed-binary surfaces while excluding unrelated Claude memory ([`rules_path.go`](../../internal/engine/rules_path.go)). Read/write behavior is locked in Engine tests, corresponding Claude/OpenCode Declarative floor tests, and the adversarial corpus. | - |
| **CR-15 One Bash call removes the guard permanently — RC4** | **Fixed** | Phase 1, `v0.9.0-dev` | Argument-based mutator destinations flow into protected-path checks through [`rules_path.go`](../../internal/engine/rules_path.go); guard machinery and the installed binary remain protected by the scoped self-configuration lists. Exact settings removal and binary replacement families are locked in [`rules_path_test.go`](../../internal/engine/rules_path_test.go) and the adversarial corpus. | - |
| **CR-16 opencode: `$GUARDRAIL_BIN`/`$PATH` bypass, and `--binary` is silently discarded** | **Fixed** | Phase 1, `v0.9.0-dev` | The generated Adapter receives a JSON-escaped absolute binary path and accepts only an explicit allow response in [`opencode_plugin.js:8-40`](../../internal/genconfig/opencode_plugin.js#L8-L40). Exact-path execution and empty/malformed/unknown response locks are in [`opencode_test.go:180-309`](../../internal/genconfig/opencode_test.go#L180-L309). | - |

The root-cause picture is therefore narrowed: RC1, RC2, and RC3 are fixed. RC4's
reviewed mutator, destructive-primitive, and reader channels are fixed
(CR-8/CR-9/CR-15/H-4); only unknown-tool coverage (H-10) remains for Phase 5.

## HIGH ledger

| Finding | Status | Remediation | Current source and regression evidence | Residual risk |
|---|---|---|---|---|
| **H-1 A junk wrapper flag downgrades DENY to ASK** | **Fixed** | Phase 2, `v0.12.0-dev` (published 2026-09-06, deployed) | Wrapper-normalization errors now retain only the affected statement as unresolved while siblings continue ([`tokenize.go:1739-1767`](../../internal/engine/tokenize.go#L1739-L1767)); `checkBash` aggregates the strongest unwaived Verdict, so deny outranks ask ([`rules_bash.go:29-60`](../../internal/engine/rules_bash.go#L29-L60)). Both statement orders, standalone unresolved input, and redirect preservation are locked in [`rules_bash_test.go:92-101`](../../internal/engine/rules_bash_test.go#L92-L101), [lines 354-366](../../internal/engine/rules_bash_test.go#L354-L366), and [`tokenize_test.go:565-605`](../../internal/engine/tokenize_test.go#L565-L605). | - |
| **H-2 `.env.example` basename-matching neutralizes the strongest globs** | **Fixed** | Phase 4, `6207a15` and `e0f2ca3` | `secret_dirs` is a distinct additive tier evaluated before filename allowances and is unwaivable for lexical and resolved matches ([`rules_path.go`](../../internal/engine/rules_path.go), [`base.toml`](../../internal/policy/base.toml)). Merge and Declarative floor propagation are locked in [`merge_test.go`](../../internal/policy/merge_test.go) and [`claude_test.go`](../../internal/genconfig/claude_test.go); filename allowances, direct paths, and symlink aliases are locked in [`rules_path_test.go`](../../internal/engine/rules_path_test.go). | - |
| **H-3 Wrapper strip-list holes** | **Fixed** | Phase 2, `v0.12.0-dev` (published 2026-09-06, deployed) | Normalization unwraps option-aware `setsid`, `stdbuf`, `ionice`, `watch`, and `chroot`, with unknown/missing values degrading only that statement ([`tokenize.go:1792-1839`](../../internal/engine/tokenize.go#L1792-L1839), [lines 2052-2104](../../internal/engine/tokenize.go#L2052-L2104)). Additional privilege launchers and deliberately unparsed `parallel` deny in [`rules_bash.go:709-713`](../../internal/engine/rules_bash.go#L709-L713). Wrapper, shell, malformed-option, and safe controls begin at [`rules_bash_test.go:1016`](../../internal/engine/rules_bash_test.go#L1016) and [`tokenize_test.go:363`](../../internal/engine/tokenize_test.go#L363). | - |
| **H-4 Uncovered destructive primitives** | **Fixed** | Phase 2, `v0.12.0-dev` (published 2026-09-06, deployed) | Option-aware destination checks cover mv/cp/ln/tee/install and deletion-mode rsync, including move sources and remote destinations ([`rules_bash.go`](../../internal/engine/rules_bash.go), [`rules_path.go`](../../internal/engine/rules_path.go)). Find destructive exec families, update-ref, worktree remove, switch discard, and git rm are covered; option-aware SSH remote commands and enabled visible `LocalCommand` settings remain subject to host and nested Bash checks ([`rules_git.go`](../../internal/engine/rules_git.go), [`rules_net.go`](../../internal/engine/rules_net.go)). Destination, rsync, find, git, SSH remote-command, local-command, malformed-setting, and control locks are in [`rules_bash_test.go`](../../internal/engine/rules_bash_test.go), [`rules_git_test.go`](../../internal/engine/rules_git_test.go), and [`rules_net_test.go`](../../internal/engine/rules_net_test.go). | -; H-10's unknown tools remain a separate Phase 5 gap. |
| **H-5 Symlink laundering outside the repo** | **Fixed** | Phase 3 whole-review hardening at `v0.11.0-dev`; secret-tier ordering completed in Phase 4 | Every visible path candidate aggregates lexical secret classification with resolved-target secret-directory and escape enforcement ([`rules_path.go`](../../internal/engine/rules_path.go)). Existing outside aliases, missing-leaf traversal, secret-directory aliases, and ambiguous-ask versus symlink-deny ordering are locked in [`rules_path_test.go`](../../internal/engine/rules_path_test.go) and [`resolve_test.go`](../../internal/pathutil/resolve_test.go). The live Overlay gate remains [`TestAuthorizedSecretAllowStillBlocksSymlinkEscape`](../../test/adversarial/overlay_test.go). | -; dynamically assembled targets remain outside the documented static boundary. |
| **H-6 WebFetch / WebSearch / Task / NotebookEdit are entirely ungated** | **Outstanding** | Phase 5 | Claude parsing retains only `command` and `file_path`, not native URL/query/notebook fields ([`claude.go:14-22`](../../internal/adapter/claude.go#L14-L22)); network signaling explicitly returns false for non-Bash calls ([`trifecta_signals.go:21-37`](../../internal/engine/trifecta_signals.go#L21-L37)). No native-tool egress/trifecta regression closes the finding. | Native network tools can bypass P6 and the trifecta network leg; unknown native write tools can bypass path protection. |
| **H-7 Case-sensitive globs** | **Fixed** | Phase 4, `b29ce8d` and `08cbc79` | Path containment and glob matching normalize case before comparison across secret, self-configuration, git-protected, and CI/infrastructure lists ([`rules_path.go`](../../internal/engine/rules_path.go)). APFS/NTFS-style variants are locked in [`rules_scope_test.go`](../../internal/engine/rules_scope_test.go) and the adversarial corpus. | - |
| **H-8 `audit_log` overlay = silencing + arbitrary append.** | **Fixed** | Phase 3, `v0.11.0-dev` | Operator config exposes an exact-repository Boolean grant ([`operator.go:97-121`](../../internal/policy/operator.go#L97-L121)); Merge retains the Base audit path unless granted ([`merge.go:87-94`](../../internal/policy/merge.go#L87-L94)). Exact-boundary and no-authorization locks are in [`merge_test.go:132-192`](../../internal/policy/merge_test.go#L132-L192), with hostile `/dev/null` integration in [`overlay_test.go:15-120`](../../test/adversarial/overlay_test.go#L15-L120). | - |
| **H-9 Claude SessionStart `additionalContext` was an unbounded prompt-injection channel.** | **Fixed** | Phase 3, `v0.11.0-dev` | Waiver IDs are format-filtered and model-facing warnings are sanitized/capped in [`sanitize.go:11-51`](../../internal/adapter/sanitize.go#L11-L51); `PostureText` uses both at [`claude.go:89-102`](../../internal/adapter/claude.go#L89-L102). Unicode/control, rune-boundary, ID-format, and posture-cap locks are in [`sanitize_test.go:12-105`](../../internal/adapter/sanitize_test.go#L12-L105). | - |
| **H-10 Unknown tool names fail OPEN on all three planes.** | **Outstanding** | Phase 5 | All Adapter normalizers preserve unknown names ([`opencode.go:48-62`](../../internal/adapter/opencode.go#L48-L62), [`antigravity.go:70-82`](../../internal/adapter/antigravity.go#L70-L82)); `Evaluate` returns allow when no specialized check hits ([`evaluate.go:18-35`](../../internal/engine/evaluate.go#L18-L35)). OpenCode also forwards arbitrary tool names and only recognized path fields ([`opencode_plugin.js:43-55`](../../internal/genconfig/opencode_plugin.js#L43-L55)). There is no unknown-pre-tool deny regression. | New, missing, or misspelled tool names, including real write/network primitives, still fail open. |
| **H-11 No overlay size limit → hook timeout → guard skipped.** | **Fixed** | Phase 3, `v0.11.0-dev` | `LoadOverlay` rejects over 1 MiB both before opening and through a bounded reader in [`config.go:14-15`](../../internal/policy/config.go#L14-L15) and [lines 58-76](../../internal/policy/config.go#L58-L76). Boundary and malformed-oversize tests are in [`config_test.go:253-303`](../../internal/policy/config_test.go#L253-L303); Antigravity oversized-failure protocol coverage is in [`hook_test.go:644-674`](../../cmd/guardrail/hook_test.go#L644-L674). | - |

## MEDIUM ledger

| Finding | Status | Remediation | Current source and regression evidence | Residual risk |
|---|---|---|---|---|
| **M-1 `checkSelfConfig` and `checkGitProtectedPaths` fire on Read** | **Fixed** | Phase 1, `v0.9.0-dev`; scoping retained in Phase 4 | Both checks return early for non-writing file calls in [`rules_path.go`](../../internal/engine/rules_path.go). Instruction, Claude configuration, memory, and git read/write boundaries are locked in [`rules_path_test.go`](../../internal/engine/rules_path_test.go) and the adversarial corpus. | - |
| **M-2 `*.key` basename fallback denies ordinary source** | **Fixed** | Phase 4, `d13f4af` | The Base policy removes generic `*.key` denial and retains explicit private-key families; matching has no basename fallback ([`base.toml`](../../internal/policy/base.toml), [`rules_path.go`](../../internal/engine/rules_path.go)). Translation/config `.key` sources and private-key controls are locked in [`rules_path_test.go`](../../internal/engine/rules_path_test.go) and the corpus. | - |
| **M-3 Test fixtures blocked** | **Fixed** | Phase 4, `d13f4af` | Public keys are allowed outside secret directories. Ambiguous certificate/keystore/service-account patterns form an in-repository ask tier and remain deny outside the repository; definitive private keys and secret directories still deny ([`base.toml`](../../internal/policy/base.toml), [`rules_path.go`](../../internal/engine/rules_path.go)). Tier, allowance, aggregation, floor, and corpus locks require exact allow/ask/deny Verdicts. | Moving in-repository certificate patterns to ask is a deliberate reduction in strictness; `secret_dirs` still denies. |
| **M-4 `ciInfraLockGlobs` basename matching gates routine work** | **Fixed** | Phase 4, `b29ce8d` | Root-only CI/infrastructure names are evaluated only as repository-relative root paths; explicitly anywhere-scoped globs remain protected ([`rules_path.go`](../../internal/engine/rules_path.go)). Relative, absolute, repository-root `/`, escape, nested, and symlink cases are locked in [`rules_scope_test.go`](../../internal/engine/rules_scope_test.go). | - |
| **M-5 `selfConfigGlobs` basename fallback blocks agent-doc repos** | **Fixed** | Phase 4, `b29ce8d` | Root-only agent-document names are evaluated only at the repository root, from lexical and resolved path forms; nested templates no longer match by basename ([`rules_path.go`](../../internal/engine/rules_path.go)). Root, nested, case, escape, and symlink controls are locked in [`rules_scope_test.go`](../../internal/engine/rules_scope_test.go) and the corpus. | - |
| **M-6 `git clean -n` dry-runs are denied** | **Fixed** | Phase 4, `d13f4af` | `git clean` recognizes `-n` and `--dry-run` before destructive selection flags ([`rules_bash.go`](../../internal/engine/rules_bash.go)). Combined short flags, long form, destructive controls, and corpus cases are locked in [`rules_bash_test.go`](../../internal/engine/rules_bash_test.go). | - |
| **M-7 Trifecta: session state is deletable and racy** | **Outstanding** | Phase 5 | Session persistence remains unlocked `ReadFile`/`WriteFile` ([`session.go:53-90`](../../internal/session/session.go#L53-L90)); empty IDs still disable state ([lines 35-50](../../internal/session/session.go#L35-L50)); flagless `rm` receives no P1 Verdict ([`rules_bash.go:269-293`](../../internal/engine/rules_bash.go#L269-L293)). No concurrency/deletion regression exists. | State legs can still be lost to races, deleted by the plane, or disabled by an empty session ID. |
| **M-8 Deny `Reason` was `Fprintf`'d unescaped into Claude's model-facing block channel.** | **Fixed** | Phase 3, `v0.11.0-dev` | Every Adapter sanitizes model-facing reasons; Claude applies it before both stderr and ask JSON ([`claude.go:64-86`](../../internal/adapter/claude.go#L64-L86)), with common Unicode-safe control normalization and rune capping in [`sanitize.go:11-21`](../../internal/adapter/sanitize.go#L11-L21) and [`safetext.go:9-20`](../../internal/safetext/safetext.go#L9-L20). Per-plane reason regressions are in [`claude_emit_test.go:19-47`](../../internal/adapter/claude_emit_test.go#L19-L47), [`opencode_test.go:44-68`](../../internal/adapter/opencode_test.go#L44-L68), and [`antigravity_test.go:65-81`](../../internal/adapter/antigravity_test.go#L65-L81). | - |
| **M-9 macOS installs no guard at all.** | **Fixed** | Phase 1 (chezmoi); merged, applied and pushed 2026-09-06 | The chezmoi branch `guardrail-remediation-phase1` is merged into chezmoi `main` (`git branch --merged main` lists it). `main` resolves `sha256sum`, `gsha256sum`, or `shasum -a 256` in `run_onchange_install_packages.sh.tmpl:340-348` and `scripts/update_ai_tools.sh`. The installer pin is `v0.12.0-dev` in all four locations (chezmoi `3205860`), and the installed binary reports `guardrail v0.12.0-dev`. This repository still cannot regression-test the external chezmoi path; the evidence is the merged chezmoi history and the live install. | Not exercised on real macOS in this session; the fallback is verified by inspection and by the merged commit, not by a Mac install. |

## New-finding ledger

| Finding | Status | Remediation | Current source and regression evidence | Residual risk |
|---|---|---|---|---|
| **NF-1 Agent memory was classified as agent configuration** | **Fixed** | Phase 4, `d13f4af` | Self-configuration globs cover settings, hooks, plugins, agents, commands, skills, and Claude instructions rather than all of `.claude`; memory writes no longer receive `P5.self-config` ([`rules_path.go`](../../internal/engine/rules_path.go)). [`TestAgentMemoryIsNotAgentConfig`](../../internal/engine/rules_path_test.go) and the corpus prove the out-of-repository memory write receives `P5.out-of-repo` ask while configuration writes deny. | - |
| **NF-2 Executable identity was not canonicalized** | **Fixed** | Phase 4, `98b7f8f` | Command heads normalize slash direction and case, take the basename, and strip `.exe` once for every command map ([`rules_bash.go`](../../internal/engine/rules_bash.go)). Unit and corpus locks cover `cat.exe`, `CAT`, `C:\bin\cat.exe`, and Unix absolute paths. | - |

## Phase 4 completion and remaining work

The original report's Phase 2 set remains fully reconciled. Phase 4 now adds
current source, focused Engine tests, Declarative floor tests, and end-to-end
corpus evidence for CR-9, H-2, H-7, M-2 through M-6, NF-1, and NF-2. The corpus
preserves all 196 prior entries in their original order with identical fields and
values, then appends 103 whole-Engine cases. The resulting adversarial corpus is
**299 cases: 76 allow, 23 ask, and 200 deny**. Its harness validates the plane
response and matching audit record rather than classifying exit status alone
([`adversarial_test.go:97-175`](../../test/adversarial/adversarial_test.go#L97-L175)).

The first meaningful H-5 live gate passed. The exact authorized
`secret_allow = ["**"]` scenario now proves that an in-repository symlink to an
external secret still denies as `P4.symlink-escape`, with the corresponding
audit record
([`overlay_test.go:211-296`](../../test/adversarial/overlay_test.go#L211-L296)).
That completed lock moves the CRITICAL addendum “Slots widened globally, not
repo-scoped” from partially fixed to fixed; it does not widen the static
tool-call boundary.

Only Phase 5 findings remain outstanding: **H-6** (native network/tool gating),
**H-10** (unknown-tool fail-open behavior), and **M-7** (trifecta session-state
integrity). The review is therefore not fully closed.

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
- The Phase 4 closeout gate passed `make check && /usr/local/go/bin/go test
  ./... -count=1` at the documentation boundary.
- The adversarial corpus is exactly **299 cases: 76 allow, 23 ask, 200 deny**.
  The harness validates the plane response and matching audit record rather than
  classifying an exit status alone
  ([`adversarial_test.go:97-175`](../../test/adversarial/adversarial_test.go#L97-L175)).
- Fresh publication checks confirmed that local and remote `v0.11.0-dev` both
  resolve to **`a2965681e4ea552f8b29b329fd8b6a2ee513a395`** and that its GitHub
  Release contains six platform binaries plus `SHA256SUMS`. Phase 2 and this
  response were authored later and are not in that tagged snapshot.
- **2026-09-06:** local and remote `v0.12.0-dev` both resolve to
  **`d4e43e814564785c28ea8d84023c60f60d72af2e`**; `gh release view v0.12.0-dev`
  lists seven assets (`darwin/linux/windows` × `amd64/arm64`, plus `SHA256SUMS`).
  The chezmoi pin was advanced to `v0.12.0-dev` and applied; before/after
  probes of the installed binary showed `rm -rf "/etc"`, `/bin/rm -rf /`,
  `cd /etc && rm -rf .`, `git --git-dir /r/.git push --force` and
  `docker compose -f d.yml down` move from exit 0 to exit 2.

## Explicit non-claims

- No code for Phase 5 has landed. H-6, H-10, and M-7 remain open.
- Phase 4 is complete in source but is not tagged, published, deployed, or
  reflected in the installer pins. `v0.13.0-dev` and `v0.14.0-dev` do not exist.
- The review is **not** closed; Phase 5 still has three outstanding findings.
- This is static Guardrail Policy enforcement at plane tool-call boundaries,
  not an operating-system sandbox and not containment against arbitrary
  same-user code with dynamically concealed effects.

## Heading audit

The authoritative report headings were audited before writing this ledger.
Covered CRITICAL headings: **CR-1 through CR-16**, plus all three addendum
bullets: **CR-3 addendum: `waive` was unbounded.**, **Slots widened globally,
not repo-scoped.**, and **"Logged" did not mean visible.** Covered HIGH
headings: **H-1 through H-11**. Covered MEDIUM headings: **M-1 through M-9**.
Covered new findings: **NF-1 and NF-2**. No numbered CRITICAL, HIGH, MEDIUM,
new, or addendum finding is omitted.
