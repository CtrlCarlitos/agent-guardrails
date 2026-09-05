# Remediation Response to the 2026-09-04 Adversarial Review

## Scope and answer

This response answers the complete finding index in the
[2026-09-04 adversarial review](./2026-09-04-adversarial-review.md), whose build
under test was `b109b33`+ and whose scope also included the separate chezmoi
installer. The reviewed and published Engine source boundary is clean commit
[`a2965681e4ea552f8b29b329fd8b6a2ee513a395`](https://github.com/CtrlCarlitos/agent-guardrails/commit/a2965681e4ea552f8b29b329fd8b6a2ee513a395):
the local and remote `v0.11.0-dev` tags resolve to that hash, and the GitHub
Release for `v0.11.0-dev` publishes six platform binaries plus `SHA256SUMS`.
This response was authored after that boundary and is not part of the tagged
snapshot. Phase 1 is published at `v0.9.0-dev`
(`aa66b99615a4ba3384ffb5a661bcfebe03f7c181`).

The honest executive answer is **not all findings are addressed**. Phase 1
closed the normalization and self-protection fixes assigned to it. Phase 3 and
its whole-review hardening repaired the Overlay trust model and related
cross-plane failures. Phase 2 is still outstanding, as are the Phase 4
closed-list, unknown-tool, native-web, case/matching, and false-positive items.
The current ledger is 16 fixed, 2 partially fixed, and 21 outstanding across 39
indexed entries.

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
| CRITICAL | 10 | 1 | 8 | 19 (16 numbered findings plus 3 addendum bullets) |
| HIGH | 4 | 0 | 7 | 11 |
| MEDIUM | 2 | 1 | 6 | 9 |
| **Total** | **16** | **2** | **21** | **39** |

## CRITICAL ledger

| Finding | Status | Remediation | Current source and regression evidence | Residual risk |
|---|---|---|---|---|
| **CR-1 Absolute-path invocation bypasses every rule — RC2** | **Fixed** | Phase 1, `v0.9.0-dev` | Command heads are reduced with `path.Base` in [`rules_bash.go:12-17`](../../internal/engine/rules_bash.go#L12-L17) and used across the Bash, git, Docker, and egress checks. Exact `/bin/rm`, `/usr/bin/sudo`, `/sbin/mkfs.ext4`, git, and curl locks are in [`rules_bash_test.go:18-47`](../../internal/engine/rules_bash_test.go#L18-L47); BusyBox and absolute launcher coverage is at [lines 50-85](../../internal/engine/rules_bash_test.go#L50-L85). | - |
| **CR-2 Quoting any operand defeats matching — RC1** | **Fixed** | Phase 1, `v0.9.0-dev` | `splitSimples` stores literal argv and redirect text and marks unresolved words in [`tokenize.go:16-56`](../../internal/engine/tokenize.go#L16-L56); unresolved words ask without masking stronger Verdicts in [`rules_bash.go:41-57`](../../internal/engine/rules_bash.go#L41-L57). Quoted rm/git/cat/curl/dd and redirect regressions are in [`tokenize_test.go:40-74`](../../internal/engine/tokenize_test.go#L40-L74). | - |
| **CR-3 `cd` is not tracked — relative operands resolve against the hook's cwd** | **Outstanding** | Phase 2 | `checkRmRf` still resolves each operand against only `tc.CWD` ([`rules_bash.go:90-108`](../../internal/engine/rules_bash.go#L90-L108)); `resolvePath` has no running statement-directory state ([lines 277-287](../../internal/engine/rules_bash.go#L277-L287)). There is no closing `cd`/`pushd` regression. | A preceding directory change can make a later relative destructive operand act outside the repository while the Engine evaluates it under the original CWD. |
| **CR-4 Redirect-only statements are discarded** | **Outstanding** | Phase 2 | `splitSimples` returns before collecting redirects when a statement has no call arguments ([`tokenize.go:27-30`](../../internal/engine/tokenize.go#L27-L30)); `checkBash` also skips empty argv ([`rules_bash.go:41-44`](../../internal/engine/rules_bash.go#L41-L44)). No redirect-only regression exists. | `> target` and descriptor-only truncation remain invisible to the Engine. |
| **CR-5 `git --git-dir <path>` (space form) bypasses every git rule** | **Outstanding** | Phase 2 | The shared git value-flag table still contains only `-C`, `-c`, and `--namespace` ([`rules_bash.go:132-151`](../../internal/engine/rules_bash.go#L132-L151)). The current regression covers only attached `--git-dir=/tmp/x` ([`rules_git_subcommand_test.go:9-19`](../../internal/engine/rules_git_subcommand_test.go#L9-L19)), not the reviewed space form. | Space-valued global git options can still be mistaken for the subcommand and bypass all git checks. |
| **CR-6 Force-push and remote-branch-delete via refspec** | **Outstanding** | Phase 2 | Push enforcement still checks force flags and whole non-flag tokens only ([`rules_git.go:64-77`](../../internal/engine/rules_git.go#L64-L77)); it does not parse `+src:dst`, `:dst`, or the destination side of a refspec. No refspec regression closes the reproductions. | Force pushes, remote deletion, and protected destination branches encoded as refspecs remain allowed. |
| **CR-7 Path dot-segments defeat every leaf-literal glob — RC3** | **Fixed** | Phase 1, `v0.9.0-dev` | Glob input is slash-normalized and `path.Clean`ed before full-path and basename matching in [`rules_path.go:542-553`](../../internal/engine/rules_path.go#L542-L553). Dot, repeated-separator, and parent-segment cases are locked in [`rules_path_test.go:52-66`](../../internal/engine/rules_path_test.go#L52-L66) and the adversarial corpus. | - |
| **CR-8 Write channels other than redirects are invisible — RC4** | **Fixed** | Phase 1, `v0.9.0-dev` | Known destination-taking mutators, all-target mutators, `dd of=`, and `sed -i` feed `writeCandidates` in [`rules_path.go:105-158`](../../internal/engine/rules_path.go#L105-L158) and [lines 276-324](../../internal/engine/rules_path.go#L276-L324). The exact cp/sed/install/dd/ln/tee/shell-rc reproductions are locked in [`rules_path_test.go:591-642`](../../internal/engine/rules_path_test.go#L591-L642). | -; broader unlisted primitives remain separately open under H-4. |
| **CR-9 Secret reads via any command outside the 14-name `pathReaders` list — RC4** | **Outstanding** | Phase 4 | Secret candidates are still collected only when the command basename is in the closed `pathReaders` map ([`rules_path.go:15-19`](../../internal/engine/rules_path.go#L15-L19), [lines 41-55](../../internal/engine/rules_path.go#L41-L55)). There is no closing regression for cp/base64/tar/dd/openssl/jq/python reads. | Any unlisted reader or encoded argument channel can still read a secret path without P4 seeing it. |
| **CR-10 Scheme-less URL fails host extraction open → egress bypass** | **Outstanding** | Phase 2 | `checkEgress` still returns no Verdict when host extraction returns empty ([`rules_net.go:82-90`](../../internal/engine/rules_net.go#L82-L90)); curl/wget extraction accepts only `url.Parse` results with a nonempty `Host` ([lines 98-106](../../internal/engine/rules_net.go#L98-L106)). No scheme-less-host lock exists. | curl/wget host tokens such as `evil.com/path` still fail open. |
| **CR-11 Fetch-then-execute with a stage in between — and CR-10 makes it unauthenticated** | **Outstanding** | Phase 2 | Fetch-to-interpreter detection still examines only adjacent simples ([`rules_net.go:22-32`](../../internal/engine/rules_net.go#L22-L32)). There is no three-stage pipeline regression. | An intermediate `tee`/`cat` stage still breaks detection; combined with CR-10 this remains an arbitrary-host execution path. |
| **CR-12 Session-id path traversal writes outside the state dir** | **Fixed** | Phase 1, `v0.9.0-dev` | `Path`, `Load`, and `Save` reject empty, dot, separator, and `..` IDs in [`session.go:35-75`](../../internal/session/session.go#L35-L75). The exact traversal is contained and checked for both write and read in [`session_test.go:50-109`](../../internal/session/session_test.go#L50-L109). | - |
| **CR-13 `docker compose -f` and the whole prune family** | **Outstanding** | Phase 2 | Docker matching still prefix-checks the joined raw arguments and recognizes only `docker` ([`rules_bash.go:179-203`](../../internal/engine/rules_bash.go#L179-L203)); runner unwrapping skips flag-looking tokens but does not consume their values ([`tokenize.go:346-361`](../../internal/engine/tokenize.go#L346-L361)). Current tests cover only the simple forms ([`rules_bash_test.go:118-145`](../../internal/engine/rules_bash_test.go#L118-L145)). | Global compose flags, alternate frontends, prune families, and valued run flags remain bypasses. |
| **CR-3 addendum: `waive` was unbounded.** | **Fixed** | Phase 3, `v0.11.0-dev` | Operator config grants are exact per cleaned absolute repository and the three fail-closed backstops are immutable ([`operator.go:13-31`](../../internal/policy/operator.go#L13-L31), [lines 97-126](../../internal/policy/operator.go#L97-L126)); Merge drops unauthorized Waiver requests ([`merge.go:96-108`](../../internal/policy/merge.go#L96-L108)). Unit locks are in [`merge_test.go:86-163`](../../internal/policy/merge_test.go#L86-L163) and [`operator_test.go:289-309`](../../internal/policy/operator_test.go#L289-L309); hostile-Overlay end-to-end evidence is in [`overlay_test.go:15-120`](../../test/adversarial/overlay_test.go#L15-L120). | - |
| **Slots widened globally, not repo-scoped.** | **Partially fixed** | Phase 3, `v0.11.0-dev` implementation | `secret_allow` and `audit_log` require exact-repository Boolean grants, while each egress entry requires an exact-repository, exact-entry grant ([`operator.go:21-31`](../../internal/policy/operator.go#L21-L31), [`operator.go:97-126`](../../internal/policy/operator.go#L97-L126), [`merge.go:65-94`](../../internal/policy/merge.go#L65-L94)). Safe roots must pass lexical and resolved repository containment ([`merge.go:41-63`](../../internal/policy/merge.go#L41-L63)). `checkPaths` proceeds from secret checks through resolved-path and symlink-escape checks ([`rules_path.go:56-69`](../../internal/engine/rules_path.go#L56-L69)). Existing regressions cover exact `secret_allow`/audit authorization and safe-root containment ([`merge_test.go:132-345`](../../internal/policy/merge_test.go#L132-L345)) plus refusal of an unauthorized Overlay's direct secret read ([`overlay_test.go:15-120`](../../test/adversarial/overlay_test.go#L15-L120)). | The exact combination of an authorized Overlay `SecretAllow` and an in-repository symlink escaping the repository has no regression test. The implementation appears corrected, but that missing lock leaves the evidence incomplete; no current bypass is claimed. |
| **"Logged" did not mean visible.** | **Fixed** | Phase 3, `v0.11.0-dev` | Merge warnings are included in Claude's SessionStart posture ([`hook.go:77-96`](../../cmd/guardrail/hook.go#L77-L96)) and universally in `guardrail doctor` ([`doctor.go:59-85`](../../cmd/guardrail/doctor.go#L59-L85)). Visibility and sanitization are locked in [`hook_test.go:717-766`](../../cmd/guardrail/hook_test.go#L717-L766) and [`doctor_test.go:79-145`](../../cmd/guardrail/doctor_test.go#L79-L145). OpenCode and Antigravity have no SessionStart posture; their generated integrations expose only pre-tool, or pre/post, events ([`opencode_plugin.js:43-55`](../../internal/genconfig/opencode_plugin.js#L43-L55), [`antigravity.go:7-31`](../../internal/genconfig/antigravity.go#L7-L31)). | - |
| **CR-14 The agent can write the file that configures its own guard** | **Fixed** | Phase 1, `v0.9.0-dev` | Engine self-config globs include `guardrail.toml`, `.guardrail`, OpenCode, Antigravity, and installed-binary paths in [`rules_path.go:340-353`](../../internal/engine/rules_path.go#L340-L353). Read/write behavior is locked in [`rules_path_test.go:178-200`](../../internal/engine/rules_path_test.go#L178-L200), with corresponding Claude/OpenCode Declarative floor tests in [`claude_test.go:99-134`](../../internal/genconfig/claude_test.go#L99-L134) and [`opencode_test.go:343-378`](../../internal/genconfig/opencode_test.go#L343-L378). | - |
| **CR-15 One Bash call removes the guard permanently — RC4** | **Fixed** | Phase 1, `v0.9.0-dev` | Argument-based mutator destinations flow into protected-path checks through [`rules_path.go:276-324`](../../internal/engine/rules_path.go#L276-L324); guard machinery and the installed binary are protected at [lines 340-353](../../internal/engine/rules_path.go#L340-L353). Exact settings removal and binary replacement reproductions are in [`rules_path_test.go:620-642`](../../internal/engine/rules_path_test.go#L620-L642). | - |
| **CR-16 opencode: `$GUARDRAIL_BIN`/`$PATH` bypass, and `--binary` is silently discarded** | **Fixed** | Phase 1, `v0.9.0-dev` | The generated Adapter receives a JSON-escaped absolute binary path and accepts only an explicit allow response in [`opencode_plugin.js:8-40`](../../internal/genconfig/opencode_plugin.js#L8-L40). Exact-path execution and empty/malformed/unknown response locks are in [`opencode_test.go:180-309`](../../internal/genconfig/opencode_test.go#L180-L309). | - |

The root-cause picture is therefore mixed: RC1, RC2, and RC3 are fixed in Phase
1. RC4 is only split into fixed reviewed mutator channels (CR-8/CR-15) and still
open reader/unknown-channel coverage (CR-9, H-4, H-10).

## HIGH ledger

| Finding | Status | Remediation | Current source and regression evidence | Residual risk |
|---|---|---|---|---|
| **H-1 A junk wrapper flag downgrades DENY to ASK** | **Outstanding** | Phase 2 | `checkBash` normalizes the entire call once and immediately returns `ask/tokenize-failed` on any normalization error ([`rules_bash.go:19-27`](../../internal/engine/rules_bash.go#L19-L27)). No per-statement survival regression exists. | A malformed later statement can still replace an earlier concrete deny with an ask. |
| **H-2 `.env.example` basename-matching neutralizes the strongest globs** | **Outstanding** | Phase 4 | `SecretAllow` uses the same matcher as deny globs ([`rules_path.go:86-89`](../../internal/engine/rules_path.go#L86-L89)), and that matcher still falls back to basename at [lines 542-551](../../internal/engine/rules_path.go#L542-L551). Current tests explicitly allow `.env.example` but do not prohibit the reviewed cross-directory laundering ([`rules_path_test.go:12-49`](../../internal/engine/rules_path_test.go#L12-L49)). | A permitted basename can still override a stronger full-path secret classification, including through a symlink. |
| **H-3 Wrapper strip-list holes** | **Outstanding** | Phase 2 | The normalization switch remains a closed list (`env`, `timeout`, `nice`, `nohup`, `xargs`, `exec`, `command`, `time`, `eval`, `builtin`) in [`tokenize.go:77-111`](../../internal/engine/tokenize.go#L77-L111); the reviewed wrappers and privilege launchers are absent. No closing regressions exist. | Listed missing wrappers can still conceal destructive inner commands. |
| **H-4 Uncovered destructive primitives** | **Outstanding** | Phase 2 | P1 still covers a finite primitive set: recursive/forced `rm`, selected disk destroyers, a few Docker prefixes, and selected ask-tier commands ([`rules_bash.go:90-109`](../../internal/engine/rules_bash.go#L90-L109), [lines 179-270](../../internal/engine/rules_bash.go#L179-L270)). Git safety has no cases for `update-ref`, worktree removal, switch discard, or `git rm` ([`rules_git.go:7-80`](../../internal/engine/rules_git.go#L7-L80)). No exhaustive reproduction lock exists. | The original mv/cp/tee/ln/rsync/find/git/ssh destructive examples remain outside command-level protection unless a separate protected-path rule happens to catch their target. |
| **H-5 Symlink laundering outside the repo** | **Fixed** | Phase 3 whole-review hardening, `v0.11.0-dev` | Every visible read candidate is rechecked after resolution in [`rules_path.go:41-69`](../../internal/engine/rules_path.go#L41-L69); write targets are checked lexically and after resolution at [lines 355-368](../../internal/engine/rules_path.go#L355-L368). Existing outside aliases are locked by [`rules_path_test.go:103-145`](../../internal/engine/rules_path_test.go#L103-L145) and Operator config aliases by [lines 234-350](../../internal/engine/rules_path_test.go#L234-L350). Missing leaves and symlink/`..` ordering are implemented in [`pathutil/resolve.go:8-40`](../../internal/pathutil/resolve.go#L8-L40) and locked in [`resolve_test.go:61-104`](../../internal/pathutil/resolve_test.go#L61-L104). | - |
| **H-6 WebFetch / WebSearch / Task / NotebookEdit are entirely ungated** | **Outstanding** | Phase 4 | Claude parsing retains only `command` and `file_path`, not native URL/query/notebook fields ([`claude.go:14-22`](../../internal/adapter/claude.go#L14-L22)); network signaling explicitly returns false for non-Bash calls ([`trifecta_signals.go:40-55`](../../internal/engine/trifecta_signals.go#L40-L55)). No native-tool egress/trifecta regression closes the finding. | Native network tools can bypass P6 and the trifecta network leg; unknown native write tools can bypass path protection. |
| **H-7 Case-sensitive globs** | **Outstanding** | Phase 4 | Secret matching still calls case-sensitive `doublestar.Match` without filesystem-aware folding ([`rules_path.go:542-551`](../../internal/engine/rules_path.go#L542-L551)). No APFS/NTFS case variant regression exists. | Case variants can reach the same protected file on case-insensitive filesystems. |
| **H-8 `audit_log` overlay = silencing + arbitrary append.** | **Fixed** | Phase 3, `v0.11.0-dev` | Operator config exposes an exact-repository Boolean grant ([`operator.go:97-121`](../../internal/policy/operator.go#L97-L121)); Merge retains the Base audit path unless granted ([`merge.go:87-94`](../../internal/policy/merge.go#L87-L94)). Exact-boundary and no-authorization locks are in [`merge_test.go:132-192`](../../internal/policy/merge_test.go#L132-L192), with hostile `/dev/null` integration in [`overlay_test.go:15-120`](../../test/adversarial/overlay_test.go#L15-L120). | - |
| **H-9 Claude SessionStart `additionalContext` was an unbounded prompt-injection channel.** | **Fixed** | Phase 3, `v0.11.0-dev` | Waiver IDs are format-filtered and model-facing warnings are sanitized/capped in [`sanitize.go:11-51`](../../internal/adapter/sanitize.go#L11-L51); `PostureText` uses both at [`claude.go:89-102`](../../internal/adapter/claude.go#L89-L102). Unicode/control, rune-boundary, ID-format, and posture-cap locks are in [`sanitize_test.go:12-105`](../../internal/adapter/sanitize_test.go#L12-L105). | - |
| **H-10 Unknown tool names fail OPEN on all three planes.** | **Outstanding** | Phase 4 | All Adapter normalizers preserve unknown names ([`opencode.go:48-62`](../../internal/adapter/opencode.go#L48-L62), [`antigravity.go:70-82`](../../internal/adapter/antigravity.go#L70-L82)); `Evaluate` returns allow when no specialized check hits ([`evaluate.go:18-35`](../../internal/engine/evaluate.go#L18-L35)). OpenCode also forwards arbitrary tool names and only recognized path fields ([`opencode_plugin.js:43-55`](../../internal/genconfig/opencode_plugin.js#L43-L55)). There is no unknown-pre-tool deny regression. | New, missing, or misspelled tool names, including real write/network primitives, still fail open. This is additional to the report header's abbreviated outstanding list. |
| **H-11 No overlay size limit → hook timeout → guard skipped.** | **Fixed** | Phase 3, `v0.11.0-dev` | `LoadOverlay` rejects over 1 MiB both before opening and through a bounded reader in [`config.go:14-15`](../../internal/policy/config.go#L14-L15) and [lines 58-76](../../internal/policy/config.go#L58-L76). Boundary and malformed-oversize tests are in [`config_test.go:253-303`](../../internal/policy/config_test.go#L253-L303); Antigravity oversized-failure protocol coverage is in [`hook_test.go:644-674`](../../cmd/guardrail/hook_test.go#L644-L674). | - |

## MEDIUM ledger

| Finding | Status | Remediation | Current source and regression evidence | Residual risk |
|---|---|---|---|---|
| **M-1 `checkSelfConfig` and `checkGitProtectedPaths` fire on Read** | **Fixed** | Phase 1, `v0.9.0-dev` | Both checks now return early for non-writing file calls in [`rules_path.go:327-337`](../../internal/engine/rules_path.go#L327-L337) and [lines 355-358](../../internal/engine/rules_path.go#L355-L358). The exact instruction, global Claude, and git reads are allowed while writes remain denied in [`rules_path_test.go:535-589`](../../internal/engine/rules_path_test.go#L535-L589). | - |
| **M-2 `*.key` basename fallback denies ordinary source** | **Outstanding** | Phase 4 | `*.key` remains a Base secret glob ([`base.toml:9-21`](../../internal/policy/base.toml#L9-L21)), and matching still includes basename fallback ([`rules_path.go:542-551`](../../internal/engine/rules_path.go#L542-L551)). Current matcher tests exercise the Base-shaped glob at [`rules_path_test.go:12-49`](../../internal/engine/rules_path_test.go#L12-L49), but no ordinary-source `.key` allow regression exists. | Common translation/config source files still receive false denials. |
| **M-3 Test fixtures blocked** | **Outstanding** | Phase 4 | Base secret globs still include `id_rsa*`, `*.pem`, `*.key`, and `service-account*.json`, while Base allowances do not cover public keys, testdata, or fixtures ([`base.toml:9-21`](../../internal/policy/base.toml#L9-L21)). The matcher tests only demonstrate the current narrow allowance behavior ([`rules_path_test.go:12-49`](../../internal/engine/rules_path_test.go#L12-L49)); no fixture allowance is implemented or tested. | Public keys and intentionally fake fixture credentials still create routine false positives. |
| **M-4 `ciInfraLockGlobs` basename matching gates routine work** | **Outstanding** | Phase 4 | Broad basename patterns remain in [`rules_path.go:499-506`](../../internal/engine/rules_path.go#L499-L506), and `checkCIInfraLockfile` still uses the basename-fallback matcher ([lines 508-522](../../internal/engine/rules_path.go#L508-L522)). Current tests assert asks for root examples only ([`rules_path_test.go:753-769`](../../internal/engine/rules_path_test.go#L753-L769)). | Nested Makefiles, Dockerfiles, `conftest.py`, `setup.py`, and Terraform files continue to prompt and create fatigue. |
| **M-5 `selfConfigGlobs` basename fallback blocks agent-doc repos** | **Outstanding** | Phase 4 | `CLAUDE.md` and `AGENTS.md` remain basename patterns ([`rules_path.go:340-353`](../../internal/engine/rules_path.go#L340-L353)) evaluated with basename fallback ([lines 542-551](../../internal/engine/rules_path.go#L542-L551)). No fixture/template path allowance is tested. | Repositories that author agent documentation still cannot write nested fixtures without a deny. |
| **M-6 `git clean -n` dry-runs are denied** | **Outstanding** | Phase 4 | `git clean` denies if any of `f`, `x`, or `d` is present and does not short-circuit on `-n`/`--dry-run` ([`rules_bash.go:123-127`](../../internal/engine/rules_bash.go#L123-L127)). The existing allow lock covers only `git clean -n`, not the reviewed `git clean -nxd` ([`rules_bash_test.go:135-145`](../../internal/engine/rules_bash_test.go#L135-L145)). | Canonical dry-run previews with selection flags remain false denials. |
| **M-7 Trifecta: session state is deletable and racy** | **Outstanding** | Phase 4 | Session persistence remains unlocked `ReadFile`/`WriteFile` ([`session.go:53-90`](../../internal/session/session.go#L53-L90)); empty IDs still disable state ([lines 35-50](../../internal/session/session.go#L35-L50)); flagless `rm` receives no P1 Verdict ([`rules_bash.go:90-101`](../../internal/engine/rules_bash.go#L90-L101)). No concurrency/deletion regression exists. | State legs can still be lost to races, deleted by the plane, or disabled by an empty session ID. |
| **M-8 Deny `Reason` was `Fprintf`'d unescaped into Claude's model-facing block channel.** | **Fixed** | Phase 3, `v0.11.0-dev` | Every Adapter sanitizes model-facing reasons; Claude applies it before both stderr and ask JSON ([`claude.go:64-86`](../../internal/adapter/claude.go#L64-L86)), with common Unicode-safe control normalization and rune capping in [`sanitize.go:11-21`](../../internal/adapter/sanitize.go#L11-L21) and [`safetext.go:9-20`](../../internal/safetext/safetext.go#L9-L20). Per-plane reason regressions are in [`claude_emit_test.go:19-47`](../../internal/adapter/claude_emit_test.go#L19-L47), [`opencode_test.go:44-68`](../../internal/adapter/opencode_test.go#L44-L68), and [`antigravity_test.go:65-81`](../../internal/adapter/antigravity_test.go#L65-L81). | - |
| **M-9 macOS installs no guard at all.** | **Partially fixed** | Phase 1 chezmoi branch only; **not in either Engine tag** | The separate chezmoi branch `guardrail-remediation-phase1` contains commit `6b882d0` and current branch source resolves `sha256sum`, `gsha256sum`, or `shasum -a 256` in `run_onchange_install_packages.sh.tmpl:340-348` and `scripts/update_ai_tools.sh:78-90`. The installer pin remains `v0.7.0-dev`, and the remediation branch remains unmerged, unapplied, and unpushed, as recorded in [`README.md:15-21`](../../README.md#L15-L21). The Phase 1 plan explicitly prohibited advancing the pin ([`2026-09-04-remediation-phase1.md:955-963`](../superpowers/plans/2026-09-04-remediation-phase1.md#L955-L963)). No regression test in this repository can prove deployment of that external patch. | The patch is unmerged, unapplied, and unpushed, so stock-macOS installation remains unfixed in the deployed chezmoi path. |

## Outstanding work, explicitly reconciled

The original report's explicit Phase 2 line names **CR-3, CR-4, CR-5, CR-6,
CR-10, CR-11, CR-13, and H-1**. Current source confirms every one remains open.
The Phase 1 roadmap additionally assigns **H-3 and H-4** to Phase 2
([plan lines 967-973](../superpowers/plans/2026-09-04-remediation-phase1.md#L967-L973));
they also remain open.

The report header is not an exhaustive open-finding summary. Current source also
proves these unannotated numbered findings remain outstanding:

- **CR-9**: the secret-reader closed list remains.
- **H-2, H-6, H-7, H-10**: basename laundering, native tool gating,
  case-sensitive matching, and unknown tool fail-open behavior remain.
- **M-2 through M-7**: the matching false positives and trifecta state defects
  remain.

These are consistent with the Phase 4 roadmap, except H-3/H-4, which are already
assigned to Phase 2. No finding has been inferred fixed merely because a phase
landed.

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
  ([`rules_path.go:369-496`](../../internal/engine/rules_path.go#L369-L496),
  [`rules_path_test.go:352-533`](../../internal/engine/rules_path_test.go#L352-L533)).
  The controls deliberately show dynamically assembled path fragments still
  allow ([`rules_path_test.go:372-385`](../../internal/engine/rules_path_test.go#L372-L385));
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
- Fresh response verification also passed `make check`, uncached
  `/usr/local/go/bin/go test ./... -count=1`, and `git diff --check`.
- GitHub Actions independently passed the final-hash
  [Linux/Windows CI run](https://github.com/CtrlCarlitos/agent-guardrails/actions/runs/33964721003),
  including build/vet on both systems and the full test plus gofmt checks on
  Linux. The
  [release run](https://github.com/CtrlCarlitos/agent-guardrails/actions/runs/33964730547)
  published six platform binaries and checksums.
- The adversarial corpus is exactly **147 cases: 29 allow, 5 ask, 113 deny**.
  The harness validates the plane response and matching audit record rather than
  classifying an exit status alone
  ([`adversarial_test.go:92-170`](../../test/adversarial/adversarial_test.go#L92-L170)).
- Fresh publication checks confirmed that local and remote `v0.11.0-dev` both
  resolve to **`a2965681e4ea552f8b29b329fd8b6a2ee513a395`** and that its GitHub
  Release contains six platform binaries plus `SHA256SUMS`. This response was
  authored later and is not in that tagged snapshot.

## Explicit non-claims

- Phase 2 is still open; the eight findings in the original Phase 2 line and
  H-3/H-4 have not been remediated.
- The installer pin is still `v0.7.0-dev`; the chezmoi M-9 branch has not been
  merged, applied, or pushed. Publishing `v0.11.0-dev` did not advance the pin.
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
