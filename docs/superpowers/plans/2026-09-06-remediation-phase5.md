# Adversarial Remediation Phase 5 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close H-6, H-10, M-7, NF-3 through NF-11 (including NF-5b), and the observed opaque-executor self-config write gap without relaxing protection outside the explicitly approved temp-root and Git-config refinements.

**Architecture:** Keep the Engine authoritative and make each plane deliver enough normalized evidence for it to evaluate. Separate plane invocation and payload coverage, native-network policy, session integrity, production-friction fixes, retired native-floor cleanup, disabled-hook reconciliation, opaque-source uncertainty, and additive audit context so each change has its own RED tests and review gate.

**Tech Stack:** Go 1.23+, JavaScript for the embedded OpenCode adapter, existing dependencies only unless a session-lock design proves that one small portability dependency is necessary.

**Spec:** `../../reviews/2026-09-04-adversarial-review.md`, NF-3 and opaque-write evidence in commit `c4509fd1358b5613450a11fc96c75e4489f0a75c`, NF-4/5/6 evidence in commit `5fb66a03339ae993b69df72745ab39a1867b098a`, the operator-approved NF-7/8/9 and NF-5b whole-log review additions, and the NF-10/NF-11 live guard findings from 2026-09-07. Carlitos ratified NF-8 as implemented on 2026-09-07.

## Global Constraints

- The Engine remains the single owner of policy semantics. Adapters normalize native payloads; generated configuration makes sure the Engine is invoked.
- Verdict aggregation remains strongest-first: Deny outranks Ask, and Ask outranks Allow.
- Zero existing adversarial-corpus entries may be removed or relaxed.
- `P3.unresolved` remains an unwaivable fail-closed backstop. Any actually unresolved word in a path-bearing or other policy-bearing position must Ask.
- NF-8 is ratified as implemented: runtime Base temp authorization covers strict descendants for `rm` and `P1.redirect`, while roots and `..` escapes remain protected. It preserves HEAD's existing temp-destination behavior for `cp`, `mv`, `ln`, `tee`, `install`, and deleting `rsync`; it does not populate Overlay safe roots or weaken secret, self-config, git-protected, or CI/infra checks.
- Native network calls remain subject to the existing `P6.egress` waiver. Waiving P6 never disables the independent P7 network signal.
- Unknown tools with no visible path or network evidence remain Allow unless another existing rule matches.
- Every plane-facing task requires generated-config or adapter-contract coverage in addition to Engine unit tests.
- Do not edit the external chezmoi repository from this repository. Record exact external follow-up commands instead.
- Do not push or tag automatically. Each implementation task stops after local verification and a reviewable commit.
- NF-4 through NF-9, including NF-5b, are complete and shipped as `v0.14.0-dev` at `09cd998`. Task 4 below is a completion record, not remaining work. Carlitos ratified NF-8.
- Execute the remaining work in this order: Task 4b (NF-10), Task 1 (H-10), Task 2 (H-6), Task 3 (M-7), Task 5 (NF-3), Task 6 (opaque-executor self-config writes), then Task 7 (NF-11, corpus, docs, and ledger).
- Start every remaining task from current local `main` on its own branch in a dedicated worktree. Commit locally, run the independent gate and probes, and stop for Carlitos's review before merge. Do not push.
- Phase 5 targets `v0.15.0-dev` only after Task 7 closes. Version changes, publication, deployment, and tags remain operator actions.

## Preflight Findings

The original plan predated Phase 4 and contained incorrect implementation premises. This table is the required pre-Task-1 report.

| Finding | Verified behavior at `c4509fd` | Correction locked by this revision |
|---|---|---|
| H-10 | Claude and Antigravity pre-hook matchers exclude unknown tools. OpenCode already receives every tool but its embedded adapter keeps only the first recognized path. All Go adapters lose additional path fields. Unknown tools also fall through write-only gates, including `checkOutOfRepoWrite`. | Widen only the generated pre-hook matchers that are closed; collect every visible path in stable order; classify the complete read-only alias set; run all five path gates; preserve Allow for pathless unknown tools. |
| H-6 | `IsNetworkAttempt` rejects every non-Bash call. Claude `WebFetch`/`WebSearch`, OpenCode `webfetch`/`websearch`, and Antigravity `read_url_content`/`search_web` currently Allow and do not arm P7. | Cover all three planes. URL-bearing native fetches use P6 host policy. URL-less search tools arm P7 without inventing a new unconditional Ask rule or a `Query` field. |
| M-7 | Flagless `rm` deletes session state; concurrent hooks lost a signal in 13/100 probes; empty IDs silently disable P7; nonempty IDs are not portable filenames. | Protect session storage in both Engine and Claude's Declarative floor, serialize the complete evaluate-and-update transaction without an unlocked fallback, hash nonempty IDs, and surface unavailable tracking on a model-visible Ask path. |
| NF-3 | `doctor` notices an absent active hook, but a disabled hook cannot run `doctor`. Claude parks disabled entries under `hooks_disabled`, and current merge code does not reconcile that store. | Detect and report disabled owned entries through `doctor`, Claude posture when SessionStart remains active, and the external updater. Preserve intentional disables during ordinary merges; only the installer's explicit owned-entry merge may re-arm them. |
| Opaque self-config writes | Literal Python source naming `~/.claude/settings.json` can Allow while direct `Write` Denies. Opaque paths feed secret-read candidates, not uncertain write candidates. Quoted heredoc bodies are not present in normalized `Simple.Argv`. | Extract visible literal paths from `-c` source and heredoc bodies. A self-config path whose read/write intent is opaque Ask; a definite self-config write still Denies. Dynamic path construction remains outside the static boundary. |
| NF-4 | Redirects to `/dev/null`, `/dev/stdout`, `/dev/stderr`, and `/dev/tty` Ask under `P1.redirect`. Mutator destinations are a separate code path. | Exempt only exact cleaned redirect targets at the redirect-authorization seam. Do not exempt the same paths from `cp`, `tee`, `dd`, file tools, or opaque-write checks. |
| NF-5 | A command-wide `Simple.Unresolved` bit makes inert data such as `echo "$?"` Ask. Shell state tracks `cd`, not prior literal assignments. | Preserve expansion provenance per argument and redirect, join it to operand roles, and resolve only quoted expansions from prior unconditional literal assignments. |
| NF-5b | Literal-assigned variables resolve as standalone quoted words, but embedded unquoted prefixes such as `$S/run.sh` and `$SP/tlp/x` remain unresolved. | Resolve plain known parameter prefixes when field splitting and glob expansion cannot change the word; retain P3 for unknown, operated, split-prone, or glob-prone values. |
| NF-6 | Claude scratch redirects Ask, but payload fixtures do not prove a stable cross-version project/session path encoding. | Close NF-6 through the approved NF-8 system-temp descendant rule instead of adding a Claude-specific `ToolCall` field or trusting an inferred scratch path. |
| NF-7 | `P2.git-config-write` Denied all 11 observed writes, all of which were routine `user.email`/`user.name` writes in fixture repositories. Claude and OpenCode also carry a broad native `git config *` Deny. | Parse mutation, scope, and key. Deny high-risk keys and global/system writes, Allow the approved low-risk key families locally, and Ask on unknown local keys. Narrow the Declarative floor in the same change. |
| NF-8 | Redirect and destructive-rm authorization do not treat system temp descendants as Base-authorized. The whole log contains 75 scratchpad and 72 other temp redirects beyond the 988 `/dev/null` redirects. | Treat descendants of `$TMPDIR`/`os.TempDir()`, `/tmp`, and `/var/tmp` as Base-authorized only for `rm` and `P1.redirect`; never authorize a temp root itself. This approved general rule subsumes NF-6 without a Claude-specific payload field. |
| NF-9 | `find <scratch>/t -delete` and `find <scratch>/t -exec rm -rf {} +` Ask even though the complete deletion scope is a trusted scratch descendant. | Parse every `find` starting root and exempt only `-delete` or direct `-exec`/`-execdir rm` whose operands are match placeholders, when every root is outside the repository and authorized by NF-8 system-temp roots. |
| NF-10 | Fresh generation removed broad `rm -rf *`-family Denies but retained `find * -delete`; installed Claude/OpenCode settings also retain retired generated permissions because merges only accumulate rules. Native permissions therefore pre-empt NF-8/NF-9 before the Engine runs. | Remove `find * -delete` from fresh generation and retire exactly the four broad `rm` patterns plus `find * -delete` during Claude/OpenCode settings merge. Preserve catastrophic literals and `srm *`; prove existing installations are migrated. |
| NF-11 | Audit records identify session, plane, tool, and visible operands but omit execution location. | Add optional `cwd` and `repo_root` fields to the additive JSONL schema and populate both from every normalized tool call. Document that subagents share the parent's `session_id`; location fields provide context, not a new session boundary. |

---

### Task 1: H-10 - Route Unknown Tools and Every Visible Path

**Files:**
- Modify: `internal/genconfig/claude.go`
- Modify: `internal/genconfig/antigravity.go`
- Modify: `internal/genconfig/opencode_plugin.js`
- Modify: `internal/adapter/claude.go`
- Modify: `internal/adapter/opencode.go`
- Modify: `internal/adapter/antigravity.go`
- Modify: `internal/engine/rules_path.go`
- Test: `internal/genconfig/claude_test.go`
- Test: `internal/genconfig/antigravity_test.go`
- Test: `internal/genconfig/opencode_test.go`
- Test: `internal/adapter/claude_test.go`
- Test: `internal/adapter/antigravity_test.go`
- Test: `internal/engine/rules_path_test.go`
- Test: `test/genconfig_test.go` and generated goldens

**Interfaces:**
- `ToolCall.Paths` contains every visible value carried by known path keys, de-duplicated in encounter order.
- Recognized keys are `file_path`, `path`, `notebook_path`, `filePath`, `absolute_path`, `AbsolutePath`, `TargetFile`, `dirPath`, and `directory`, including path entries inside `edits` and `changes` arrays.
- Known read-only aliases are case-insensitive: `Read`, `List`, `Glob`, `Grep`, `lsp`, `grep_search`, `list_dir`, `view_file`, `WebFetch`, `WebSearch`, `webfetch`, `websearch`, `search_web`, and `read_url_content`.
- A path-bearing unknown tool is write-uncertain and reaches secret, git-protected, self-config, CI/infra/lockfile, and out-of-repository checks. A pathless unknown tool remains unaffected.

- [ ] **Step 0: Create the dedicated Task 1 worktree from local main**

```bash
git worktree add ../agent-guardrails-phase5-task1 -b phase5-task1-h10 main
```

- [ ] **Step 1: Add RED adapter tests for complete extraction**

Use payloads containing both a safe first path and protected later paths. Assert that all paths survive normalization, rather than asserting only the first match.

```json
{"cwd":"/repo","tool_name":"FutureTool","tool_input":{"path":"/repo/readme.md","file_path":"/home/u/.ssh/id_rsa","changes":[{"file_path":"/repo/.github/workflows/ci.yml"}]}}
```

```json
{"conversationId":"s1","workspacePaths":["/repo"],"toolCall":{"name":"future_tool","args":{"AbsolutePath":"/repo/readme.md","TargetFile":"/home/u/.ssh/id_rsa"}}}
```

For OpenCode, update the embedded-plugin test so `args` with `path`, `filePath`, and `changes[].file_path` emits one `paths` array containing all three values.

- [ ] **Step 2: Add RED generated-matcher tests**

Assert Claude `PreToolUse.matcher == "*"` and Antigravity `PreToolUse.matcher == "*"`. Assert their post-tool matchers remain restricted to known editing tools. Assert the OpenCode plugin continues to register `tool.execute.before` without a tool-name filter.

- [ ] **Step 3: Add RED Engine tests for every gate**

Use `SomeFutureTool` with the following cases:

| Paths | Expected Verdict |
|---|---|
| `[]` | Allow |
| `[/repo/readme.md, /home/u/.ssh/id_rsa]` | Deny `P4.secret-path` |
| `[/repo/readme.md, /repo/.git/config]` | Deny `P2.git-protected-path` |
| `[/repo/readme.md, /repo/.claude/settings.json]` | Deny `P5.self-config` |
| `[/repo/readme.md, /repo/.github/workflows/ci.yml]` | Ask `P5.ci-infra-lockfile` |
| `[/repo/readme.md, /outside/result.txt]` | Ask `P5.out-of-repo` |

Repeat the protected-path controls with `List`, `lsp`, `grep_search`, `list_dir`, `view_file`, and the native network read aliases; these tools may trigger secret-read policy but must not be treated as writers.

- [ ] **Step 4: Run the RED tests**

```bash
/usr/local/go/bin/go test ./internal/adapter ./internal/engine ./internal/genconfig ./test -run 'Unknown|Alternate|Matcher|Golden' -count=1
```

Expected: failures show closed matchers, first-path-only extraction, and unknown-tool gate bypasses.

- [ ] **Step 5: Implement the minimal routing change**

Widen the two closed pre-hook matchers, collect all recognized path fields in the plane adapters, and remove closed file-tool guards from candidate construction. Keep one centralized case-insensitive read-only classifier. Do not recursively classify arbitrary strings as paths, and do not turn pathless custom/MCP tools into Ask.

- [ ] **Step 6: Regenerate and inspect goldens**

```bash
/usr/local/go/bin/go test ./test -run Golden -update
git diff -- test/fixtures internal/genconfig/opencode_plugin.js
```

Expected: generated matcher and OpenCode adapter changes only; no unrelated permission relaxation.

- [ ] **Step 7: Measure installed-binary latency and confirm wildcard delivery**

Changing the matcher to `"*"` makes the pre-hook run on every Claude and Antigravity tool call, including pathless `TodoWrite` and `Task` calls. This is production work, not a unit-test inference.

Before implementation, record a baseline by invoking the installed `~/.local/bin/guardrail` directly with valid pathless Claude `TodoWrite`, Claude `Task`, and an already matched harmless control payload. Run 100 warm invocations per payload and record total, median, and p95 wall-clock latency. After implementation, build the candidate binary and run the identical probe; report both result sets and investigate any material candidate regression. Do not substitute `go test` benchmark output for this process-level measurement.

Invoke one harmless pathless custom tool in Claude and Antigravity and confirm the wildcard pre-hook runs without changing the Allow Verdict. Explicitly probe `TodoWrite` and `Task` in Claude because both now incur hook startup and evaluation. If either plane does not support `"*"`, record the observed native wildcard syntax and update its generated-config test before proceeding.

- [ ] **Step 8: Verify and commit locally**

```bash
/usr/local/go/bin/gofmt -w internal/adapter/claude.go internal/adapter/antigravity.go internal/engine/rules_path.go internal/genconfig/claude.go internal/genconfig/antigravity.go
/usr/local/go/bin/go test ./... -count=1
git diff --check
git add internal test
git commit -m "fix: route unknown tool paths through every gate (H-10)"
```

---

### Task 2: H-6 - Apply Native Network Policy Across All Planes

**Files:**
- Modify: `internal/engine/toolcall.go`
- Modify: `internal/engine/rules_net.go`
- Modify: `internal/engine/evaluate.go`
- Modify: `internal/engine/trifecta_signals.go`
- Modify: `internal/adapter/claude.go`
- Modify: `internal/adapter/opencode.go`
- Modify: `internal/adapter/antigravity.go`
- Modify: `internal/genconfig/opencode_plugin.js`
- Test: `internal/adapter/claude_test.go`
- Test: `internal/adapter/opencode_test.go`
- Test: `internal/adapter/antigravity_test.go`
- Test: corresponding Engine, hook, and generated-config tests

**Interfaces:**
- `ToolCall` gains `URL string` for a visible native-network destination. It does not gain `Query`; policy does not need search text.
- The OpenCode plugin writes `url` into its JSON envelope from `args.url`; `opencodePayload.URL` reads that field and `ParseOpencode` copies it to `ToolCall.URL`.
- Native network aliases are case-insensitive: Claude `WebFetch` and `WebSearch`, OpenCode `webfetch` and `websearch`, Antigravity `read_url_content` and `search_web`.
- `IsNetworkAttempt` returns true for all six aliases, whether or not a destination URL is present.
- A native network call with a visible URL reuses `P6.egress` host parsing, local-host handling, allowlist, reason shape, and waiver behavior.
- A URL-less search has no host to evaluate, so it produces no standalone P6 Verdict. It still arms P7.

- [ ] **Step 0: Create the dedicated Task 2 worktree from reviewed local main**

```bash
git worktree add ../agent-guardrails-phase5-task2 -b phase5-task2-h6 main
```

- [ ] **Step 1: Capture live plane contracts before writing fixtures**

Capture one fetch and one search payload from each installed plane. Record the actual native tool names and URL keys, especially Antigravity. If a plane is unavailable, stop that plane's H-6 work and report the missing contract rather than encoding a guessed fixture.

- [ ] **Step 2: Add RED adapter contract tests**

For each plane, parse a URL-bearing fetch payload and assert `ToolCall.URL`. Parse its search payload and assert no fabricated destination. Assert tool identity is retained so `IsNetworkAttempt` can recognize both forms. The tests must cover Claude `tool_input.url`, OpenCode `args.url` through the generated envelope and `ParseOpencode`, and Antigravity's verified native URL key.

- [ ] **Step 3: Add RED Engine policy tests**

```text
WebFetch https://api.github.com/repos/x, allowlist api.github.com -> Allow
WebFetch https://evil.example/steal, allowlist api.github.com -> Deny P6.egress
webfetch https://evil.example/steal -> Deny P6.egress
read_url_content https://evil.example/steal -> Deny P6.egress
WebSearch with no URL -> Allow and IsNetworkAttempt true
websearch with no URL -> Allow and IsNetworkAttempt true
search_web with no URL -> Allow and IsNetworkAttempt true
```

Repeat the off-allowlist case with `pol.Waived["P6.egress"] = true`: the P6 Deny disappears, but `IsNetworkAttempt` remains true.

- [ ] **Step 4: Add RED P7 sequence tests through `cmdHook`**

For Claude, OpenCode, and Antigravity, use a fresh session, perform a private read with its P4 Verdict explicitly waived in the test policy, then an allowlisted native fetch. The second call must Ask `P7.trifecta`. For reverse ordering, perform the allowlisted fetch first and again waive the private read's P4 Verdict so P7 can escalate its otherwise-Allow Verdict. Add a control proving the ordinary unwaived private read remains Deny under strongest-first aggregation. Repeat with URL-less search ordering. These tests prove both plane delivery and Engine state, not only helper behavior.

- [ ] **Step 5: Run the RED tests**

```bash
/usr/local/go/bin/go test ./internal/adapter ./internal/engine ./cmd/guardrail -run 'Native|Web|Trifecta' -count=1
```

- [ ] **Step 6: Implement native destination normalization and evaluation**

Keep network-tool identity in the Engine, not the generated matchers. Reuse the current host allowlist helpers and `P6.egress`; do not add `P6.web-search`, log query text, or bypass the normal waiver-aware strongest-Verdict aggregation.

- [ ] **Step 7: Verify and commit locally**

```bash
/usr/local/go/bin/gofmt -w internal/engine/toolcall.go internal/engine/rules_net.go internal/engine/evaluate.go internal/engine/trifecta_signals.go internal/adapter/claude.go internal/adapter/opencode.go internal/adapter/antigravity.go
/usr/local/go/bin/go test ./... -count=1
git diff --check
git add internal cmd test
git commit -m "fix: enforce native network policy across planes (H-6)"
```

---

### Task 3: M-7 - Make Session Tracking Durable and Non-Bypassable

**Files:**
- Modify: `internal/session/session.go`
- Modify: `cmd/guardrail/hook.go`
- Modify: `internal/engine/rules_path.go`
- Modify: `internal/genconfig/claude.go`
- Test: `internal/session/session_test.go`
- Test: `cmd/guardrail/hook_test.go`
- Test: `internal/engine/rules_path_test.go`
- Test: `internal/genconfig/claude_test.go`

**Interfaces:**
- Any nonempty native session ID maps to a fixed-length portable storage key using SHA-256; raw IDs never become filenames.
- The session package exposes one transaction that loads state, evaluates the caller callback, and persists the updated state under exclusive cross-process serialization.
- Lock acquisition never falls back to an unlocked write. A crashed process cannot leave later sessions blocked indefinitely. A bounded acquisition failure is returned to the caller without overwriting state.
- Missing session IDs and transaction failures escalate an otherwise-Allow private-data or network signal to a model-visible Ask when P7 is active. Existing Ask and Deny Verdicts remain unchanged. Routine calls that carry neither signal are not interrupted.

- [ ] **Step 0: Create the dedicated Task 3 worktree from reviewed local main**

```bash
git worktree add ../agent-guardrails-phase5-task3 -b phase5-task3-m7 main
```

- [ ] **Step 1: Add RED storage-key tests**

Cover empty IDs, `/`, `\\`, `..`, colons, control characters, and a 4 KiB ID. Empty remains invalid. Every nonempty value maps deterministically to a portable fixed-length key and cannot escape the session directory.

- [ ] **Step 2: Add RED concurrency and crash-recovery tests**

Run at least 100 concurrent private/network updates against one session and assert both monotonic bits survive every run. Add a subprocess test that exits while holding the transaction primitive, then prove the next process can acquire and update without an unlocked fallback.

```bash
/usr/local/go/bin/go test ./internal/session -run 'Concurrent|Crash|Portable' -race -count=100
```

- [ ] **Step 3: Add RED deletion-protection tests**

Assert Bash `rm` of Linux, macOS/XDG, and Windows session-store forms Denies as `P5.self-config`. Update the duplicated Claude self-config path list for direct file-tool edits and add coarse `Bash(rm *guardrail/sessions/*)` and Windows-equivalent entries to `bashDenyGlobs` so flagless deletion retains a Declarative-floor fallback when the Engine is unavailable.

- [ ] **Step 4: Add RED hook tests for unavailable tracking**

With P7 active, an allowlisted native network call carrying no session ID must return a model-visible Ask with a P7 rule ID. Exercise the private-data signal with its ordinary P4 Verdict explicitly waived in the test policy so the underlying Verdict is Allow. Repeat with forced session transaction failure. Add controls proving existing Ask/Deny Verdicts are not downgraded. With `P7.trifecta` waived, preserve the normal underlying Verdict.

- [ ] **Step 5: Implement one serialized transaction**

Replace the `Load`/mutate/`Save` sequence in `cmdHook` with the transaction. Keep pruning best-effort, but do not let pruning delete active lock state or race the transaction. Reject any design based on permanent `O_CREATE|O_EXCL` lock files or a timeout that proceeds unlocked.

- [ ] **Step 6: Verify and commit locally**

```bash
/usr/local/go/bin/gofmt -w internal/session/session.go cmd/guardrail/hook.go internal/engine/rules_path.go internal/genconfig/claude.go
/usr/local/go/bin/go test ./internal/session ./cmd/guardrail ./internal/engine ./internal/genconfig -race -count=20
/usr/local/go/bin/go test ./... -count=1
git diff --check
git add internal cmd test
git commit -m "fix: make P7 session state durable and non-bypassable (M-7)"
```

---

### Task 4 Completion Record: NF-4 through NF-9 - Shipped in v0.14.0-dev

**Status:** Complete, independently reviewed, published, deployed, and enforcing. The shipped boundary is tag `v0.14.0-dev` at `09cd998`; this section records the work and is not an execution checklist. Carlitos ratified NF-8.

**Files:**
- Modify: `internal/engine/tokenize.go`
- Modify: `internal/engine/operands.go`
- Modify: `internal/engine/rules_bash.go`
- Modify: `internal/engine/rules_git.go`
- Modify: `internal/genconfig/claude.go`
- Test: `internal/engine/tokenize_test.go`
- Test: `internal/engine/rules_bash_test.go`
- Test: `internal/engine/rules_git_test.go`
- Test: `internal/genconfig/claude_test.go`
- Test: `internal/genconfig/opencode_test.go`
- Test: `test/genconfig_test.go` and generated goldens
- Test: `test/adversarial/corpus.json`

**Interfaces:**
- Standard output devices are a redirect-only exemption, not safe roots.
- `systemTempRoots() []string` returns unique, cleaned, non-filesystem-root Base roots from `os.TempDir()` and, on Unix, `/tmp` and `/var/tmp`.
- Temp authorization accepts physical descendants only and rejects each root itself. It is consumed by `checkRmRf`, `P1.redirect`, and NF-9's scoped `find` classification.
- Git-config mutation parsing returns operation, scope, and every normalized key or section subject before policy classification. Approved keys treat a repository whose resolved common directory is a strict system-temp descendant as local-equivalent; dangerous keys and global, system, file, worktree, edit, foreign, and uncertain cases retain their stronger Verdicts.
- `Simple` preserves literal, locally-resolved, or unresolved provenance per argument and redirect while retaining `Argv`, `Redirects`, and `ReadRedirects` for existing classifiers.
- `parsedOperand` retains its source argument index so operand role can be joined to expansion provenance, including attached option values.

- [x] **Step 1: Create the local review branch**

```bash
git switch -c phase5-task4
```

The branch was reviewed locally before publication.

#### NF-4: Standard Output Devices

- [x] **Step 2: Add RED redirect-only tests**

The following exact cleaned redirect targets must not independently trigger `P1.redirect`:

```text
ls x 2>/dev/null
echo x >/dev/stdout
echo x >/dev/stderr
echo x >/dev/tty
echo x >/dev/./null
```

Controls that retain current protection:

```text
echo x >/dev/sda                         -> Ask P1.redirect
echo x >/proc/self/fd/1                  -> Ask P1.redirect
cp /repo/x /dev/null                     -> Ask P1.out-of-repo-write
tee /dev/null                            -> Ask P1.out-of-repo-write
Write /dev/null                          -> Ask P5.out-of-repo
echo x >/dev/null/child                  -> Ask P1.redirect
dd if=/repo/x of=/dev/null               -> Deny P1.dd
sh -c 'echo x >/dev/stdout' >/etc/passwd -> Ask P1.redirect
```

- [x] **Step 3: Implement NF-4 at the redirect seam**

Normalization must retain the redirects. Exempt only exact cleaned paths `/dev/null`, `/dev/stdout`, `/dev/stderr`, and `/dev/tty` inside redirect authorization. Do not add `/dev/*` as a safe root and do not affect mutator destinations, file tools, or opaque writes.

- [x] **Step 4: Verify and commit NF-4 first**

```bash
/usr/local/go/bin/gofmt -w internal/engine/rules_bash.go
/usr/local/go/bin/go test ./internal/engine ./test/adversarial -count=1
git add internal/engine/rules_bash.go internal/engine/rules_bash_test.go test/adversarial/corpus.json
git commit -m "fix: exempt standard output devices from redirect asks (NF-4)"
```

#### NF-8 and NF-6: System Temp Descendants

- [x] **Step 5: Add RED Base temp-root tests**

Set `TMPDIR` to a real test directory and cover that root plus `/tmp` and `/var/tmp` when present:

```text
rm -rf $TMPDIR/work/item      -> Allow
rm -rf /tmp/work/item         -> Allow
rm -rf /var/tmp/work/item     -> Allow
echo x >$TMPDIR/work/out      -> Allow
echo x >/tmp/work/out         -> Allow
echo x >/var/tmp/work/out     -> Allow
```

The roots and escapes remain protected:

```text
rm -rf $TMPDIR                -> Deny P1.rm-rf
rm -rf /tmp                   -> Deny P1.rm-rf
rm -rf /var/tmp               -> Deny P1.rm-rf
echo x >$TMPDIR               -> Ask P1.redirect
echo x >/tmp                  -> Ask P1.redirect
echo x >/var/tmp              -> Ask P1.redirect
rm -rf /tmp/..                -> Deny P1.rm-rf
echo x >/tmp/../etc/passwd    -> Ask P1.redirect
```

Add physical-containment controls where a symlink below a temp root points outside it. The `rm` form Denies and the redirect form Asks. Add a Claude scratchpad-shaped redirect under `/tmp/claude-<uid>/.../scratchpad/out.txt` as the NF-6 regression; the same path is allowed on every plane because NF-8 authorizes the temp descendant, not the plane identity.

Also cover duplicate/overlapping roots when `TMPDIR` is below `/tmp`, a symlinked `TMPDIR`, `TMPDIR=/`, `/tmpish`, and cleaned equality such as `/tmp/work/..`. Invalid roots are discarded; aliases must not turn equality or an escape into a descendant.

- [x] **Step 6: Align the Declarative floor with NF-8**

The broad native patterns `Bash(rm -rf *)`, `Bash(rm -fr *)`, `Bash(rm -r -f *)`, and `Bash(rm -f -r *)` would preempt the Engine's approved Allow. Replace them with narrow catastrophic-target forms covering the filesystem root, home shorthand, current directory, and parent directory. Add generated-config tests proving `rm -rf /` retains a native Deny while `rm -rf /tmp/work/item` is not natively denied and reaches HEAD's existing Bash pre-hook matcher; Task 4 must not depend on Task 1's future wildcard matcher.

Revise the existing `TestBashDenyGlobsP2P6` and OpenCode floor assertions that currently require `rm -rf *`; they must require the new catastrophic-target set and reject restoration of the broad pattern.

- [x] **Step 7: Implement and commit NF-8/NF-6**

Reuse `authorizedPath` physical containment, but pass runtime Base temp roots separately from Overlay `SafeRoots`. Require strict descendant containment after cleaning; equality with a temp root is unauthorized. Preserve the existing destination-mutator calls that already pass `allowTemp=true`; NF-8 changes only `checkRmRf` and redirect authorization. Do not extend temp authorization to self-config, secret, git-protected, or CI/infra checks.

```bash
/usr/local/go/bin/gofmt -w internal/engine/rules_bash.go internal/genconfig/claude.go
/usr/local/go/bin/go test ./internal/engine ./internal/genconfig ./test -count=1
git add internal/engine/rules_bash.go internal/engine/rules_bash_test.go internal/genconfig/claude.go internal/genconfig/claude_test.go internal/genconfig/opencode_test.go test/fixtures/claude/settings-floor.golden.json test/fixtures/opencode/settings-floor.golden.json
git commit -m "fix: authorize system temp descendants for rm and redirects (NF-6, NF-8)"
```

#### NF-7: Key-Scope Git Config Writes

- [x] **Step 8: Add RED Git-config classification tests**

Read forms remain Allow, including `git config user.email`, `git config --get user.name`, `git config --global --get user.name`, and `git config --list`. Scope alone never turns a read into a write.

Repository-local writes to these case-insensitive keys or families become Allow when the effective repository is `ToolCall.RepoRoot` or its resolved common directory is a strict NF-8 system-temp descendant. This covers fixture repositories selected by `cd` or `git -C` and a same-command `git init -q` immediately followed by `git config`; unrelated non-temp repositories do not inherit trust.

```text
user.*
init.defaultBranch
commit.gpgsign
advice.*
color.*
```

Repository-local writes to these keys or families remain Deny `P2.git-config-write`:

```text
core.hooksPath
core.fsmonitor
core.sshCommand
core.pager
core.editor
credential.*
include.path
includeIf.*
alias.*
```

Any write using `--global` or `--system` remains Deny, including approved low-risk keys such as `user.email`. Any write through `-f`/`--file` remains Deny because it can target arbitrary configuration. `--worktree` writes Ask unless a dangerous key makes the Verdict Deny. A repository-local write outside `ToolCall.RepoRoot` and the strict system-temp descendants Asks. A local write to any unclassified key, such as `merge.tool`, Asks as `P2.git-config-write`.

- [x] **Step 9: Add RED operation-parser controls**

Cover positional writes and `--add`, `--replace-all`, `--unset`, and `--unset-all`; attached and separated global options; `git -C <repo> config`; `--git-dir`; case variants; values beginning with `-`; `--` option termination; malformed arguments; and unknown options. Reads must not become writes, and parser uncertainty must Ask rather than fall through.

`-e`/`--edit` is a write with no visible key: local edit Asks, while global/system/file edit Denies. `--rename-section` carries source and destination sections; Deny when either is `core`, `credential`, `include`, `includeIf`, or `alias`, Allow only when both are approved families (`user`, `advice`, or `color`), and Ask otherwise. `--remove-section` classifies its one section by the same family rules. `-f` is the short form of `--file`; `--blob` remains read-only.

Include explicit Deny controls for `git config --remove-section core`, `git config --rename-section core user`, and `git config --rename-section user core`; section-wide operations must not bypass protected `core.*` keys.

- [x] **Step 10: Align the Declarative floor with NF-7**

Remove broad `Bash(git config *)` from Claude and OpenCode generation. Add coarse Deny patterns only for definite dangerous-key writes in common positional forms. Do not add scope-only `--global`, `--system`, or `--file` patterns because they would also Deny reads before the Engine can classify them. Generated-config tests must prove `git config user.email x@y.com` and `git config --global --get user.name` are not natively denied while `git config core.hooksPath /tmp/evil` retains native Deny coverage. The existing Bash pre-hook delivers every other Git-config form to the Engine.

Revise HEAD's `TestGitConfigWriteDenied` and the Git-config entry in `TestGitRulesSurvivePrefixes` to the new Verdict matrix; keep dangerous-key prefix coverage and add approved-key prefix coverage.

- [x] **Step 11: Implement and commit NF-7**

Parse once inside the Git module and classify only proven writes. Normalize key matching case-insensitively. Use exact matches where listed and prefix matches only for entries ending in `.*`. Resolve `-C`/`--git-dir` and the common directory enough to prove whether the effective repository is `ToolCall.RepoRoot` or a strict system-temp descendant; Ask on another or uncertain repository. Preserve stronger existing Git-option and P3 uncertainty Verdicts.

```bash
/usr/local/go/bin/gofmt -w internal/engine/rules_git.go internal/genconfig/claude.go
/usr/local/go/bin/go test ./internal/engine ./internal/genconfig ./test -count=1
git add internal/engine/rules_git.go internal/engine/rules_git_test.go internal/genconfig/claude.go internal/genconfig/claude_test.go internal/genconfig/opencode_test.go test/fixtures/claude/settings-floor.golden.json test/fixtures/opencode/settings-floor.golden.json test/adversarial/corpus.json
git commit -m "fix: classify git config writes by scope and key (NF-7)"
```

#### NF-5: Position-Aware Unresolved Words

- [x] **Step 12: Add RED provenance and shell-state tests**

Cover prior unconditional scalar literal assignments, quoted expansion, command-prefix assignment semantics, branch-dependent invalidation, arrays, modifiers, command substitution, arithmetic, inherited variables, and unquoted expansion. A command-prefix assignment does not resolve that command's own argument expansion.

- [x] **Step 13: Add RED P3 behavior tests**

```text
echo "exit: $?"                         -> Allow
for f in a b; do echo "=== $f"; done    -> Allow
"$CMD" harmless                        -> Ask P3.unresolved
future-tool "$TARGET"                 -> Ask P3.unresolved
cat "$INPUT"                           -> Ask P3.unresolved
grep --future-option "$TARGET"         -> Ask P3.unresolved
echo x > "$OUT"                        -> Ask P3.unresolved
curl "$URL"                            -> Ask P3.unresolved
sh -c "$CODE"                          -> Ask P3.unresolved
python3 -c "$CODE"                     -> Ask P3.unresolved
```

Set `pol.Waived["P3.unresolved"] = true` directly in an Engine test and assert an unresolved policy-bearing word still Asks as `P3.unresolved`.
Replace HEAD's `TestUnresolvedRedirectStillRunsRedirectChecks`, which assumes an Engine-internal P3 waiver can take effect, with this unwaivable regression.

- [x] **Step 14: Add RED locally-resolved path tests**

```text
SDK="/abs/lit"; grep -rn Foo "$SDK/api/" -> Allow
OUT="/etc/passwd"; echo x > "$OUT"       -> Ask P1.redirect
SCRATCH=/tmp/x; rm -rf "$SCRATCH/y"       -> Allow under NF-8
DANGER=/etc; rm -rf "$DANGER/y"           -> Deny P1.rm-rf
rm -rf /etc/y                               -> Deny P1.rm-rf
```

NF-8 supersedes the earlier proposed Ask for the resolved `/tmp/x/y` case: P3 must hand the concrete path to P1, and P1 now authorizes that temp descendant. Locally resolved secret and self-config paths continue to their normal P4/P5 Verdicts.

- [x] **Step 15: Implement one position-aware P3 classifier**

Join per-word expansion provenance to `parseOperandRoles`. P3 still owns unresolved executable names, redirects, path operands, unknown-command operands, option ambiguity that can change operand interpretation, network destinations, nested-shell source, and opaque-executor source. Only arguments whose inert non-policy role is positively known avoid P3. Resolve quoted references and simple embedded parameter prefixes from prior unconditionally executed scalar literal assignments; unquoted values remain unresolved when IFS splitting, globbing, parameter operators, or uncertain mutation can alter the runtime word.

- [x] **Step 16: Verify and commit NF-5**

```bash
/usr/local/go/bin/gofmt -w internal/engine/tokenize.go internal/engine/operands.go internal/engine/rules_bash.go
/usr/local/go/bin/go test ./internal/engine ./test/adversarial -count=1
git add internal/engine/tokenize.go internal/engine/tokenize_test.go internal/engine/operands.go internal/engine/rules_bash.go internal/engine/rules_bash_test.go test/adversarial/corpus.json
git commit -m "fix: restrict P3 to unresolved policy positions (NF-5)"
```

#### NF-5b: Literal Parameter Prefixes

- [x] **Step 17: Add RED embedded-parameter tests**

Lock `S=<tmp>; bash $S/run.sh` as Allow and `S=/etc; rm -rf $S/x` as Deny `P1.rm-rf`. Cover `$SP/tlp/x`, braced parameters, unknown and operated parameters, glob/IFS-sensitive values, custom IFS, and unknown IFS mutation. Preserve quoted expansion behavior.

- [x] **Step 18: Implement NF-5b substitution**

Extend `resolveLocalWord` to substitute plain known parameter parts inside a larger word. Resolve unquoted values only when tracked IFS and glob semantics prove the expansion remains one concrete field; otherwise preserve unresolved provenance for P3.

#### NF-9: Scoped Find Deletion

- [x] **Step 19: Add RED find-scope tests**

Lock absolute and `cd`-relative scratch roots plus `-exec rm -rf {} +` as Allow. Keep `/etc`, repository `internal/`, default/unknown roots, root equality, symlink escapes, mixed safe/unsafe roots, `-ok`, non-`rm` callbacks, and `rm` actions containing operands other than `{}` at Ask `P1.find-delete`.

- [x] **Step 20: Implement NF-9 root authorization**

Parse leading `find` options and every starting root conservatively. Repository overlap in either direction takes precedence over temp authorization. Exempt only `-delete` and direct `-exec`/`-execdir rm` actions whose deletion operands are exact match placeholders, and only when every root is a strict NF-8 system-temp descendant. Overlay safe roots remain repository-internal after policy merge and therefore stay at Ask for this bulk-deletion primitive.

- [x] **Step 21: Verify Task 4 and stop for review**

```bash
/usr/local/go/bin/go test ./... -race -count=1
make check
git diff --check
git status --short
git log --oneline --decorate -5
```

The final independent review returned `READY`; the complete race suite and `make check` passed. NF-4 through NF-9 were published as `v0.14.0-dev` and deployed before remaining Phase 5 work resumed.

---

### Task 4b: NF-10 - Retire Native Rules That Pre-empt NF-8/NF-9

**Files:**
- Modify: `internal/genconfig/claude.go`
- Modify: `internal/genconfig/merge.go`
- Modify: `cmd/guardrail/genconfig.go`
- Modify: `cmd/guardrail/sync.go`
- Test: `internal/genconfig/claude_test.go`
- Test: `internal/genconfig/opencode_test.go`
- Test: `internal/genconfig/merge_test.go`
- Test: `cmd/guardrail/genconfig_test.go`
- Test: `test/fixtures/claude/settings-floor.golden.json`
- Test: `test/fixtures/opencode/settings-floor.golden.json`
- Document: `docs/superpowers/plans/2026-09-06-remediation-phase5.md`

**Interfaces:**
- Fresh Claude and OpenCode floors retain exact catastrophic `rm` targets `/`, `~`, `.`, and `..` for each supported recursive/force flag ordering, plus `srm *`.
- Fresh floors contain none of `rm -rf *`, `rm -fr *`, `rm -r -f *`, `rm -f -r *`, or `find * -delete`.
- `MergePlaneInto(path, plane, frag)` treats exactly those five patterns as retired guardrail floor rules for explicit Claude/OpenCode generation. It removes the wrapped forms from Claude `permissions.deny`/`permissions.ask` and the unwrapped keys from OpenCode `permission.bash` before merging the current fragment. Generic `MergeInto` retains its non-destructive union semantics; no other user permission is removed.
- The literal shell command `rm -rf /*` remains an Engine Deny, not a native-floor rule. Both planes define `*` as an unescapable Bash-permission wildcard, so a native `rm -rf /*` rule would also pre-empt NF-8 for absolute temp descendants.

- [ ] **Step 0: Create the dedicated Task 4b worktree from local main**

```bash
git worktree add ../agent-guardrails-phase5-task4b -b phase5-task4b main
```

- [ ] **Step 1: Add RED fresh-floor and migration regressions**

Assert both generated floors retain `/`, `~`, `.`, `..`, and `srm *`, omit all five retired patterns, and allow a representative strict temp descendant to reach the hook. Also prove no native `/*` rule reintroduces absolute-path pre-emption. Start merge fixtures with the old Claude and OpenCode rules present; after `MergePlaneInto`, assert every retired rule is absent while unrelated user rules survive.

- [ ] **Step 2: Run the focused tests and confirm the root-cause failures**

```bash
/usr/local/go/bin/go test ./internal/genconfig -run 'Retired|TempDelete|BashPermissions' -count=1
```

Expected: fresh-generation coverage fails on `find * -delete`; merge fixtures fail because obsolete `rm` and `find` rules survive accumulation.

- [ ] **Step 3: Implement exact retirement and regenerate goldens**

Delete `Bash(find * -delete)` from `bashAskGlobs`. Add an explicit plane-aware merge entry point used by `gen-config` and `sync`; before its permission merge, remove only the five exact retired patterns from Claude's permission arrays and OpenCode's Bash permission object. Keep generic merges unchanged, centralize the retirement list, and do not broaden it to pattern-based deletion.

```bash
/usr/local/go/bin/go test ./test -run Golden -update
git diff -- test/fixtures/claude/settings-floor.golden.json test/fixtures/opencode/settings-floor.golden.json
```

- [ ] **Step 4: Verify Engine delivery through a real Claude session**

Run live probe #5 through Claude with the candidate floor installed. Confirm a strict system-temp descendant `rm -rf` and scoped `find ... -delete` reach the hook and receive the Engine's NF-8/NF-9 Allow, while every catastrophic literal remains natively denied. Record the exact payloads, native config, audit evidence, and Verdicts; Engine-only probes are insufficient.

- [ ] **Step 5: Verify, gate, and commit locally**

```bash
/usr/local/go/bin/gofmt -w internal/genconfig/claude.go internal/genconfig/merge.go cmd/guardrail/genconfig.go cmd/guardrail/sync.go
/usr/local/go/bin/go test ./internal/genconfig ./cmd/guardrail ./test -count=1
/usr/local/go/bin/go test ./... -race -count=1
make check
git diff --check
git add internal/genconfig cmd/guardrail/genconfig.go cmd/guardrail/genconfig_test.go cmd/guardrail/sync.go test/fixtures/claude/settings-floor.golden.json test/fixtures/opencode/settings-floor.golden.json docs/superpowers/plans/2026-09-06-remediation-phase5.md
git commit -m "fix: retire native rules that pre-empt temp authorization (NF-10)"
```

Do not push. Stop for the independent gate and Carlitos's review before merge.

---

### Task 5: NF-3 - Reconcile Plane-Disabled Owned Hooks

**Files:**
- Modify: `internal/genconfig/merge.go`
- Modify: `cmd/guardrail/genconfig.go`
- Modify: `cmd/guardrail/doctor.go`
- Modify: `cmd/guardrail/hook.go`
- Test: `internal/genconfig/merge_test.go`
- Test: `cmd/guardrail/genconfig_test.go`
- Test: `cmd/guardrail/doctor_test.go`
- Test: `cmd/guardrail/hook_test.go`
- Test: `cmd/guardrail/sync_test.go`
- Document: deployment follow-up in `README.md`

**Interfaces:**
- An owned Claude group is any hook group whose `id` starts with `guardrail-`.
- `MergeInto(path string, frag Fragment) error` remains the ordinary merge. It preserves `hooks_disabled` byte-semantically and suppresses generated active groups whose owned IDs are disabled, so it never re-arms a hook that a person disabled.
- `MergeInstalledInto(path string, frag Fragment) (int, error)` is the explicit installer-owned merge. It removes only generated `guardrail-` groups from Claude's top-level `hooks_disabled` store while replacing owned groups in active `hooks`, preserves unrelated disabled groups, reports the number re-armed, and produces byte-identical output on a second merge.
- `guardrail gen-config claude --merge ...` is the sole caller of `MergeInstalledInto`; this is the operator action used by the installer and `update_ai_tools`. `guardrail sync` continues to call `MergeInto` and therefore preserves intentional disables.
- `doctor` requires the expected owned IDs in their expected `PreToolUse`, `PostToolUse`, and `SessionStart` locations. It distinguishes complete active, partially active, misplaced, disabled, duplicated active-and-disabled, and absent states.
- Disabled or duplicated owned hooks produce a `doctor` warning and, when the `SessionStart` hook remains active, a Claude posture warning. A fully disabled plane cannot emit its own posture warning.

- [ ] **Step 0: Create the dedicated Task 5 worktree from reviewed local main**

```bash
git worktree add ../agent-guardrails-phase5-task5 -b phase5-task5-nf3 main
```

- [ ] **Step 1: Add RED preservation tests using the observed disabled shape**

Start with active `hooks` empty and `hooks_disabled.PreToolUse`, `PostToolUse`, and `SessionStart` containing owned groups plus unrelated groups. Call ordinary `MergeInto` with `ClaudeConfig`. Assert every disabled owned ID remains disabled and absent from active hooks, generated groups not present in the disabled store are merged normally, unrelated groups remain, and a second merge is identical. Add a `cmdSync` regression proving project sync does not re-arm a disabled owned group.

- [ ] **Step 2: Add RED installer-owned reconciliation tests**

Call `MergeInstalledInto` with the same fixture. Assert generated owned groups exist only under active `hooks`, only matching owned groups are removed from `hooks_disabled`, unrelated disabled groups remain, the returned count identifies the re-armed groups, and a second merge returns zero with byte-identical output. Through `cmdGenConfig`, assert a nonzero count emits an explicit operator-facing re-arm message rather than silently changing state.

- [ ] **Step 3: Add RED doctor and posture tests**

Cover the complete active set, each required ID missing in turn, an ID under the wrong event, owned groups only disabled, both active and disabled, absent, malformed JSON, and unmarked guardrail-like commands. Disabled and duplicated states must print an explicit `WARNING` containing `hooks_disabled`; partial and misplaced states must identify the missing expected event; none may report the installation as healthy. Feed the same diagnostic into Claude's SessionStart posture and assert the warning appears when that hook remains active.

- [ ] **Step 4: Implement explicit diagnosis and installer-owned reconciliation**

Extend the existing marker-based merge instead of matching command strings for deletion. Keep disabled-store cleanup out of ordinary `MergeInto`; restrict `MergeInstalledInto` cleanup to generated owned IDs in Claude's `hooks_disabled`. Share one Claude-settings diagnostic between `doctor` and SessionStart posture without reinterpreting unrelated keys or removing unowned entries.

- [ ] **Step 5: Document the unavoidable external repair trigger**

Record that a fully disabled plane cannot invoke its own repair. The external updater must display a message that it detected or may reconcile disabled owned hooks before it runs the operator-owned merge:

```bash
guardrail gen-config claude --merge "$HOME/.claude/settings.json" --binary "$HOME/.local/bin/guardrail" --print=false
guardrail doctor
```

Provide Carlitos the exact `run_onchange_install_packages.{sh,ps1}.tmpl` and `scripts/update_ai_tools.{sh,ps1}` changes needed to print that message immediately before the merge. Do not modify the external chezmoi repository from this worktree. `guardrail sync` must not inherit re-arming behavior.

- [ ] **Step 6: Verify and commit locally**

```bash
/usr/local/go/bin/gofmt -w internal/genconfig/merge.go cmd/guardrail/genconfig.go cmd/guardrail/doctor.go cmd/guardrail/hook.go
/usr/local/go/bin/go test ./internal/genconfig ./cmd/guardrail -run 'Disabled|Doctor|Merge' -count=1
/usr/local/go/bin/go test ./... -count=1
git diff --check
git add internal/genconfig cmd/guardrail README.md
git commit -m "fix: reconcile disabled owned Claude hooks (NF-3)"
```

Do not mark NF-3 fully fixed in the review ledger until the external updater message and installer-owned merge are separately applied and verified. Diagnosis alone is not re-arming, and no background or ordinary sync path may override a person's intentional disable.

---

### Task 6: Opaque Executors - Ask on Visible Self-Config Write Uncertainty

**Files:**
- Modify: `internal/engine/tokenize.go`
- Modify: `internal/engine/rules_path.go`
- Test: `internal/engine/tokenize_test.go`
- Test: `internal/engine/rules_path_test.go`
- Test: `cmd/guardrail/hook_test.go`
- Test: `test/adversarial/corpus.json`

**Interfaces:**
- Normalization exposes literal opaque-executor source from `-c`-style arguments and heredoc bodies without labeling every source path as a definite write.
- A visible literal path matching self-config scope in opaque source produces Ask `P5.self-config-uncertain` when write intent cannot be proven.
- Existing definite `P5.self-config` writes remain Deny. Existing special handling for the Operator config remains Deny. Stronger secret-path Denies outrank the new Ask.

- [ ] **Step 0: Create the dedicated Task 6 worktree from reviewed local main**

```bash
git worktree add ../agent-guardrails-phase5-task6 -b phase5-task6-opaque-writes main
```

- [ ] **Step 1: Add RED literal-source tests**

```text
python3 -c 'open("/home/u/.claude/settings.json", "w").write("x")'
    -> Ask P5.self-config-uncertain
node -e 'require("fs").writeFileSync("/repo/CLAUDE.md", "x")'
    -> Ask P5.self-config-uncertain
python3 -c 'print(open("/repo/CLAUDE.md").read())'
    -> Ask P5.self-config-uncertain
python3 -c 'print("/repo/CLAUDE.md")'
    -> Ask P5.self-config-uncertain
```

The last two cases intentionally Ask because the Engine can see the protected path but cannot prove opaque read/write intent without implementing each interpreter.

- [ ] **Step 2: Add RED heredoc tests**

Use quoted and unquoted heredoc delimiters whose bodies contain a literal `os.replace(tmp, "/home/u/.claude/settings.json")`. Both must reach the same P5 uncertainty Ask; the quoted heredoc must not depend on incidental `P3.unresolved` behavior.

- [ ] **Step 3: Add boundary and precedence controls**

```text
python3 -c 'print("/repo/docs/example.txt")'        -> Allow
python3 -c 'open(base + name, "w")'                -> existing static boundary
python3 -c 'open("/home/u/.ssh/id_rsa").read()'    -> Deny P4.secret-path
Write /home/u/.claude/settings.json                 -> Deny P5.self-config
python3 -c 'open("/home/u/.config/guardrail/waivers.toml")' -> Deny P5.self-config
```

- [ ] **Step 4: Implement the uncertainty path once**

Reuse `visiblePathCandidates` and scoped matching. Keep uncertain opaque candidates separate from `writeCandidates`; adding every source path there would incorrectly turn reads and mentions into definite write Denies. Preserve Task 4's rule that dynamically unresolved opaque source remains P3.

- [ ] **Step 5: Verify and commit locally**

```bash
/usr/local/go/bin/gofmt -w internal/engine/tokenize.go internal/engine/rules_path.go
/usr/local/go/bin/go test ./internal/engine ./cmd/guardrail ./test/adversarial -run 'Opaque|Heredoc|SelfConfig|Adversarial' -count=1
/usr/local/go/bin/go test ./... -count=1
git diff --check
git add internal/engine cmd/guardrail test/adversarial/corpus.json
git commit -m "fix: ask on opaque self-config write uncertainty"
```

---

### Task 7: NF-11, Corpus, Documentation, and Release Readiness

**Files:**
- Modify: `internal/audit/audit.go`
- Modify: `internal/audit/audit_test.go`
- Modify: `cmd/guardrail/hook.go`
- Modify: `cmd/guardrail/hook_test.go`
- Modify: `test/adversarial/corpus.json`
- Modify: `docs/reviews/2026-09-04-adversarial-review.md`
- Modify: `docs/reviews/2026-09-05-remediation-response.md`
- Modify: `README.md` if user-facing behavior changed

**Interfaces:**
- Corpus totals and Verdict counts are computed from the final file; never hard-code predicted totals.
- NF-6/NF-8 remain in specialized Engine tests because system temp roots vary by host; do not hard-code a platform-specific root into the generic corpus.
- NF-3 remains open or partial until the external global updater is verified.
- `audit.Record` gains additive `CWD` and `RepoRoot` fields serialized as optional `cwd` and `repo_root` JSON keys. `cmdHook` copies both from the normalized `ToolCall` for every written audit record.
- Subagents share the parent's `session_id`; audit consumers correlate parent and subagent calls by that ID and use `cwd`/`repo_root` as execution context, not as a new session boundary.

- [ ] **Step 0: Create the dedicated Task 7 worktree from reviewed local main**

```bash
git worktree add ../agent-guardrails-phase5-task7 -b phase5-task7-closeout main
```

- [ ] **Step 1: Add and verify NF-11 audit context**

Add serialization tests proving nonempty `cwd` and `repo_root` appear under those exact JSON keys and older records without them still decode. Add a `cmdHook` test that parses the emitted audit record and matches both fields to the normalized tool call. Document the shared parent/subagent `session_id` behavior and the role of the two location fields.

- [ ] **Step 2: Audit coverage by finding**

Confirm at least one regression test and one non-regression control for H-6, H-10, M-7, NF-3, NF-4, NF-5, NF-5b, NF-6, NF-7, NF-8, NF-9, NF-10, NF-11, and opaque self-config uncertainty. Add missing corpus entries only where the generic corpus can express the payload.

- [ ] **Step 3: Run the complete verification suite**

```bash
make check
/usr/local/go/bin/go test ./... -race -count=1
git diff --check
```

Expected: all checks pass and all pre-Phase-5 corpus entries retain their exact Verdict and rule ID.

- [ ] **Step 4: Update the review records factually**

Mark a finding fixed only when its behavior and plane delivery are both verified. Record the opaque dynamic-path boundary explicitly. Record NF-3 as partial until its external repair trigger is deployed. Do not describe the 2026-09-04 review as closed while any ledger entry remains partial or outstanding.

- [ ] **Step 5: Commit the local closeout**

```bash
git add internal/audit cmd/guardrail test/adversarial/corpus.json docs/reviews README.md
git commit -m "docs: record Phase 5 remediation evidence"
git status --short
git log --oneline --decorate -10
```

Stop for review. After the independent gate and Carlitos's merge, Phase 5 ships as `v0.15.0-dev`. Pushes, version changes, release tags, binary publication, and external installer pin updates are separate operator-approved work.

---

## Self-Review

**Spec coverage:** H-10 is Task 1; H-6 is Task 2; M-7 is Task 3; NF-4 through NF-9, including NF-5b, are the completed Task 4; NF-10 is Task 4b; NF-3 is Task 5; opaque-executor self-config uncertainty is Task 6; NF-11, corpus, and evidence are Task 7.

**Corrected stale premises:** The plan no longer assumes Claude-only native networking, a `Query` field, a new unconditional WebSearch Ask, first-path extraction, four rather than five write gates, an incomplete read-only alias list, `O_CREATE|O_EXCL` timeout locking, a stable Claude-specific scratch encoding, blanket Git-config denial, or automatic push/tag closeout.

**Known boundaries:** Dynamic opaque path construction remains outside static inspection. A disabled plane cannot invoke its own repair, so NF-3 needs an external updater trigger. Pathless unknown custom/MCP tools remain allowed. Ratified NF-8 authorizes strict temp descendants for destructive `rm` and output redirects while preserving existing destination-mutator behavior; NF-9 reuses that boundary only for fully scoped `find` deletion, and root equality remains unauthorized.

**Execution order:** Task 4 is complete and shipped. Execute Task 4b, then Tasks 1, 2, 3, 5, 6, and 7 in that order, each from reviewed local `main` on its own branch in a dedicated worktree. Every task stops after its local commit, independent gate, and probes; Carlitos merges. Task 7 closes only what the evidence supports and prepares, but does not publish, `v0.15.0-dev`.
