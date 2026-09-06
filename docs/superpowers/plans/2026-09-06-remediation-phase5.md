# Adversarial Remediation — Phase 5: Plane Coverage and Session Integrity

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the three findings that are not path-matching bugs. Each of them fails at a layer *outside* the engine — the plane's hook matcher never invokes us, the tool payload has a shape we never parse, or the session file races with itself. Phase 4 makes the engine correct; Phase 5 makes sure the engine is actually consulted.

**Architecture:** Three independent corrections. (1) The generated hook matchers list the tools they accept, so an unknown tool never reaches the engine at all — widen them and fix the guard that rejects unknown tool names before candidates are built. (2) `WebSearch` carries `query`, not `url`, so URL-based gating is inert against it — the network signal has to come from the tool identity. (3) Session state is a lock-free read-modify-write across concurrent hook processes, and an empty session ID silently disables the trifecta entirely.

**Tech Stack:** Go 1.23+, existing deps only.

**Spec:** `../reviews/2026-09-04-adversarial-review.md`. Findings addressed: **H-6, H-10, M-7**. Prerequisite: **Phase 4 must be landed first** — Task 1 here relies on `pathCandidate.repoRoot` and `matchesScoped` from Phase 4 Task 1.

## Global Constraints

- **A fix inside the engine is worthless if the plane never calls the engine.** Every task here must be verified end-to-end against the *generated config*, not just the Go unit tests. The golden-file tests are the check that matters.
- **Zero corpus entries may be relaxed.** If an existing test starts failing, decide whether the new behaviour is correct per the review before touching the expectation.
- **If a premise here is wrong, stop and say so** rather than working around it. Phase 4 Revision 1 shipped five wrong premises and was caught at exactly this stage; that was the correct outcome.
- Every code step is literal. `gofmt -w` before every commit. Conventional Commits, one commit per task.

**Verified current state:**

- `genconfig/claude.go:157` — `PreToolUse` matcher is `"Bash|Read|Edit|Write|MultiEdit"`. `NotebookEdit`, `WebFetch`, `WebSearch` and every future tool never invoke the hook.
- `genconfig/antigravity.go:15` — matcher is `"run_command|view_file|write_to_file|replace_file_content|multi_replace_file_content"`. Same closed-list problem.
- `rules_path.go:637` — `checkCIInfraLockfile` opens `if !isFileTool(tc.Tool) && !tc.IsBash() { return nil }`, rejecting an unknown tool name before any candidate is built. `checkSelfConfig` and `checkGitProtectedPaths` open with the narrower `if isFileTool(tc.Tool) && !isWriteToolCall(tc.Tool) { return nil }`, which does not have this defect.
- `trifecta_signals.go:23` — `IsNetworkAttempt` returns `false` immediately unless `tc.IsBash()`, so no native tool can ever arm the network leg.
- `session/session.go` — `Load` reads and unmarshals, `Save` marshals and writes, with no lock between them. `safeSessionID` rejects `""`.
- `cmd/guardrail/hook.go:101` — the whole trifecta block is guarded by `tc.Event == "pre" && tc.SessionID != ""`. An empty session ID skips it **silently**: the `unsafe session id` warning is inside the `else` branch and is never reached.

---

### Task 1: H-10 — unknown tools must reach the engine, and survive it

**Files:** `internal/genconfig/claude.go`, `internal/genconfig/antigravity.go`, `internal/adapter/claude.go`, `internal/adapter/opencode.go`, `internal/adapter/antigravity.go`, `internal/engine/rules_path.go`, `internal/engine/evaluate.go`, tests + goldens

**The defect has four layers**, and fixing any one alone leaves the bypass open:
1. The generated matchers exclude unknown tools, so the hook is never invoked.
2. `ParseClaude` (and the opencode/antigravity parsers) only extract `file_path`, so an unknown tool's path is never populated even when the hook does fire.
3. `privatePathCandidates` and `writeCandidates` gate on `isFileTool`, discarding paths from unknown tools.
4. `checkCIInfraLockfile` returns `nil` for an unknown tool name before reaching its candidates.

**Interfaces:**
- Claude `PreToolUse` matcher becomes `"*"`; `PostToolUse` keeps its narrower write-tool list. Antigravity `PreToolUse` matcher becomes `"*"`.
- All three adapters extract a path from the first present of `file_path`, `path`, `notebook_path`, `filePath`, `absolute_path`, plus `edits[].file_path` / `changes[].file_path`.
- New `func isKnownReadOnlyTool(name string) bool` covering `read`, `glob`, `grep`, `websearch`, `webfetch`, `todowrite`, `task`, `view_file` (case-insensitive).
- `privatePathCandidates` drops its `isFileTool` guard entirely. `writeCandidates` swaps `isFileTool(tc.Tool)` for `!isKnownReadOnlyTool(tc.Tool)`.
- `checkCIInfraLockfile`'s opening guard becomes the same shape as `checkSelfConfig`'s: `if isFileTool(tc.Tool) && !isWriteToolCall(tc.Tool) { return nil }`.

- [ ] **Step 1: Write the failing test**

```go
func TestUnknownToolPathsAreChecked(t *testing.T) {
	pol := pathPol()
	for _, tool := range []string{"NotebookEdit", "SomeFutureTool", "patch", "str_replace_editor"} {
		tc := ToolCall{Tool: tool, Paths: []string{"/home/u/.ssh/id_rsa"}, CWD: "/repo", RepoRoot: "/repo"}
		if v := checkPaths(tc, pol); v == nil || v.Decision != policy.Deny {
			t.Errorf("tool %q reading a secret -> %+v, want deny", tool, v)
		}
		tc.Paths = []string{"/repo/.github/workflows/ci.yml"}
		if v := checkCIInfraLockfile(tc); v == nil {
			t.Errorf("tool %q writing CI config -> nil, want a verdict", tool)
		}
	}
}

func TestParseClaudeExtractsAlternatePathKeys(t *testing.T) {
	for _, raw := range []string{
		`{"cwd":"/tmp","tool_name":"NotebookEdit","tool_input":{"notebook_path":"/home/u/.ssh/id_rsa"}}`,
		`{"cwd":"/tmp","tool_name":"Future","tool_input":{"path":"/home/u/.ssh/id_rsa"}}`,
	} {
		tc, err := ParseClaude(strings.NewReader(raw))
		if err != nil {
			t.Fatal(err)
		}
		if !slices.Contains(tc.Paths, "/home/u/.ssh/id_rsa") {
			t.Errorf("%s -> Paths=%v, want the secret path", raw, tc.Paths)
		}
	}
}

func TestGeneratedMatchersAcceptUnknownTools(t *testing.T) {
	pre := ClaudeConfig("guardrail")["hooks"].(map[string]any)["PreToolUse"].([]any)[0].(map[string]any)
	if pre["matcher"] != "*" {
		t.Errorf("Claude PreToolUse matcher = %v, want \"*\" so unknown tools reach the hook", pre["matcher"])
	}
}
```

(Adjust the last test's traversal to the real `ClaudeConfig` return shape.)

- [ ] **Step 2: Run to verify it fails.**

- [ ] **Step 3: Implement** all four layers. In the engine:

```go
func isKnownReadOnlyTool(name string) bool {
	switch strings.ToLower(name) {
	case "read", "glob", "grep", "websearch", "webfetch", "todowrite", "task", "view_file":
		return true
	}
	return false
}
```

```go
	// Any path the payload carries is a path, whatever the tool is called. A
	// closed tool-name list failed open on NotebookEdit, opencode's patch, and
	// every future tool (review H-10).
	for _, p := range tc.Paths {
		candidates = append(candidates, pathCandidate{path: p, cwd: tc.CWD, repoRoot: tc.RepoRoot})
	}
```

```go
	// An unrecognized tool carrying a path may well be writing to it; only the
	// tools known to be read-only are exempt from the write rules (H-10).
	if !isKnownReadOnlyTool(tc.Tool) {
		for _, p := range tc.Paths {
			out = append(out, pathCandidate{path: p, cwd: tc.CWD, repoRoot: tc.RepoRoot})
		}
	}
```

- [ ] **Step 4: Regenerate the goldens and read the diff**

```bash
/usr/local/go/bin/go test ./test/ -run Golden -update && /usr/local/go/bin/go test ./... -count=1
```
The diff must be the two matcher strings and nothing else.

- [ ] **Step 5: Live check.** Widening Claude's matcher to `*` means the hook now runs on *every* tool call, including `TodoWrite` and `Task`. Confirm the latency is acceptable and that no ordinary tool call starts asking. If it does, that is a real regression — fix it rather than narrowing the matcher back.

- [ ] **Step 6: Commit**

```bash
gofmt -w internal/ && git add internal/
git commit -m "fix: route unknown tools through the engine and check their paths (H-10)"
```

---

### Task 2: H-6 — gate the web tools, including the one with no URL

**Files:** `internal/engine/rules_net.go`, `internal/engine/trifecta_signals.go`, `internal/adapter/claude.go`, tests

**The defect.** No native tool can arm the trifecta's network leg — `IsNetworkAttempt` returns `false` unless `tc.IsBash()`. And `WebSearch` carries `query`, `allowed_domains`, `blocked_domains` — **not** `url`. Gating on `tool_input.url` is therefore inert against it: the URL is empty, the egress allowlist has nothing to match, and the net leg stays unarmed. The network signal has to come from the *tool identity*, not from a URL that may not exist.

**Interfaces:**
- `ToolCall` gains `URL string` and `Query string`; `ParseClaude` fills them from `tool_input.url` and `tool_input.query`.
- New `func isNetworkTool(name string) bool` — `webfetch`, `websearch`, `web_search`, `read_url_content` (case-insensitive).
- `IsNetworkAttempt` returns `true` when `isNetworkTool(tc.Tool)`, before the `IsBash` check. This arms P7 for both web tools regardless of payload shape.
- New `func checkEgressTool(tc ToolCall, pol *policy.Policy) *policy.Verdict`, called from `Evaluate` alongside `checkPaths`/`checkBash`: when `tc.URL != ""`, extract the host and apply `pol.Slots.EgressAllowlist` exactly as the bash path does. When the tool is a network tool with **no** URL (i.e. `WebSearch`), return an `ask` verdict with rule ID `P6.web-search` and the query in the reason — a search cannot be host-checked, so it is surfaced rather than silently allowed.

- [ ] **Step 1: Write the failing test**

```go
func TestWebFetchIsGatedByEgressAllowlist(t *testing.T) {
	pol := netPol("api.github.com")
	tc := ToolCall{Tool: "WebFetch", URL: "https://evil.example.com/steal", CWD: "/repo", RepoRoot: "/repo"}
	if v := checkEgressTool(tc, pol); v == nil || v.Decision != policy.Deny {
		t.Fatalf("off-allowlist WebFetch -> %+v, want deny", v)
	}
	tc.URL = "https://api.github.com/repos/x"
	if v := checkEgressTool(tc, pol); v != nil {
		t.Fatalf("allowlisted WebFetch -> %+v, want nil", v)
	}
}

func TestWebSearchIsGatedDespiteHavingNoURL(t *testing.T) {
	pol := netPol("api.github.com")
	// The real payload shape: a query, no url.
	tc := ToolCall{Tool: "WebSearch", Query: "exfiltrate this", CWD: "/repo", RepoRoot: "/repo"}
	v := checkEgressTool(tc, pol)
	if v == nil || v.Decision == policy.Allow {
		t.Fatalf("WebSearch -> %+v, want ask (no host to check)", v)
	}
	if !IsNetworkAttempt(tc) {
		t.Fatal("WebSearch must arm the trifecta network leg")
	}
	if !IsNetworkAttempt(ToolCall{Tool: "WebFetch", URL: "https://x.example.com/y"}) {
		t.Fatal("WebFetch must arm the trifecta network leg")
	}
}

func TestParseClaudeExtractsURLAndQuery(t *testing.T) {
	tc, err := ParseClaude(strings.NewReader(
		`{"cwd":"/tmp","tool_name":"WebSearch","tool_input":{"query":"hello"}}`))
	if err != nil {
		t.Fatal(err)
	}
	if tc.Query != "hello" {
		t.Errorf("Query = %q, want \"hello\"", tc.Query)
	}
}
```

- [ ] **Step 2: Run to verify it fails.**

- [ ] **Step 3: Implement.** Note the matcher widening in Task 1 is what makes the hook fire for these tools at all — if Task 1 has not landed, these tests pass while production stays open.

- [ ] **Step 4: Run + commit**

```bash
gofmt -w internal/ && git add internal/
git commit -m "fix(engine): gate WebFetch by allowlist, WebSearch by ask, arm the net leg for both (H-6)"
```

---

### Task 3: M-7 — session state must be atomic, present, and undeletable

**Files:** `internal/session/session.go`, `cmd/guardrail/hook.go`, `internal/engine/rules_path.go`, tests

**The defect has three parts**, and Phase 4 Revision 1 addressed only the first:
1. The session file is deletable — a flagless `rm <session>.json` clears both trifecta legs.
2. `Load` → mutate → `Save` has no lock. Claude Code issues tool calls in parallel; two hook processes interleaving lose whichever leg was set first, which is exactly the signal P7 exists to accumulate.
3. `tc.SessionID == ""` skips the entire trifecta block **silently** — the `unsafe session id` warning sits in the `else` branch and is unreachable for the empty case.

**Interfaces:**
- `selfConfigAnywhere` gains `**/.local/state/guardrail/**`, `**/guardrail/sessions/**`, `**/AppData/Local/guardrail/**`.
- New `func Update(sessionID string, fn func(*State)) error` in `internal/session`: acquires an exclusive lock, loads, applies `fn`, saves, releases. Implemented with an `O_CREATE|O_EXCL` lock file (`<session>.json.lock`) and a bounded retry — portable across Linux, macOS and Windows, which `syscall.Flock` is not. On lock-acquisition timeout, proceed unlocked and return a non-nil error so the caller can warn: losing a leg is better than blocking the agent.
- `hook.go` replaces the `Load` / mutate / `Save` sequence with a single `session.Update` call.
- `hook.go`'s guard changes from `tc.SessionID != ""` to always entering the block, with the empty and unsafe cases both producing the `unsafe session id` warning. A missing session ID must be *loud*, not silent.

- [ ] **Step 1: Write the failing test**

```go
func TestSessionUpdateIsAtomicUnderConcurrency(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	const id = "concurrent-session"
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_ = Update(id, func(s *State) {
				if i == 0 {
					s.SawPrivateRead = true
				} else {
					s.SawNetworkCall = true
				}
			})
		}(i)
	}
	wg.Wait()
	st, err := Load(id)
	if err != nil {
		t.Fatal(err)
	}
	if !st.SawPrivateRead || !st.SawNetworkCall {
		t.Fatalf("state = %+v, want both legs set — a concurrent update was lost", st)
	}
}

func TestEmptySessionIDIsReportedNotIgnored(t *testing.T) {
	if _, ok := safeSessionID(""); ok {
		t.Fatal("empty session id must be rejected by safeSessionID")
	}
	if p := Path(""); p != "" {
		t.Fatalf("Path(\"\") = %q, want \"\"", p)
	}
}
```

Plus an engine test that `rm /home/u/.local/state/guardrail/sessions/s1.json` denies.

- [ ] **Step 2: Run to verify it fails** — the concurrency test loses a leg; the `rm` allows.

- [ ] **Step 3: Implement.** Run the concurrency test with `-race -count=20`; a lock bug that passes once is not fixed.

- [ ] **Step 4: Verify the empty-ID path end-to-end.** Feed the hook a payload with no `session_id` and confirm the warning is actually emitted on the surface Claude shows — the review's original complaint about stderr on an exit-0 hook applies here too. If the warning is not visible, escalate the delivery mechanism rather than declaring it done.

- [ ] **Step 5: Commit**

```bash
gofmt -w internal/ cmd/ && git add internal/ cmd/
git commit -m "fix(session): lock updates, protect state files, report a missing session id (M-7)"
```

---

### Task 4: Corpus, docs, tag

- [ ] **Step 1:** Add corpus entries for the unknown-tool secret read, the unknown-tool CI write, the off-allowlist `WebFetch`, `WebSearch`, and the session-file `rm`.
- [ ] **Step 2:** `make check && /usr/local/go/bin/go test ./... -race -count=1` → green, zero corpus entries relaxed.
- [ ] **Step 3:** Annotate the review with `**[FIXED — Phase 5]**` on H-6, H-10, M-7. Update the response-report ledger. **Only now, with Phase 4 also landed, may the 2026-09-04 review be described as closed** — and only if the ledger shows every finding accounted for. If anything remains, say so.
- [ ] **Step 4:**
```bash
git add -A && git commit -m "docs: Phase 5 landed — plane coverage and session integrity"
git push origin main && git tag v0.14.0-dev && git push origin v0.14.0-dev
```

> Do not bump the installer pins — those live in the chezmoi repo and are Carlitos's call.

---

## Self-Review

**1. Finding coverage.** H-10 → Task 1 (all four layers: matcher, parser, candidate gates, CI guard); H-6 → Task 2 (URL gating *and* the URL-less `WebSearch` case); M-7 → Task 3 (file protection, locking, empty-ID reporting). Locked in Task 4.

**2. Placeholder scan.** One deliberate instruction rather than literal code: Task 1's golden test says to adjust the traversal to the real `ClaudeConfig` return shape, because that shape is not quoted here. Everything else is literal.

**3. Type consistency.** `ToolCall` gains `URL` and `Query` (Task 2), after Phase 4's `pathCandidate.repoRoot`. New helpers: `isKnownReadOnlyTool` (Task 1), `isNetworkTool`, `checkEgressTool` (Task 2), `session.Update` (Task 3). `IsNetworkAttempt` keeps its signature.

**4. Dependency on Phase 4.** Task 1 uses `pathCandidate.repoRoot` from Phase 4 Task 1. Do not start Phase 5 until Phase 4 is landed and tagged.

**5. Risk.** Task 1's `matcher: "*"` is the highest-blast-radius change in the whole remediation: the hook begins running on every tool call in every session. Step 5 exists to catch a latency or false-ask regression before it ships. Task 3's lock must be exercised under `-race -count=20`, not once.
