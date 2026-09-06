# Adversarial Remediation — Phase 4: Invert the Closed Allowlists

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the last of the 2026-09-04 adversarial review. Phases 1–3 fixed how a command is *tokenized*; Phase 4 fixes what the rules are *allowed to see* — the closed allowlists that fail open on anything unlisted — and removes the false positives that make a guardrail get switched off.

**Architecture:** One root cause explains most of both halves. `matchesAnyGlob` applies a **basename fallback to every glob**, which simultaneously creates false positives (`*.key` matches `i18n/translations.key`; `Makefile` matches `vendor/x/Makefile`) *and* a bypass (`secret_allow`'s `**/.env.example` matches the bare name `.env.example` anywhere — including inside `~/.ssh/`). Removing that fallback and making bare-name intent explicit in the glob lists fixes M-2, M-4, M-5 and H-2 in a single change. The rest is structural: scan every argument rather than 14 named readers, treat any payload-carried path as a file path regardless of tool name, and gate the native web tools.

**Tech Stack:** Go 1.23+, existing deps only.

**Spec:** `../reviews/2026-09-04-adversarial-review.md`. Findings addressed: **RC4 (CR-9), H-2, H-6, H-7, H-10, M-2, M-3, M-4, M-5, M-6, M-7**. All eleven were re-probed against `main` immediately before this plan was written and confirmed still open.

## Global Constraints

- **This phase changes what is matched, in both directions.** Task 1 removes a fallback that currently *catches* things; Task 5 starts scanning arguments that are currently *ignored*. Both directions need corpus locks: every task adds `"want": "deny"` entries for the bypass it closes **and** `"want": "allow"` entries for the legitimate cases nearby.
- **False positives are in scope, and they matter.** M-2/M-4/M-6 are why people disable guardrails. A fix that closes a bypass while making `conftest.py` prompt on every test file has not improved safety.
- **Do not blanket-exempt `testdata/`.** A real key can live at `testdata/id_rsa`. `*.pub` is exempted because a public key is public by definition; anything broader belongs in a project's overlay, which now requires an operator grant (ADR-0010) and is therefore a deliberate decision rather than a default.
- Every code step is literal. `gofmt -w` before every commit. Conventional Commits, one commit per task.
- Verified current state (read from the tree immediately before writing): `matchesAnyGlob` does `path.Clean(filepath.ToSlash(...))` then tries `doublestar.Match(g, p)` **and** `doublestar.Match(g, base)` — the basename fallback. `pathReaders` is a 14-entry map consulted in `privatePathCandidates`, which already gathers `s.Redirects`, `s.ReadRedirects` and `writeTargets(s)` (so *writes* are covered; *reads* are not). `classifiedSecretPath` checks `SecretAllow` before `SecretGlobs`, both via `matchesAnyGlob`. `isFileTool` accepts `read/edit/write/multiedit` only.

---

### Task 1: Remove the basename fallback; make bare-name intent explicit

**Files:** `internal/engine/rules_path.go`, `internal/policy/base.toml`, and their tests

**Why not simply delete it:** the glob lists deliberately mix two kinds of entry. `**/.claude/**` and `**/.bashrc` are meant to match anywhere; `CLAUDE.md`, `Makefile`, `conftest.py`, `.envrc`, `Dockerfile` and the lockfiles are meant to match **only at a repository root**. Today the *only* thing that makes the second kind match an absolute path like `/repo/CLAUDE.md` is the basename fallback — and that same fallback is what wrongly matches `/repo/docs/templates/CLAUDE.md` and `/repo/vendor/x/Makefile`. So the fallback is not deleted, it is **replaced with the correct form**: the path relative to the repository root.

**Interfaces:**
- `matchesAnyGlob(p string, globs []string) bool` matches the cleaned full path only — no basename fallback.
- New `func repoRelative(p, repoRoot string) (string, bool)` in `rules_path.go`: cleans and slash-normalizes both, returns `p` relative to `repoRoot` when `p` is inside it, and `("", false)` otherwise (including when `repoRoot` is empty).
- `checkSelfConfig`, `checkCIInfraLockfile` and the `gitProtectedGlobs` check each test the repo-relative form as well. All three already read `protected := matchesAnyGlob(raw, …)` then `protected = protected || matchesAnyGlob(resolved, …)` — this is a third `||` in the same shape. `tc.RepoRoot` is already in scope in each.
- `pathCandidate` gains a `repoRoot string` field, set wherever candidates are built (`writeCandidates`, `privatePathCandidates`), and `pathCandidateForms` appends the repo-relative form so `classifiedSecretPath` sees it too.
- `base.toml`'s `secret_globs` and `secret_allow` get explicit `**/` prefixes on every bare-name entry — `id_rsa*` → `**/id_rsa*`, `*.pem` → `**/*.pem`, `*.key` → `**/*.key`, `service-account*.json` → `**/service-account*.json`, and so on. Secrets are meant to match anywhere, not only at a repo root, so for these the prefix is the right replacement for the fallback.

- [ ] **Step 1: Write the failing test**

```go
func TestBasenameFallbackRemoved(t *testing.T) {
	pol := pathPol()
	// False positives that must now be ALLOWED (M-2, M-4, M-5):
	allow := []string{
		"/repo/i18n/translations.key",
		"/repo/src/locale/en.key",
		"/repo/vendor/x/Makefile",
		"/repo/tests/unit/conftest.py",
		"/repo/docs/templates/CLAUDE.md",
		"/repo/node_modules/pkg/AGENTS.md",
	}
	for _, p := range allow {
		for _, tool := range []string{"Read", "Write"} {
			tc := ToolCall{Tool: tool, Paths: []string{p}, RepoRoot: "/repo", CWD: "/repo"}
			if v := checkPaths(tc, pol); v != nil && v.Decision == policy.Deny {
				t.Errorf("%s %q -> %+v, want not-deny (basename fallback false positive)", tool, p, v)
			}
		}
	}
	// Real targets that must still be caught, now via explicit **/ globs:
	deny := []string{"/home/u/.ssh/id_rsa", "/home/u/secrets/server.pem", "/repo/.env"}
	for _, p := range deny {
		tc := ToolCall{Tool: "Read", Paths: []string{p}, RepoRoot: "/repo", CWD: "/repo"}
		if v := checkPaths(tc, pol); v == nil || v.Decision != policy.Deny {
			t.Errorf("Read %q -> %+v, want deny", p, v)
		}
	}
	// Repo-root-only entries must NOT match at depth:
	tcRoot := ToolCall{Tool: "Write", Paths: []string{"/repo/CLAUDE.md"}, RepoRoot: "/repo", CWD: "/repo"}
	if v := checkPaths(tcRoot, pol); v == nil || v.Decision != policy.Deny {
		t.Errorf("repo-root CLAUDE.md -> %+v, want deny", v)
	}
}

func TestSecretAllowNoLongerMatchesByBasename(t *testing.T) {
	// H-2: a file merely NAMED .env.example must not neutralize **/.ssh/**
	pol := pathPol()
	tc := ToolCall{Tool: "Read", Paths: []string{"/home/u/.ssh/.env.example"}, RepoRoot: "/repo", CWD: "/repo"}
	if v := checkPaths(tc, pol); v == nil || v.Decision != policy.Deny {
		t.Fatalf("-> %+v, want deny — a basename must not beat a directory glob", v)
	}
}
```

- [ ] **Step 2: Run to verify it fails** → the allow cases DENY, and the `.ssh/.env.example` case ALLOWs.

- [ ] **Step 3: Implement**

```go
func matchesAnyGlob(p string, globs []string) bool {
	p = path.Clean(filepath.ToSlash(strings.TrimPrefix(p, "./")))
	for _, g := range globs {
		if ok, _ := doublestar.Match(g, p); ok {
			return true
		}
	}
	return false
}

// repoRelative returns p expressed relative to repoRoot when p is inside it.
// Bare-name globs like "CLAUDE.md" and "Makefile" are repo-root-relative by
// intent; matching them against this form is what the basename fallback was
// standing in for, without also matching them at any depth (review M-2/M-4/M-5).
func repoRelative(p, repoRoot string) (string, bool) {
	if repoRoot == "" || !filepath.IsAbs(p) {
		return "", false
	}
	root := path.Clean(filepath.ToSlash(repoRoot))
	q := path.Clean(filepath.ToSlash(p))
	if q == root {
		return "", false
	}
	if !strings.HasPrefix(q, root+"/") {
		return "", false
	}
	return strings.TrimPrefix(q, root+"/"), true
}
```

Then add the third `||` to each of the three callers, e.g. in `checkSelfConfig`:

```go
		if rel, ok := repoRelative(path, tc.RepoRoot); ok {
			protected = protected || matchesAnyGlob(rel, selfConfigGlobs)
		}
```

and append the same form in `pathCandidateForms`. Finally prefix the bare-name entries in `base.toml`. **Work one list at a time and re-run the suite after each** — a missed `**/` prefix silently *weakens* a rule, which is the dangerous direction. Afterwards `grep -n` each list and confirm every entry is either `**/`-prefixed or deliberately repo-root-only.

- [ ] **Step 4: Run the full suite** — expect existing tests to need updating where they encoded basename behaviour. Confirm each change is correct per the review before editing an expectation.

- [ ] **Step 5: Commit**

```bash
gofmt -w internal/engine/ internal/policy/ && git add internal/engine/ internal/policy/
git commit -m "fix(engine): drop the universal basename fallback; make bare-name globs explicit (H-2, M-2, M-4, M-5)"
```

---

### Task 2: H-7 — case-insensitive glob matching

**Files:** `internal/engine/rules_path.go`, tests

**Interfaces:** `matchesAnyGlob` lowercases both the pattern and the path before matching. These are security globs; on APFS/NTFS `~/.SSH/ID_RSA` opens the real key, and a false positive from case-folding a secret path is not a realistic cost.

- [ ] **Step 1: Write the failing test**

```go
func TestGlobMatchingIsCaseInsensitive(t *testing.T) {
	pol := pathPol()
	for _, p := range []string{"/home/u/.SSH/ID_RSA", "/home/u/.Ssh/id_rsa", "/repo/.ENV"} {
		tc := ToolCall{Tool: "Read", Paths: []string{p}, RepoRoot: "/repo", CWD: "/repo"}
		if v := checkPaths(tc, pol); v == nil || v.Decision != policy.Deny {
			t.Errorf("Read %q -> %+v, want deny", p, v)
		}
	}
}
```

- [ ] **Step 2: Run to verify it fails** → all ALLOW.

- [ ] **Step 3: Implement**

```go
func matchesAnyGlob(p string, globs []string) bool {
	p = strings.ToLower(path.Clean(filepath.ToSlash(strings.TrimPrefix(p, "./"))))
	for _, g := range globs {
		if ok, _ := doublestar.Match(strings.ToLower(g), p); ok {
			return true
		}
	}
	return false
}
```

- [ ] **Step 4: Run + commit**

```bash
gofmt -w internal/engine/ && git add internal/engine/
git commit -m "fix(engine): case-insensitive glob matching — ~/.SSH/ID_RSA opens the real key on APFS/NTFS (H-7)"
```

---

### Task 3: M-3 / M-6 — the remaining false positives

**Files:** `internal/policy/base.toml`, `internal/engine/rules_bash.go:307`, tests

**Interfaces:**
- `base.toml` `secret_allow` gains `**/*.pub` — a public key is public by definition, and `id_rsa.pub` is currently denied.
- The `case "clean":` arm in `rules_bash.go` (line ~307, `if hasAnyFlag(s.Argv, "fxd", "--force")`) short-circuits to `nil` when `-n`/`--dry-run` is present, *before* that check: `git clean -nxd` is the canonical *preview* and removes nothing.

- [ ] **Step 1: Write the failing test**

```go
func TestPublicKeysAndDryRunsAllowed(t *testing.T) {
	pol := pathPol()
	tc := ToolCall{Tool: "Read", Paths: []string{"/repo/testdata/id_rsa.pub"}, RepoRoot: "/repo", CWD: "/repo"}
	if v := checkPaths(tc, pol); v != nil && v.Decision == policy.Deny {
		t.Errorf("id_rsa.pub -> %+v, want not-deny (a public key is public)", v)
	}
	// the private key beside it must still deny
	tc = ToolCall{Tool: "Read", Paths: []string{"/repo/testdata/id_rsa"}, RepoRoot: "/repo", CWD: "/repo"}
	if v := checkPaths(tc, pol); v == nil || v.Decision != policy.Deny {
		t.Errorf("id_rsa -> %+v, want deny", v)
	}
	for _, c := range []string{`git clean -n`, `git clean -nxd`, `git clean --dry-run -d`} {
		if v := evalBash(t, c); v != nil && v.Decision == policy.Deny {
			t.Errorf("%q -> %+v, want not-deny (dry run is read-only)", c, v)
		}
	}
	if v := evalBash(t, `git clean -fdx`); v == nil || v.Decision != policy.Deny {
		t.Errorf("git clean -fdx -> %+v, want deny", v)
	}
}
```

- [ ] **Step 2: Run to verify it fails.**

- [ ] **Step 3: Implement** — add `"**/*.pub"` to `secret_allow` in `base.toml`; in `checkGit`'s `clean` case, before the existing flag check:

```go
	case "clean":
		if hasAnyFlag(s.Argv, "n", "--dry-run") {
			return nil // a dry run lists what would be removed; nothing is deleted
		}
```

- [ ] **Step 4: Run + commit**

```bash
gofmt -w internal/engine/ internal/policy/ && git add internal/engine/ internal/policy/
git commit -m "fix(policy): exempt *.pub; git clean dry runs are read-only (M-3, M-6)"
```

---

### Task 4: M-7 — protect the guard's own session state

**Files:** `internal/engine/rules_path.go`, tests

**Interfaces:** `selfConfigGlobs` gains `**/.local/state/guardrail/**` and `**/guardrail/sessions/**` (plus the Windows `%LOCALAPPDATA%` shape via `**/AppData/Local/guardrail/**`). A flagless `rm <session>.json` currently deletes both trifecta legs — self-neutering.

- [ ] **Step 1: Write the failing test**

```go
func TestSessionStateIsProtected(t *testing.T) {
	for _, c := range []string{
		`rm /home/u/.local/state/guardrail/sessions/s1.json`,
		`rm -f /home/u/.local/state/guardrail/audit.jsonl`,
		`cp evil /home/u/.local/state/guardrail/sessions/s1.json`,
	} {
		v := evalBash(t, c)
		if v == nil || v.Decision == policy.Allow {
			t.Errorf("%q -> %+v, want deny or ask", c, v)
		}
	}
}
```

- [ ] **Step 2: Run to verify it fails** → the flagless `rm` ALLOWs.

- [ ] **Step 3: Implement** — extend `selfConfigGlobs`:

```go
	// the guard's own state: deleting a session file erases both trifecta legs,
	// and truncating the audit log destroys the record (review M-7).
	"**/.local/state/guardrail/**", "**/guardrail/sessions/**",
	"**/AppData/Local/guardrail/**",
```

- [ ] **Step 4: Run + commit**

```bash
gofmt -w internal/engine/ && git add internal/engine/
git commit -m "fix(engine): protect the guard's own session state and audit log from deletion (M-7)"
```

---

### Task 5: RC4 — scan every argument, not fourteen named readers

**Files:** `internal/engine/rules_path.go`, tests

**Interfaces:** `privatePathCandidates` stops consulting `pathReaders` and instead contributes **every non-flag argument of every simple** as a read candidate. `pathReaders` is deleted. The secret globs are specific enough that an ordinary argument will not match; the corpus locks the legitimate cases.

- [ ] **Step 1: Write the failing test**

```go
func TestSecretReadsViaAnyCommand(t *testing.T) {
	pol := pathPol()
	deny := []string{
		`cp /home/u/.ssh/id_rsa /tmp/x`,
		`mv /home/u/.ssh/id_rsa /tmp/x`,
		`base64 /home/u/.aws/credentials`,
		`tar cf - /home/u/.ssh/id_rsa`,
		`openssl rsa -in /home/u/.ssh/id_rsa`,
		`md5sum /home/u/.ssh/id_rsa`,
		`jq . /home/u/.claude.json`,
		`dd if=/home/u/.ssh/id_rsa`,
	}
	for _, c := range deny {
		tc := ToolCall{Tool: "Bash", Command: c, RepoRoot: "/repo", CWD: "/repo"}
		v := checkPaths(tc, pol)
		if v == nil || v.Decision != policy.Deny {
			t.Errorf("%q -> %+v, want deny", c, v)
		}
	}
}

func TestOrdinaryArgumentsStillAllowed(t *testing.T) {
	pol := pathPol()
	for _, c := range []string{
		`go build ./...`, `npm test`, `grep -r TODO src/`,
		`cp src/a.go src/b.go`, `docker compose up -d`,
		`echo "--env is a flag not a secret"`,
	} {
		tc := ToolCall{Tool: "Bash", Command: c, RepoRoot: "/repo", CWD: "/repo"}
		if v := checkPaths(tc, pol); v != nil && v.Decision == policy.Deny {
			t.Errorf("%q -> %+v, want not-deny", c, v)
		}
	}
}
```

- [ ] **Step 2: Run to verify it fails** → the deny cases ALLOW.

- [ ] **Step 3: Implement** — in `privatePathCandidates`, replace the `pathReaders[head(s.Argv)]` guard:

```go
			// Every non-flag argument is a potential path. A closed list of
			// "reader" commands failed open on cp/base64/python3/tar/openssl
			// and everything else unlisted (review CR-9/RC4).
			for _, p := range nonFlagArgs(s.Argv) {
				candidates = append(candidates, pathCandidate{path: p, cwd: s.Cwd, cwdUnknown: s.cwdUnknown, repoRoot: tc.RepoRoot})
			}
```

and delete the now-unused `pathReaders` map.

- [ ] **Step 4: Run the full suite carefully**

Run: `/usr/local/go/bin/go test ./... -v`
This is the highest false-positive-risk change in the plan. Any newly-failing test is a signal: confirm whether the new deny is correct before touching the expectation.

- [ ] **Step 5: Commit**

```bash
gofmt -w internal/engine/ && git add internal/engine/
git commit -m "fix(engine): scan every argument for secret paths instead of 14 named readers (CR-9/RC4)"
```

---

### Task 6: H-10 — any payload-carried path is a path, whatever the tool is called

**Files:** `internal/engine/rules_path.go`, `internal/adapter/claude.go`, tests

**Interfaces:**
- `ParseClaude` extracts a path from `tool_input` for **any** tool name, not only the four known file tools — checking `file_path`, `path`, `notebook_path`, and `edits[].file_path` in order.
- `privatePathCandidates` contributes `tc.Paths` unconditionally (drop its `isFileTool` guard) — an unknown tool's path is treated as a read, which is the safe floor.
- `writeCandidates` has the same closed guard and needs the same treatment, but the *write* rules must not fire on a read: change its guard from `isFileTool(tc.Tool)` to `!isKnownReadOnlyTool(tc.Tool)`, with a small `isKnownReadOnlyTool` covering `Read`, `Glob`, `Grep`, `WebFetch`, `WebSearch`, `TodoWrite`, `Task` (case-insensitively). An unrecognized tool carrying a path is then treated as a potential write — which is what makes `NotebookEdit` and opencode's `patch` reach `checkSelfConfig` at all.

- [ ] **Step 1: Write the failing test**

```go
func TestUnknownToolPathsAreStillChecked(t *testing.T) {
	pol := pathPol()
	for _, tool := range []string{"NotebookEdit", "SomeFutureTool", "", "patch"} {
		tc := ToolCall{Tool: tool, Paths: []string{"/home/u/.ssh/id_rsa"}, RepoRoot: "/repo", CWD: "/repo"}
		v := checkPaths(tc, pol)
		if v == nil || v.Decision != policy.Deny {
			t.Errorf("tool %q with a secret path -> %+v, want deny", tool, v)
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
		if len(tc.Paths) != 1 || tc.Paths[0] != "/home/u/.ssh/id_rsa" {
			t.Errorf("%s -> Paths=%v, want the secret path extracted", raw, tc.Paths)
		}
	}
}
```

- [ ] **Step 2: Run to verify it fails.**

- [ ] **Step 3: Implement**

In `internal/adapter/claude.go`, widen the payload struct and extraction — decode `tool_input` into a `map[string]any` alongside the typed fields, and pull the first present of `file_path`, `path`, `notebook_path`; for `edits`, collect each element's `file_path`.

In `privatePathCandidates`, drop the file-tool guard entirely:

```go
	// Any path the payload carries is a path, whatever the tool is called.
	// A closed tool-name list failed open on NotebookEdit, opencode's patch,
	// and every future tool (review H-10).
	for _, p := range tc.Paths {
		candidates = append(candidates, pathCandidate{path: p, cwd: tc.CWD, repoRoot: tc.RepoRoot})
	}
```

In `writeCandidates`, swap the guard for the read-only list:

```go
func isKnownReadOnlyTool(name string) bool {
	switch strings.ToLower(name) {
	case "read", "glob", "grep", "webfetch", "websearch", "todowrite", "task":
		return true
	}
	return false
}
```

```go
	// An unrecognized tool carrying a path may well be writing to it; only the
	// tools we know to be read-only are exempt from the write rules (H-10).
	if !isKnownReadOnlyTool(tc.Tool) {
		for _, p := range tc.Paths {
			out = append(out, pathCandidate{path: p, cwd: tc.CWD, repoRoot: tc.RepoRoot})
		}
	}
```

Then re-check `checkSelfConfig` and `checkCIInfraLockfile`: both open with `if isFileTool(tc.Tool) && !isWriteToolCall(tc.Tool) { return nil }`, which still correctly exempts a known `Read` and no longer decides anything for unknown tools.

- [ ] **Step 4: Run + commit**

```bash
gofmt -w internal/engine/ internal/adapter/ && git add internal/engine/ internal/adapter/
git commit -m "fix(engine): check paths from any tool, not a closed tool-name list (H-10)"
```

---

### Task 7: H-6 — gate the native web tools

**Files:** `internal/engine/rules_net.go`, `internal/engine/trifecta_signals.go`, `internal/genconfig/claude.go`, tests

**Interfaces:**
- `ToolCall` gains `URL string`; `ParseClaude` fills it from `tool_input.url`.
- `checkEgress` additionally evaluates `tc.URL` against `pol.Slots.EgressAllowlist` for tools named `WebFetch`/`WebSearch`/`webfetch` — the same host extraction and allowlist as bash egress.
- `IsNetworkAttempt` returns true when `tc.URL != ""`, so the native web tools arm the trifecta's network leg.
- `claudeHooks`'s `PreToolUse` matcher gains `WebFetch|WebSearch` so the hook is actually invoked for them; regenerate the golden.

- [ ] **Step 1: Write the failing test**

```go
func TestWebFetchIsGated(t *testing.T) {
	pol := netPol("api.github.com")
	tc := ToolCall{Tool: "WebFetch", URL: "https://evil.example.com/steal", CWD: "/repo", RepoRoot: "/repo"}
	if v := checkEgress2(tc, pol); v == nil || v.Decision != policy.Deny {
		t.Fatalf("-> %+v, want deny", v)
	}
	tc.URL = "https://api.github.com/repos/x"
	if v := checkEgress2(tc, pol); v != nil {
		t.Fatalf("allowlisted host -> %+v, want nil", v)
	}
}

func TestWebFetchArmsTrifectaNetLeg(t *testing.T) {
	if !IsNetworkAttempt(ToolCall{Tool: "WebFetch", URL: "https://x.example.com/y"}) {
		t.Fatal("WebFetch must arm the network leg")
	}
}
```

(Name the tool-level entry point to match whatever `checkEgress` becomes — if it stays `checkEgress(s Simple, pol)`, add a sibling `checkEgressTool(tc ToolCall, pol *policy.Policy) *policy.Verdict` and call it from `Evaluate`.)

- [ ] **Step 2: Run to verify it fails.**

- [ ] **Step 3: Implement** — add `URL` to `ToolCall`, fill it in `ParseClaude`, add the tool-level egress check and wire it into `Evaluate` alongside `checkPaths`/`checkBash`, extend `IsNetworkAttempt`, and widen the `PreToolUse` matcher in `claudeHooks`.

- [ ] **Step 4: Regenerate the golden**

```bash
/usr/local/go/bin/go test ./test/ -run Golden -update && /usr/local/go/bin/go test ./test/ -run Golden -v
```
Confirm the diff is only the matcher string.

- [ ] **Step 5: Commit**

```bash
gofmt -w internal/ && git add internal/
git commit -m "fix(engine): gate WebFetch/WebSearch by the egress allowlist and arm the trifecta net leg (H-6)"
```

---

### Task 8: Corpus, docs, tag

- [ ] **Step 1: Extend the corpus** with every Phase 4 reproduction as `deny`/`ask`, and — equally important — as `allow`: `Read /repo/i18n/translations.key`, `Read /repo/testdata/id_rsa.pub`, `Write /repo/tests/unit/conftest.py`, `Write /repo/vendor/x/Makefile`, `git clean -nxd`, `go build ./...`, `npm test`, `grep -r TODO src/`, `cp src/a.go src/b.go`.
- [ ] **Step 2:** `make check && /usr/local/go/bin/go test ./... -count=1` → green, **zero corpus entries relaxed**.
- [ ] **Step 3:** Annotate the review with `**[FIXED — Phase 4]**` on CR-9/RC4, H-2, H-6, H-7, H-10, M-2, M-3, M-4, M-5, M-6, M-7; update the response-report ledger — **the review should now be fully closed**.
- [ ] **Step 4:**
```bash
git add -A && git commit -m "docs: Phase 4 landed — the 2026-09-04 adversarial review is fully closed"
git push origin main && git tag v0.13.0-dev && git push origin v0.13.0-dev
```

> **After this, the installer pin should be advanced to `v0.13.0-dev`** — but that is Carlitos's call and it is done in the chezmoi repo (four pin locations; see the Phase 1 plan's Task 10b for the file list). Do not do it from here.

---

## Self-Review

**1. Finding coverage.** H-2/M-2/M-4/M-5 → Task 1 (one root cause); H-7 → Task 2; M-3/M-6 → Task 3; M-7 → Task 4; CR-9/RC4 → Task 5; H-10 → Task 6; H-6 → Task 7; all locked in Task 8. That is every remaining open finding in the review.

**2. Placeholder scan.** No `TBD`. Task 7's parenthetical about naming the tool-level egress entry point is a real "match what exists" instruction — the current `checkEgress` takes a `Simple`, and a tool-level call needs a `ToolCall`, so the executor must pick the shape that fits rather than force one.

**3. Type consistency.** `pathCandidate` gains `repoRoot string` in Task 1; Tasks 5 and 6 set it on the candidates they add. `ToolCall` gains `URL string` (Task 7) — additive, after `Unresolved` (Phase 1) and `Cwd` (Phase 2) on `Simple`. `pathReaders` is **deleted** (Task 5); `isFileTool` survives but stops gating candidate collection (Task 6), and the new `isKnownReadOnlyTool` is what gates the write side. `matchesAnyGlob` keeps its signature; its semantics change twice (Tasks 1, 2). `ParseClaude` keeps its signature; its extraction widens (Tasks 6, 7). No exported signature outside `internal/engine` and `internal/adapter` changes.

**4. Risk, and the order it dictates.** Task 5 is the highest false-*positive* risk in the whole remediation — it starts matching every argument of every command. Task 1 is the highest false-*negative* risk: a missed `**/` prefix or an unthreaded `repoRoot` silently weakens a rule rather than loudly breaking one. **Task 1 must land before Tasks 5 and 6**, because both of those feed many more candidates into the very matcher Task 1 is changing; doing them first would mean debugging two semantics at once. Tasks 2, 3, 4 are independent and can move in any order. This is also why Task 8's `allow` locks matter as much as the `deny` ones.

**5. What this does not cover.** `writeTargets` still enumerates a fixed list of mutating commands — Task 5 fixes the *read* side of RC4 by scanning every argument, and Task 6 fixes the *tool-name* side, but a novel mutating binary invoked with an argument that is not a redirect is still only caught if its target matches a secret or self-config glob. That residue is narrower than the original finding and is recorded here deliberately rather than left implied.

---

## Execution Handoff

**Plan complete and saved to `docs/superpowers/plans/2026-09-06-remediation-phase4.md`. Two execution options:**

**1. Subagent-Driven (recommended)** — fresh subagent per task via `superpowers:subagent-driven-development`, review between tasks.

**2. Inline Execution** — `superpowers:executing-plans`, batch with checkpoints.

**Which approach?**
