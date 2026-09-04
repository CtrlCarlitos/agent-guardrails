# Adversarial Remediation — Phase 1: Self-Protection and Surgical Fixes

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the findings from `docs/reviews/2026-09-04-adversarial-review.md` that are (a) exploitable without a hostile repo, (b) small and surgical, or (c) currently leaving a whole platform unguarded — and lock every one behind a permanent adversarial regression test.

**Architecture:** No architectural change. Four of these are one-to-three-line fixes to helpers that already exist; two add a lookup table; one is a chezmoi one-liner. The largest single win (`literalText` in `splitSimples`) uses a helper already written and already used elsewhere in the same file. Phase 1 deliberately excludes the overlay trust model, which is a **design change requiring Carlitos's decision** — see the Roadmap.

**Tech Stack:** Go 1.23+, existing deps only. One chezmoi shell change.

**Spec:** `../../reviews/2026-09-04-adversarial-review.md`. Findings addressed here: **RC1 (CR-2), RC2 (CR-1), RC3 (CR-7), CR-8, CR-12, CR-14, CR-15, CR-16, M-1, M-9**.

## Global Constraints

- **Every fix ships with an adversarial regression test using the review's exact reproduction.** Task 11 collects them into `test/adversarial/`; individual tasks add theirs as they go. A fix without its lock does not count as done.
- **Fail closed on ambiguity.** Where a word cannot be resolved to literal text (`$VAR`, `$(…)`), the verdict must degrade to at least `ask` — never silently allow.
- **Do not weaken any existing deny.** Run the full suite after every task; the review's "correctly defended" list must stay defended. Several existing tests encode current (wrong) behaviour for quoted/absolute forms — if a test fails because the guard now *correctly* denies something, update the test and say so in the commit body.
- **Out of scope for Phase 1** (tracked in the Roadmap): the overlay trust model (unbounded `waive`, slot widening, `audit_log`, size cap), `cd` tracking, git `valueFlags`/refspec, redirect-only statements, docker arg parsing, egress host extraction, pipeline-wide fetch→interpreter, unknown-tool default-deny, `Reason` sanitization.
- Every code step is literal. `gofmt -w` before every commit. Conventional Commits, one commit per task.
- Verified building blocks: `literalText(tok string) (string, bool)` at `internal/engine/tokenize.go:133` — confirmed by probe to return `("/etc", true)` for `"/etc"`, `("--force", true)` for `"--force"`, and `("", false)` for `$HOME` / `$(echo /etc)`. `matchesAnyGlob(p string, globs []string) bool` at `rules_path.go:158`. `writeCandidates(tc ToolCall) []string` at `rules_path.go:75`. `checkCIInfraLockfile`'s Write/Edit gate at `rules_path.go:129` is the correct model to copy.

---

### Task 1: RC1 — store literal text, not source spelling

**Files:** Modify `internal/engine/tokenize.go`, `internal/engine/tokenize_test.go`

**Interfaces:**
- `Simple` gains `Unresolved bool` — true when any word in this command could not be reduced to literal text (an unexpanded `$VAR`, `$(…)`, backtick).
- `splitSimples` runs every argv word and every redirect word through `literalText`; on success stores the literal, on failure stores the raw spelling **and sets `Unresolved`**.

- [ ] **Step 1: Write the failing test**

Add to `internal/engine/tokenize_test.go`:

```go
func TestSplitSimplesStoresLiteralText(t *testing.T) {
	cases := []struct {
		src  string
		want [][]string
	}{
		{`rm -rf "/etc"`, [][]string{{"rm", "-rf", "/etc"}}},
		{`rm -rf '/etc'`, [][]string{{"rm", "-rf", "/etc"}}},
		{`git push "--force"`, [][]string{{"git", "push", "--force"}}},
		{`cat "/home/u/.env"`, [][]string{{"cat", "/home/u/.env"}}},
	}
	for _, c := range cases {
		got, err := splitSimples(c.src)
		if err != nil {
			t.Fatalf("splitSimples(%q): %v", c.src, err)
		}
		if !reflect.DeepEqual(argvs(got), c.want) {
			t.Errorf("splitSimples(%q) = %v, want %v", c.src, argvs(got), c.want)
		}
	}
}

func TestSplitSimplesRedirectLiteral(t *testing.T) {
	got, err := splitSimples(`echo x > "/etc/passwd"`)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || len(got[0].Redirects) != 1 || got[0].Redirects[0] != "/etc/passwd" {
		t.Fatalf("redirects = %+v, want [/etc/passwd]", got[0].Redirects)
	}
}

func TestSplitSimplesMarksUnresolved(t *testing.T) {
	got, err := splitSimples(`rm -rf $HOME`)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || !got[0].Unresolved {
		t.Fatalf("want Unresolved=true for an unexpanded $HOME, got %+v", got)
	}
	clean, _ := splitSimples(`rm -rf /etc`)
	if clean[0].Unresolved {
		t.Error("a fully literal command must not be marked Unresolved")
	}
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `/usr/local/go/bin/go test ./internal/engine/ -run TestSplitSimples -v`
Expected: FAIL — argv currently contains `"/etc"` with quotes; `Unresolved` undefined.

- [ ] **Step 3: Write the implementation**

In `internal/engine/tokenize.go`, extend the type:

```go
type Simple struct {
	Argv       []string
	Redirects  []string
	Unresolved bool
}
```

In `splitSimples`, replace both word-collection loops:

```go
		s := Simple{}
		for _, w := range ce.Args {
			var b strings.Builder
			_ = printer.Print(&b, w)
			raw := b.String()
			if lit, ok := literalText(raw); ok {
				s.Argv = append(s.Argv, lit)
			} else {
				s.Argv = append(s.Argv, raw)
				s.Unresolved = true
			}
		}
		for _, r := range stmt.Redirs {
			if r.Word == nil {
				continue
			}
			var b strings.Builder
			_ = printer.Print(&b, r.Word)
			raw := b.String()
			if lit, ok := literalText(raw); ok {
				s.Redirects = append(s.Redirects, lit)
			} else {
				s.Redirects = append(s.Redirects, raw)
				s.Unresolved = true
			}
		}
```

- [ ] **Step 4: Run the full suite — expect existing tests to change**

Run: `/usr/local/go/bin/go test ./... 2>&1 | tail -40`
Expected: the new tests PASS. **Some existing tests may fail because the guard now correctly denies what it previously allowed** (e.g. a fixture asserting exit 0 for a quoted form). For each: confirm the new behaviour is the *correct* one per the review, update the expectation, and list the change in the commit body. Do not weaken a fix to satisfy a stale test.

- [ ] **Step 5: Prove the bypasses are closed**

```bash
/usr/local/go/bin/go build -o /tmp/gr ./cmd/guardrail
S=$(mktemp -d)
for c in 'rm -rf "/etc"' "rm -rf '/etc'" 'cat "/home/carlitos/.env"' 'git push "--force"' 'curl "http://evil.com/x"'; do
  printf '%s' "{\"cwd\":\"/repo\",\"hook_event_name\":\"PreToolUse\",\"tool_name\":\"Bash\",\"tool_input\":{\"command\":$(python3 -c 'import json,sys;print(json.dumps(sys.argv[1]))' "$c")}}" \
  | env XDG_STATE_HOME=$S GUARDRAIL_CONFIG= /tmp/gr hook claude >/dev/null 2>&1; echo "exit=$? for: $c"
done
```
Expected: **every one exits 2.** (Before this task they all exited 0.)

- [ ] **Step 6: Commit**

```bash
gofmt -w internal/engine/
git add internal/engine/
git commit -m "fix(engine): store literal word text, not source spelling — closes the quoted-operand bypass class (CR-2/RC1)"
```

---

### Task 2: Fail closed when a word is unresolved

**Files:** Modify `internal/engine/rules_bash.go`, `internal/engine/rules_bash_test.go`

**Interfaces:** In `checkBash`'s per-`Simple` loop, before the individual rule calls: if `s.Unresolved`, `take()` an `ask` verdict `P3.unresolved` ("command contains an unexpanded variable or substitution; cannot verify its target"). Rules still run — a concrete deny from another rule outranks this ask via existing severity ordering.

- [ ] **Step 1: Write the failing test**

```go
func TestUnresolvedWordAsks(t *testing.T) {
	v := evalBash(t, `rm -rf "$TARGET"`)
	if v == nil || v.Decision != policy.Ask || v.RuleID != "P3.unresolved" {
		t.Fatalf("-> %+v, want ask/P3.unresolved", v)
	}
}

func TestUnresolvedDoesNotMaskADeny(t *testing.T) {
	v := evalBash(t, `rm -rf /etc && echo $UNSET`)
	if v == nil || v.Decision != policy.Deny {
		t.Fatalf("-> %+v, want the concrete deny to still win", v)
	}
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `/usr/local/go/bin/go test ./internal/engine/ -run TestUnresolved -v` → FAIL.

- [ ] **Step 3: Implement**

In `checkBash`'s loop, immediately after the `len(s.Argv) == 0` guard:

```go
		if s.Unresolved {
			take(&policy.Verdict{Decision: policy.Ask, RuleID: "P3.unresolved",
				Reason: "command contains an unexpanded variable or substitution; its real target cannot be verified"})
		}
```

- [ ] **Step 4: Run + commit**

Run: `/usr/local/go/bin/go test ./internal/engine/ -v` → PASS.
```bash
gofmt -w internal/engine/ && git add internal/engine/
git commit -m "fix(engine): unresolved expansions fail closed to ask instead of resolving into a safe root"
```

---

### Task 3: RC3 — lexically clean paths before glob matching

**Files:** Modify `internal/engine/rules_path.go`, `internal/engine/rules_path_test.go`

**Interfaces:** `matchesAnyGlob` normalizes with `path.Clean(filepath.ToSlash(p))` before computing `base` and matching.

- [ ] **Step 1: Write the failing test**

```go
func TestGlobMatchingIgnoresDotSegments(t *testing.T) {
	pol := pathPol()
	deny := []string{
		"/home/u/.kube/./config",
		"/home/u/.kube//config",
		"/home/u/.docker/./config.json",
		"/repo/.git/x/../config",
	}
	for _, p := range deny {
		tc := ToolCall{Tool: "Write", Paths: []string{p}, RepoRoot: "/repo", CWD: "/repo"}
		if v := checkPaths(tc, pol); v == nil {
			t.Errorf("%q -> nil, want a deny (dot-segments must not defeat the glob)", p)
		}
	}
}
```

(Ensure `pathPol()`'s `SecretGlobs` include `**/.kube/config` and `**/.docker/config.json`; add them if absent.)

- [ ] **Step 2: Run to verify it fails** → FAIL for every case.

- [ ] **Step 3: Implement**

In `internal/engine/rules_path.go`, add `"path/filepath"` to imports if absent, and change `matchesAnyGlob`'s first lines:

```go
func matchesAnyGlob(p string, globs []string) bool {
	p = path.Clean(filepath.ToSlash(strings.TrimPrefix(p, "./")))
	base := path.Base(p)
	...
```

- [ ] **Step 4: Run + prove**

Run: `/usr/local/go/bin/go test ./internal/engine/ -v` → PASS. Then rebuild and confirm `cat /home/carlitos/.kube/./config` exits 2.

- [ ] **Step 5: Commit**

```bash
gofmt -w internal/engine/ && git add internal/engine/
git commit -m "fix(engine): path.Clean before glob matching — closes the dot-segment bypass (CR-7/RC3)"
```

---

### Task 4: M-1 — gate self-config and git-protected checks to writes

**Files:** Modify `internal/engine/rules_path.go`, `internal/engine/rules_path_test.go`

**Interfaces:** `checkSelfConfig` and `checkGitProtectedPaths` each gain the same tool gate `checkCIInfraLockfile` already has (`rules_path.go:129`): when the call is a file tool, only `edit`/`write`/`multiedit` proceed. Bash redirect candidates still count for both. Their `Reason` strings change from "write to …" to accurate wording.

- [ ] **Step 1: Write the failing test**

```go
func TestSelfConfigAndGitProtectedAllowReads(t *testing.T) {
	allow := []string{
		"/repo/CLAUDE.md", "/repo/AGENTS.md",
		"/home/u/.claude/skills/x/SKILL.md",
		"/home/u/.claude/plugins/cache/x/y.js",
		"/repo/.git/config", "/repo/.git/hooks/pre-commit",
	}
	for _, p := range allow {
		tc := ToolCall{Tool: "Read", Paths: []string{p}, RepoRoot: "/repo", CWD: "/repo"}
		if v := checkPaths(tc, pathPol()); v != nil {
			t.Errorf("Read %q -> %+v, want nil (reads are not the risk)", p, v)
		}
	}
}

func TestSelfConfigAndGitProtectedStillDenyWrites(t *testing.T) {
	deny := []string{
		"/repo/.claude/settings.json", "/repo/CLAUDE.md",
		"/home/u/.claude/settings.json",
		"/repo/.git/config", "/repo/.git/hooks/pre-commit",
	}
	for _, p := range deny {
		tc := ToolCall{Tool: "Write", Paths: []string{p}, RepoRoot: "/repo", CWD: "/repo"}
		v := checkPaths(tc, pathPol())
		if v == nil || v.Decision != policy.Deny {
			t.Errorf("Write %q -> %+v, want deny", p, v)
		}
	}
}
```

- [ ] **Step 2: Run to verify it fails** → the read cases currently DENY.

- [ ] **Step 3: Implement**

Add a shared helper near `isFileTool` in `rules_path.go`:

```go
// isWriteToolCall reports whether tc is a file-tool call that mutates.
// Bash calls are excluded here on purpose: their write intent is carried by
// redirect targets (and, after the writeCandidates work, by argv), not by the
// tool name.
func isWriteToolCall(tool string) bool {
	switch strings.ToLower(tool) {
	case "edit", "write", "multiedit":
		return true
	}
	return false
}
```

At the top of both `checkSelfConfig` and `checkGitProtectedPaths`:

```go
	if isFileTool(tc.Tool) && !isWriteToolCall(tc.Tool) {
		return nil
	}
```

And correct the reason strings — `checkSelfConfig`: `"write to the agent's own guardrail/shell config: "`; `checkGitProtectedPaths`: `"write to a protected git-internal path: "` (both are now only reachable on writes, so the wording is finally accurate).

- [ ] **Step 4: Run + commit**

Run: `/usr/local/go/bin/go test ./internal/engine/ -v` → PASS.
```bash
gofmt -w internal/engine/ && git add internal/engine/
git commit -m "fix(engine): self-config and git-protected checks gate to writes — reading CLAUDE.md, skills, and .git/config works again (M-1)"
```

---

### Task 5: CR-14 — protect guardrail's own machinery

**Files:** Modify `internal/engine/rules_path.go`, `internal/engine/rules_path_test.go`

**Interfaces:** `selfConfigGlobs` gains `guardrail.toml`, `**/guardrail.toml`, `**/.guardrail/**`, `opencode.json`, `**/opencode.json`, `**/.agents/hooks.json`, `**/.gemini/config/hooks.json`.

- [ ] **Step 1: Write the failing test**

```go
func TestGuardrailOwnMachineryIsProtected(t *testing.T) {
	deny := []string{
		"/repo/guardrail.toml",
		"/repo/.guardrail/guardrail.js",
		"/repo/opencode.json",
		"/repo/.agents/hooks.json",
		"/home/u/.gemini/config/hooks.json",
	}
	for _, p := range deny {
		tc := ToolCall{Tool: "Write", Paths: []string{p}, RepoRoot: "/repo", CWD: "/repo"}
		v := checkPaths(tc, pathPol())
		if v == nil || v.Decision != policy.Deny {
			t.Errorf("Write %q -> %+v, want deny (the agent must not configure its own guard)", p, v)
		}
	}
}
```

- [ ] **Step 2: Run to verify it fails** → all currently ALLOW.

- [ ] **Step 3: Implement** — extend `selfConfigGlobs`:

```go
var selfConfigGlobs = []string{
	"**/.claude/**", "CLAUDE.md", "AGENTS.md", ".mcp.json", ".envrc",
	"**/.bashrc", "**/.zshrc", "**/.profile", "**/.bash_profile",
	// guardrail's own machinery — the agent must not be able to configure,
	// disable, or replace the thing supervising it (review CR-14).
	"guardrail.toml", "**/guardrail.toml",
	"**/.guardrail/**",
	"opencode.json", "**/opencode.json",
	"**/.agents/hooks.json",
	"**/.gemini/config/hooks.json",
}
```

- [ ] **Step 4: Run + commit**

```bash
gofmt -w internal/engine/ && git add internal/engine/
git commit -m "fix(engine): the agent can no longer write guardrail's own policy, plugin, or hook config (CR-14)"
```

---

### Task 6: CR-15/CR-8 — see writes made by argument, not just redirects

**Files:** Modify `internal/engine/rules_path.go`, `internal/engine/rules_path_test.go`

**Interfaces:**
- `var mutatingCommands = map[string][]int{...}` — command basename → argv indices that are write targets, using `-1` to mean "every non-flag argument after the first" where the position varies.
- Simpler and safer given the review's findings: `writeTargets(s Simple) []string` returns, for a mutating command, **all non-flag arguments except the first** (the source), plus any `of=<path>` value for `dd`. For `rm`/`truncate`/`chmod`/`chown`/`mkdir` — where every non-flag arg is a target — it returns all of them.
- `writeCandidates` appends `writeTargets(s)` for every simple.

- [ ] **Step 1: Write the failing test**

```go
func TestWritesByArgumentAreSeen(t *testing.T) {
	deny := []string{
		`cp evil /home/u/.claude/settings.json`,
		`mv evil /home/u/.claude/settings.json`,
		`rm /home/u/.claude/settings.json`,
		`install -m755 evil /home/u/.claude/settings.json`,
		`sed -i s/a/b/ /repo/.git/hooks/pre-commit`,
		`ln -sf evil /repo/.git/hooks/pre-commit`,
		`dd if=evil of=/repo/.git/hooks/pre-commit`,
		`cp evil /repo/guardrail.toml`,
	}
	for _, c := range deny {
		tc := ToolCall{Tool: "Bash", Command: c, RepoRoot: "/repo", CWD: "/repo"}
		v := checkPaths(tc, pathPol())
		if v == nil || v.Decision != policy.Deny {
			t.Errorf("%q -> %+v, want deny", c, v)
		}
	}
}

func TestReadingViaMutatingCommandSourceIsNotAWrite(t *testing.T) {
	// `cp <protected> /tmp/x` reads the protected file; it is not a write to it.
	// It must not be reported as a self-config *write* (the secret-path rule
	// covers the read side separately).
	tc := ToolCall{Tool: "Bash", Command: `cp /repo/CLAUDE.md /tmp/x`, RepoRoot: "/repo", CWD: "/repo"}
	if v := checkSelfConfig(tc); v != nil {
		t.Errorf("-> %+v, want nil (source position is a read, not a write)", v)
	}
}
```

- [ ] **Step 2: Run to verify it fails** → all the deny cases currently ALLOW.

- [ ] **Step 3: Implement**

Add to `internal/engine/rules_path.go`:

```go
// mutatingCommands maps a command basename to how its write targets are found.
// allButFirst: every non-flag arg after the first is written (cp, mv, install, ln).
// allArgs:     every non-flag arg is written/removed (rm, truncate, chmod, chown, mkdir, tee, sed -i).
var mutatingAllButFirst = map[string]bool{
	"cp": true, "mv": true, "install": true, "ln": true, "rsync": true,
}
var mutatingAllArgs = map[string]bool{
	"rm": true, "truncate": true, "chmod": true, "chown": true,
	"mkdir": true, "tee": true, "touch": true, "shred": true,
}

func writeTargets(s Simple) []string {
	if len(s.Argv) == 0 {
		return nil
	}
	head := path.Base(s.Argv[0])
	args := nonFlagArgs(s.Argv)

	if head == "dd" {
		var out []string
		for _, a := range s.Argv[1:] {
			if strings.HasPrefix(a, "of=") {
				out = append(out, strings.TrimPrefix(a, "of="))
			}
		}
		return out
	}
	// `sed -i` edits in place; without -i it is a reader.
	if head == "sed" {
		if !hasAnyFlag(s.Argv, "i", "--in-place") {
			return nil
		}
		if len(args) > 1 {
			return args[1:] // args[0] is the script
		}
		return nil
	}
	if mutatingAllButFirst[head] {
		if len(args) > 1 {
			return args[1:]
		}
		return nil
	}
	if mutatingAllArgs[head] {
		return args
	}
	return nil
}
```

Extend `writeCandidates`'s bash branch:

```go
	if tc.IsBash() {
		if simples, err := Normalize(tc.Command); err == nil {
			for _, s := range simples {
				out = append(out, s.Redirects...)
				out = append(out, writeTargets(s)...)
			}
		}
	}
```

- [ ] **Step 4: Run + prove**

Run: `/usr/local/go/bin/go test ./internal/engine/ -v` → PASS. Rebuild and confirm `rm /home/carlitos/.claude/settings.json` and `install -m755 evil /home/carlitos/.local/bin/guardrail` both exit 2.

> Note: `install … ~/.local/bin/guardrail` is caught only once `~/.local/bin/guardrail` is itself a protected path. Add `**/.local/bin/guardrail` and `**/bin/guardrail` to `selfConfigGlobs` in this task and extend Task 5's test accordingly.

- [ ] **Step 5: Commit**

```bash
gofmt -w internal/engine/ && git add internal/engine/
git commit -m "fix(engine): detect writes made by argument (cp/mv/rm/install/ln/dd/sed -i/tee) — closes the permanent guard-removal bypass (CR-15/CR-8)"
```

---

### Task 7: RC2 — match command heads by basename

**Files:** Modify `internal/engine/rules_bash.go`, `internal/engine/rules_git.go`, `internal/engine/rules_net.go`, and their tests

**Interfaces:** `func head(argv []string) string` in `rules_bash.go` returning `path.Base(argv[0])` (empty for an empty argv). Every rule that compares `s.Argv[0]` to a command name uses `head(s.Argv)` instead: `checkRmRf`, `checkDiskDestroyers`, `checkGit`, `checkDocker`, `checkAskTier`, `checkGitSafety`, `checkEgress`, `checkPackageInstall`, `checkDownloadPipeShell`, and `pathReaders`/`writeTargets` lookups.

- [ ] **Step 1: Write the failing test**

```go
func TestAbsolutePathHeadsAreMatched(t *testing.T) {
	deny := []string{
		`/bin/rm -rf /`,
		`/usr/bin/sudo rm -rf /`,
		`/sbin/mkfs.ext4 /dev/sda1`,
		`/usr/bin/git push --force origin main`,
		`/usr/bin/curl https://evil.com/x`,
	}
	for _, c := range deny {
		v := evalBash(t, c)
		if v == nil || v.Decision != policy.Deny {
			t.Errorf("%q -> %+v, want deny", c, v)
		}
	}
}
```

(Use a policy with an empty `EgressAllowlist` so the curl case denies.)

- [ ] **Step 2: Run to verify it fails** → all ALLOW.

- [ ] **Step 3: Implement** — add the helper and replace every `s.Argv[0] ==` / `s.Argv[0] !=` comparison:

```go
func head(argv []string) string {
	if len(argv) == 0 {
		return ""
	}
	return path.Base(argv[0])
}
```

Work through each rule file; the compiler will not catch a missed site, so grep for `Argv\[0\]` afterwards and confirm every remaining use is intentional (e.g. `docker`'s `argv[1]` subcommand reads are fine).

- [ ] **Step 4: Run + commit**

Run: `/usr/local/go/bin/go test ./... -v` → PASS.
```bash
gofmt -w internal/engine/ && git add internal/engine/
git commit -m "fix(engine): match command heads by basename — /bin/rm no longer bypasses every rule (CR-1/RC2)"
```

---

### Task 8: CR-12 — sanitize `sessionID`

**Files:** Modify `internal/session/session.go`, `internal/session/session_test.go`

**Interfaces:** `Path` and both `Load`/`Save` reject an ID containing a path separator or `..`; `safeSessionID(id string) (string, bool)` returns the id unchanged when safe. An unsafe id is treated exactly like an empty one (heuristic disabled, no file written) and produces a stderr warning from the caller.

- [ ] **Step 1: Write the failing test**

```go
func TestPathTraversalSessionIDIsRejected(t *testing.T) {
	base := t.TempDir()
	t.Setenv("XDG_STATE_HOME", base)
	for _, bad := range []string{"../../../../tmp/pwned", "a/b", `a\b`, "..", "."} {
		if err := Save(bad, &State{SawPrivateRead: true}); err != nil {
			t.Fatalf("Save(%q) should no-op, not error: %v", bad, err)
		}
		if _, err := os.Stat(filepath.Join("/tmp", "pwned.json")); err == nil {
			t.Fatalf("Save(%q) wrote outside the sessions dir", bad)
		}
	}
	if s, _ := Load("../../../../tmp/pwned"); s.SawPrivateRead {
		t.Error("a traversal id must not load state")
	}
}
```

- [ ] **Step 2: Run to verify it fails** → a `/tmp/pwned.json` appears.

- [ ] **Step 3: Implement**

```go
func safeSessionID(id string) bool {
	if id == "" || id == "." || id == ".." {
		return false
	}
	if strings.ContainsAny(id, `/\`) || strings.Contains(id, "..") {
		return false
	}
	return true
}
```

Guard `Load` and `Save` with `if !safeSessionID(sessionID) { return &State{}, nil }` / `{ return nil }` respectively (add `"strings"` to imports).

- [ ] **Step 4: Run + commit**

```bash
gofmt -w internal/session/ && git add internal/session/
git commit -m "fix(session): reject path-traversal session ids — no writes outside the sessions dir (CR-12)"
```

---

### Task 9: CR-16 — pin the opencode binary and require an explicit allow

**Files:** Modify `internal/genconfig/opencode.go`, `internal/genconfig/opencode_plugin.js`, `cmd/guardrail/genconfig.go`, `cmd/guardrail/sync.go`, and their tests

**Interfaces:**
- `OpencodeConfig(pol *policy.Policy, pluginPath string) Fragment` is unchanged, but the **plugin source is templated at deploy time**: `cmdGenConfig`/`cmdSync` substitute the absolute `--binary` value into a `__GUARDRAIL_BIN__` placeholder in the embedded JS before writing it out.
- `callGuardrail` treats anything other than an explicit `decision === "allow"` as a block.

- [ ] **Step 1: Write the failing test**

```go
func TestGenConfigOpencodeBakesAbsoluteBinary(t *testing.T) {
	dir := t.TempDir()
	settings := filepath.Join(dir, "opencode.json")
	os.WriteFile(settings, []byte(`{}`), 0o644)
	var out, errb bytes.Buffer
	code := run([]string{"gen-config", "opencode", "--merge", settings, "--binary", "/ABS/SENTINEL/guardrail"}, strings.NewReader(""), &out, &errb)
	if code != 0 {
		t.Fatalf("exit=%d stderr=%s", code, errb.String())
	}
	js, err := os.ReadFile(filepath.Join(dir, "guardrail.js"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(js), "/ABS/SENTINEL/guardrail") {
		t.Fatalf("deployed plugin does not pin the absolute binary path:\n%s", js)
	}
	if strings.Contains(string(js), "process.env.GUARDRAIL_BIN") {
		t.Error("plugin still resolves its enforcer from the environment")
	}
}
```

- [ ] **Step 2: Run to verify it fails** → the value appears 0 times.

- [ ] **Step 3: Implement**

In `internal/genconfig/opencode_plugin.js`, replace the resolution line and harden the decision check:

```js
// Absolute path baked in by `guardrail gen-config opencode` at deploy time.
// Deliberately NOT read from the environment: an agent that can set
// GUARDRAIL_BIN could otherwise point the enforcer at /bin/true.
const GUARDRAIL_BIN = "__GUARDRAIL_BIN__";
```

and in `callGuardrail`, replace the two `if (decision.decision === …)` branches with:

```js
	if (decision.decision !== "allow") {
		const reason = decision.reason || "no decision returned";
		if (decision.decision === "ask") {
			throw new Error(`guardrail: needs confirmation - ${reason}. Ask the user directly, then retry if they approve.`);
		}
		throw new Error(`guardrail: ${reason}`);
	}
```

Add to `internal/genconfig/opencode.go`:

```go
// OpencodePluginFor returns the embedded plugin source with the absolute
// guardrail path baked in.
func OpencodePluginFor(binary string) []byte {
	return []byte(strings.ReplaceAll(string(OpencodePluginJS), "__GUARDRAIL_BIN__", binary))
}
```

In `cmd/guardrail/genconfig.go` and `cmd/guardrail/sync.go`, replace `os.WriteFile(pluginPath, genconfig.OpencodePluginJS, 0o644)` with `os.WriteFile(pluginPath, genconfig.OpencodePluginFor(absBinary), 0o644)`, where `absBinary` is `filepath.Abs(*binary)` (falling back to `*binary`).

- [ ] **Step 4: Run + commit**

```bash
gofmt -w internal/genconfig/ cmd/guardrail/ && git add internal/genconfig/ cmd/guardrail/
git commit -m "fix(opencode): bake the absolute binary path into the plugin and require an explicit allow (CR-16)"
```

---

### Task 10: M-9 — macOS installs no guard at all

**Files (chezmoi, branch `guardrail-remediation-phase1`):** `run_onchange_install_packages.sh.tmpl`, `scripts/update_ai_tools.sh`

**Interfaces:** Both call sites resolve a checksum tool instead of assuming `sha256sum`.

- [ ] **Step 1: Branch**

```bash
cd ~/.local/share/chezmoi && git checkout main && git pull --ff-only
git checkout -b guardrail-remediation-phase1
```

- [ ] **Step 2: Implement in both files**

Immediately before each checksum verification, add:

```bash
    # stock macOS ships `shasum`, not `sha256sum` — without this the pipeline
    # returns 127, the install is skipped, and the Mac is left with NO guard
    # under a message that misattributes it to a checksum mismatch.
    local SHA_CMD
    if command -v sha256sum &>/dev/null; then SHA_CMD="sha256sum"
    elif command -v gsha256sum &>/dev/null; then SHA_CMD="gsha256sum"
    elif command -v shasum &>/dev/null; then SHA_CMD="shasum -a 256"
    else warn "guardrail: no SHA-256 tool found - cannot verify, skipping install"; rm -rf "$tmp"; return; fi
```

and change the verification to `| $SHA_CMD -c -`. Apply the same in `scripts/update_ai_tools.sh` (without `local`, which is invalid at top level there).

- [ ] **Step 3: Validate**

```bash
chezmoi execute-template < run_onchange_install_packages.sh.tmpl > /tmp/rendered.sh && bash -n /tmp/rendered.sh && echo "sh ok"
bash -n scripts/update_ai_tools.sh && echo "updater ok"
grep -n 'SHA_CMD' /tmp/rendered.sh scripts/update_ai_tools.sh
```

- [ ] **Step 4: Commit (branch, do not apply)**

```bash
git add run_onchange_install_packages.sh.tmpl scripts/update_ai_tools.sh
git commit -m "fix(packages): resolve a SHA-256 tool instead of assuming sha256sum — macOS was installing no guard at all"
```

---

### Task 11: The adversarial regression corpus

**Files:** Create `test/adversarial/corpus.json`, `test/adversarial/adversarial_test.go`

**Interfaces:** A data-driven test locking **every** reproduction fixed in this plan, so none can silently reopen. `corpus.json` is a list of `{name, tool, command|paths, cwd, repo_root, want}` where `want` ∈ `deny|ask|allow`; the test builds the binary once and drives `hook claude` per entry.

- [ ] **Step 1: Write the corpus**

`test/adversarial/corpus.json` — include at minimum, every one `"want": "deny"`:
`rm -rf "/etc"` · `rm -rf '/etc'` · `cat "/home/u/.env"` · `git push "--force"` · `/bin/rm -rf /` · `/usr/bin/sudo rm -rf /` · `/sbin/mkfs.ext4 /dev/sda1` · `cat /home/u/.kube/./config` · `cp evil /home/u/.claude/settings.json` · `rm /home/u/.claude/settings.json` · `install -m755 evil /home/u/.local/bin/guardrail` · `sed -i s/a/b/ /repo/.git/hooks/pre-commit` · `ln -sf evil /repo/.git/hooks/pre-commit` · `dd if=evil of=/repo/.git/hooks/pre-commit`; plus `Write /repo/guardrail.toml`, `Write /repo/.guardrail/guardrail.js`, `Write /repo/.git/./config`.
And `"want": "allow"` for the false-positive locks: `Read /repo/CLAUDE.md`, `Read /repo/AGENTS.md`, `Read /home/u/.claude/skills/x/SKILL.md`, `Read /repo/.git/config`.

- [ ] **Step 2: Write the test**

```go
package adversarial

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

type entry struct {
	Name     string   `json:"name"`
	Tool     string   `json:"tool"`
	Command  string   `json:"command,omitempty"`
	Paths    []string `json:"paths,omitempty"`
	CWD      string   `json:"cwd"`
	RepoRoot string   `json:"repo_root"`
	Want     string   `json:"want"`
}

func TestAdversarialCorpus(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "guardrail")
	if out, err := exec.Command("go", "build", "-o", bin, "../../cmd/guardrail").CombinedOutput(); err != nil {
		if out2, err2 := exec.Command("/usr/local/go/bin/go", "build", "-o", bin, "../../cmd/guardrail").CombinedOutput(); err2 != nil {
			t.Fatalf("build: %v %s / %v %s", err, out, err2, out2)
		}
	}
	raw, err := os.ReadFile("corpus.json")
	if err != nil {
		t.Fatal(err)
	}
	var entries []entry
	if err := json.Unmarshal(raw, &entries); err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		t.Run(e.Name, func(t *testing.T) {
			in := map[string]any{
				"session_id": "adv", "cwd": e.CWD,
				"hook_event_name": "PreToolUse", "tool_name": e.Tool,
			}
			ti := map[string]any{}
			if e.Command != "" {
				ti["command"] = e.Command
			}
			if len(e.Paths) > 0 {
				ti["file_path"] = e.Paths[0]
			}
			in["tool_input"] = ti
			payload, _ := json.Marshal(in)

			cmd := exec.Command(bin, "hook", "claude")
			cmd.Stdin = bytes.NewReader(payload)
			cmd.Env = append(os.Environ(), "XDG_STATE_HOME="+t.TempDir(), "GUARDRAIL_CONFIG=")
			var out bytes.Buffer
			cmd.Stdout = &out
			_ = cmd.Run()
			code := cmd.ProcessState.ExitCode()

			got := "allow"
			switch {
			case code == 2:
				got = "deny"
			case strings.Contains(out.String(), `"permissionDecision":"ask"`):
				got = "ask"
			}
			if got != e.Want {
				t.Fatalf("%s: got %s, want %s (exit=%d stdout=%s)", e.Name, got, e.Want, code, out.String())
			}
		})
	}
}
```

- [ ] **Step 3: Run — it must pass only because the fixes landed**

Run: `/usr/local/go/bin/go test ./test/adversarial/ -v`
Expected: PASS. If any entry fails, the corresponding fix is incomplete — fix the code, never the corpus.

- [ ] **Step 4: Wire into CI and the Makefile**

Add to `Makefile`:
```make
adversarial:
	$(GO) test ./test/adversarial/ -v
```
(add `adversarial` to `.PHONY` and to `check`'s prerequisites). `.github/workflows/ci.yml` already runs `go test ./...`, which now includes it.

- [ ] **Step 5: Commit**

```bash
git add test/adversarial/ Makefile
git commit -m "test: adversarial regression corpus — every Phase 1 bypass locked against reopening"
```

---

### Task 12: docs, review status, tag

**Files:** `README.md`, `docs/reviews/2026-09-04-adversarial-review.md`, `docs/HANDOFF-2026-09-03.md`

- [ ] **Step 1: Full green**

Run: `make check && /usr/local/go/bin/go test ./...` → all pass, vet clean, gofmt clean.

- [ ] **Step 2: Annotate the review**

In the review document, mark each finding addressed here with `**[FIXED — Phase 1]**` inline (CR-1, CR-2, CR-7, CR-8, CR-12, CR-14, CR-15, CR-16, M-1, M-9), so what remains open is unambiguous at a glance.

- [ ] **Step 3: README + HANDOFF**

README Status: note the adversarial review and that Phase 1 remediation has landed, with Phases 2–4 outstanding (link the review). HANDOFF: add the remediation phases to the plan table.

- [ ] **Step 4: Push and tag**

```bash
git add -A && git commit -m "docs: Phase 1 remediation landed; review annotated with fixed findings"
git push origin main
git tag v0.9.0-dev && git push origin v0.9.0-dev
```

> **Do not bump the chezmoi installer pin yet.** Phases 2–3 contain further criticals; a single deliberate bump after Phase 3 is better than three partial ones. The macOS fix (Task 10) is on a chezmoi branch awaiting Carlitos.

---

## Roadmap — what Phase 1 deliberately leaves open

| Phase | Contents | Why not now |
|---|---|---|
| **2 — token normalization, part 2** | CR-3 (`cd` tracking), CR-4 (redirect-only statements), CR-5/CR-6 (git `valueFlags` + refspec), CR-10/CR-11 (egress host extraction fails closed; pipeline-wide fetch→interpreter), CR-13 (docker arg parsing), H-1 (per-statement normalize so a junk wrapper can't downgrade a deny), H-3/H-4 (wrapper list, uncovered primitives) | Each needs real parsing work rather than a table or a one-liner. None is a self-protection failure. |
| **3 — the overlay trust model** ⚠️ | CR-3-addendum (unbounded `waive`), H-5 (slot widening is global), H-8 (`audit_log` silencing + arbitrary append), H-11 (no size cap), H-9/M-8 (sanitize `Reason` and waiver ids before any model-facing writer) | **Needs a design decision from Carlitos first.** ADR-0003 promised "tighten only; waivers are logged" and the implementation delivers neither. The fix is a *policy* question: should a repo be able to waive at all, and if so should it require an operator-scoped allowlist in `~/.config/guardrail/`? Write an ADR-0010 before code. |
| **4 — invert the allowlists** | RC4 in full: `pathReaders` → scan every argument of every command; `writeCandidates` → complete mutating-command coverage; H-10 (unknown tool names default-deny on `pre`); H-6 (WebFetch/WebSearch gated by the egress allowlist and arming the trifecta net leg); H-2 (`secret_allow` basename fallback), H-5/H-7 (case-insensitive matching), M-2..M-7 false positives | The structural work, and the highest ceiling. Best done once Phases 1–3 have stabilised the semantics it would otherwise churn. |

**Sequencing note:** Phase 3 is the one that most changes the *product*, and it is blocked on a decision, not on effort. Consider making that decision before Phase 2 so Phase 3 can follow immediately.

---

## Self-Review

**1. Finding coverage.** Every Phase 1 finding maps to a task: RC1/CR-2 → 1–2; RC3/CR-7 → 3; M-1 → 4; CR-14 → 5; CR-15/CR-8 → 6; RC2/CR-1 → 7; CR-12 → 8; CR-16 → 9; M-9 → 10; all of them locked by 11. Everything else is explicitly routed to a Roadmap phase — nothing from the review is silently dropped.

**2. Placeholder scan.** No `TBD`/"handle appropriately". Task 1 Step 4 explicitly anticipates that existing tests will fail *because the fix is correct* and instructs updating the expectation rather than weakening the fix — that is a real instruction, not a hedge. Task 6's note about `~/.local/bin/guardrail` needing to be in `selfConfigGlobs` for the `install` case to be caught is a genuine cross-task dependency, called out where it bites.

**3. Type consistency.** `Simple` gains one field (`Unresolved bool`) — every existing construction site uses field-free literals or named fields, so this is additive. `head(argv []string) string` and `isWriteToolCall(tool string) bool` and `writeTargets(s Simple) []string` and `safeSessionID(id string) bool` are all new, unexported, single-package. `genconfig.OpencodePluginFor(binary string) []byte` is new and exported; `OpencodePluginJS` stays for compatibility. No existing exported signature changes — `Evaluate`, `checkBash`, `checkPaths`, `MergeInto`, all three `Parse*`/`Emit*` pairs, and every `cmd*` entry point keep their shapes.

**4. Risk.** Tasks 1, 6, and 7 broaden what gets denied. That is the point, but it is also where a false positive would land. Task 11's corpus includes explicit `"want": "allow"` entries for the legitimate reads precisely so a Phase 1 over-correction shows up as a test failure rather than as friction discovered in daily use.

---

## Execution Handoff

**Plan complete and saved to `docs/superpowers/plans/2026-09-04-remediation-phase1.md`. Two execution options:**

**1. Subagent-Driven (recommended)** — fresh subagent per task via `superpowers:subagent-driven-development`, review between tasks.

**2. Inline Execution** — `superpowers:executing-plans`, batch with checkpoints.

**Which approach?**
