# Adversarial Remediation — Phase 4: Path Matching Correctness

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

> **Revision 3 (2026-09-06).** Revisions 1 and 2 were each reviewed before execution, and each had five load-bearing premises disproved. Nothing has been committed against either. Every correction is recorded in the revision history at the foot of this document; the fixes below are the corrected ones. Phase 4 covers **path matching only**; plane coverage and session integrity are in `2026-09-06-remediation-phase5.md`.

**Goal:** Make the path matcher say what it means. Today one glob list is asked to express three different intents — "anywhere", "at the repo root", "unless allowed" — and a single basename fallback stands in for all three. That produces false positives and a bypass at the same time.

**Architecture:** Four separate corrections, not one. (1) Repo-root-only globs get matched against the repo-relative form of both the lexical and the resolved path, and nothing else. (2) Secret **directories** become unwaivable by filename-pattern allows, which is what H-2 actually needs. (3) Genuinely ambiguous patterns (`*.pem`, `service-account*.json`) move to an `ask` tier instead of denying, which is what M-3 actually needs. (4) Argument scanning gains flag-attached values and opaque-executor source, with the reader-command list demoted from gate to hint so bare filenames keep working.

**Tech Stack:** Go 1.23+, existing deps only.

**Spec:** `../reviews/2026-09-04-adversarial-review.md`. Findings addressed: **CR-9/RC4, H-2, H-7, M-2, M-3, M-4, M-5, M-6**, plus **NF-1** (new, found live 2026-09-06 — see Task 3). Deferred to Phase 5: **H-6, H-10, M-7**.

**Policy schema change:** Task 2 adds `secret_dirs` and Task 3 adds `secret_ask_globs` to `[slots]`. Both are additive and tightening-only, so no Operator grant is needed to set them, and an Overlay written against the old schema keeps working. Update `guardrail.toml.example` and `CONTEXT.md` in Task 7.

## Global Constraints

- **Verify glob behaviour empirically, never by reading.** Revision 1 asserted that prefixing `*.key` → `**/*.key` would stop it matching `i18n/translations.key`. It does not: `doublestar.Match("**/*.key", "i18n/translations.key")` is `true`, because `**/` matches zero or more leading segments. The same error hid H-2. Before you rely on a glob narrowing anything, write a two-line test and run it.
- **This phase changes matching in both directions.** Every task adds `want: "allow"` corpus entries as well as `want: "deny"` ones. A fix that closes a bypass while making `conftest.py` prompt on every test file has not improved safety — M-2/M-4/M-6 are in scope precisely because false positives are why guardrails get switched off.
- **Zero corpus entries may be relaxed.** If an existing test starts failing, decide whether the *new* behaviour is correct per the review before touching the expectation. Never edit an expectation to make a suite green.
- **If a premise here is wrong, stop and say so** rather than working around it. That is how Revisions 1 and 2 were caught, both times before a line of code was written.
- **Never let a fix weaken something that works today.** Revision 2's Task 6 would have turned `cat id_rsa` from `~/.ssh` (exit 2 on the deployed binary) into exit 0. Before changing a gate, probe the deployed binary for what it already catches and add that as a regression test first.
- Every code step is literal. `gofmt -w` before every commit. Conventional Commits, one commit per task.

**Verified current state** (read from the tree, and where noted executed, immediately before this revision):

- `matchesAnyGlob` cleans the path, then tries `doublestar.Match(g, p)` **and** `doublestar.Match(g, base)` — the basename fallback.
- `base.toml` `secret_globs` mixes directory globs (`**/.ssh/**`, `**/.aws/**`) with bare filename globs (`id_rsa*`, `*.pem`, `*.key`, `service-account*.json`); `secret_allow` is `**/.env.example`, `.env.example`, `**/.env.sample`, `.env.sample`.
- `classifiedSecretPath` returns early on **any** `secret_allow` match, before consulting `secret_globs`.
- `checkSelfConfig` (`rules_path.go:483`), `checkCIInfraLockfile` (`:637`) and `checkGitProtectedPaths` (`:450`) each match the **raw** path and the **resolved** path against their list. There is no repo-relative form anywhere.
- `nonFlagArgs` (`rules_bash.go:259`) drops every argument beginning with `-`, so the value in `-f/home/u/.ssh/id_rsa` and `--file=/home/u/.ssh/id_rsa` is discarded.
- `visiblePathCandidates(arg string) []string` (`rules_path.go`) already extracts quoted literals and path-shaped tokens from an arbitrary string. `isOpaqueExecutor` already recognizes python/node/perl/ruby/php/lua/awk/powershell. Both are reused below.

---

### Task 1: Separate "anywhere" globs from "repo-root-only" globs

**Files:** `internal/engine/rules_path.go`, `internal/engine/rules_git.go`, tests

**The actual defect.** The lists mix two intents. `**/.bashrc` means *anywhere*; `CLAUDE.md`, `Makefile`, `conftest.py`, `Dockerfile` and the lockfiles mean *at the repository root*. The basename fallback is currently the only thing that makes the second kind match an absolute `/repo/CLAUDE.md` — and the same fallback wrongly matches `/repo/docs/templates/CLAUDE.md`.

**Revision 1 got this wrong** by adding a repo-relative form *alongside* the existing raw match. That leaves the false positive intact: an agent whose cwd is `/repo/docs/templates` writing the relative path `CLAUDE.md` still matches the bare glob `CLAUDE.md` directly, with no basename fallback involved. The raw form must stop being tested against root-only globs altogether.

**Interfaces:**
- `matchesAnyGlob(p string, globs []string) bool` — basename fallback removed, full cleaned path only.
- New `func repoRelative(p, cwd, repoRoot string) (string, bool)`: resolves `p` against `cwd` when relative, then uses `filepath.Rel` — **not** prefix arithmetic, which breaks for `repoRoot == "/"` because `root+"/"` becomes `"//"` — and rejects any result that escapes the repo with `..`.
- Each of the three lists splits in two: `selfConfigAnywhere` / `selfConfigRootOnly`, `ciInfraAnywhere` / `ciInfraRootOnly`, and `gitProtectedGlobs` (already all-`**/`, stays as one).
- New `func matchesScoped(c pathCandidate, anywhere, rootOnly []string) bool`: tests raw and resolved forms against `anywhere`; tests the repo-relative form of **both the lexical and the resolved path** against `rootOnly`.
- `pathCandidate` gains `repoRoot string`, set wherever candidates are built (`writeCandidates`, `privatePathCandidates`).

- [ ] **Step 1: Write the failing test**

```go
func TestRootOnlyGlobsMatchOnlyAtRepoRoot(t *testing.T) {
	// The relative form is the one Revision 1 missed: cwd is the subdirectory.
	deep := []struct{ path, cwd string }{
		{"CLAUDE.md", "/repo/docs/templates"},
		{"/repo/docs/templates/CLAUDE.md", "/repo"},
		{"Makefile", "/repo/vendor/x"},
		{"/repo/vendor/x/Makefile", "/repo"},
		{"conftest.py", "/repo/tests/unit"},
		{"/repo/tests/unit/conftest.py", "/repo"},
	}
	for _, d := range deep {
		tc := ToolCall{Tool: "Write", Paths: []string{d.path}, CWD: d.cwd, RepoRoot: "/repo"}
		if v := checkSelfConfig(tc); v != nil {
			t.Errorf("selfConfig %q (cwd %s) -> %+v, want nil", d.path, d.cwd, v)
		}
		if v := checkCIInfraLockfile(tc); v != nil {
			t.Errorf("ciInfra %q (cwd %s) -> %+v, want nil", d.path, d.cwd, v)
		}
	}
	// ...and still caught at the root, by either form.
	for _, r := range []struct{ path, cwd string }{
		{"CLAUDE.md", "/repo"}, {"/repo/CLAUDE.md", "/repo"}, {"./CLAUDE.md", "/repo"},
	} {
		tc := ToolCall{Tool: "Write", Paths: []string{r.path}, CWD: r.cwd, RepoRoot: "/repo"}
		if v := checkSelfConfig(tc); v == nil || v.Decision != policy.Deny {
			t.Errorf("selfConfig %q (cwd %s) -> %+v, want deny", r.path, r.cwd, v)
		}
	}
	// "anywhere" globs are unaffected by repo scoping.
	tc := ToolCall{Tool: "Write", Paths: []string{"/home/u/.bashrc"}, CWD: "/repo", RepoRoot: "/repo"}
	if v := checkSelfConfig(tc); v == nil || v.Decision != policy.Deny {
		t.Errorf("~/.bashrc -> %+v, want deny", v)
	}
}

func TestRepoRelativeHandlesRootAndEscapes(t *testing.T) {
	for _, c := range []struct {
		p, cwd, root, want string
		ok                 bool
	}{
		{"/CLAUDE.md", "/", "/", "CLAUDE.md", true}, // repoRoot "/" — the "//" bug
		{"/repo/docs/CLAUDE.md", "/repo", "/repo", "docs/CLAUDE.md", true},
		{"CLAUDE.md", "/repo/docs", "/repo", "docs/CLAUDE.md", true},
		{"/etc/passwd", "/repo", "/repo", "", false}, // must not become "../etc/passwd"
		{"/repo", "/repo", "/repo", "", false},       // the root itself
	} {
		got, ok := repoRelative(c.p, c.cwd, c.root)
		if ok != c.ok || got != c.want {
			t.Errorf("repoRelative(%q,%q,%q) = (%q,%v), want (%q,%v)",
				c.p, c.cwd, c.root, got, ok, c.want, c.ok)
		}
	}
}

func TestRootOnlyGlobsFollowSymlinks(t *testing.T) {
	// A symlink named notes.md pointing at CLAUDE.md must still be caught: its
	// lexical repo-relative form is "notes.md", so only the resolved form sees it.
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "CLAUDE.md"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(root, "CLAUDE.md"), filepath.Join(root, "notes.md")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	tc := ToolCall{Tool: "Write", Paths: []string{filepath.Join(root, "notes.md")},
		CWD: root, RepoRoot: root}
	if v := checkSelfConfig(tc); v == nil || v.Decision != policy.Deny {
		t.Errorf("symlink to CLAUDE.md -> %+v, want deny", v)
	}
}
```

- [ ] **Step 2: Run to verify it fails** — expect the six `deep` cases to DENY.

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

// repoRelative expresses p relative to repoRoot, resolving against cwd first
// when p is relative. Root-only globs ("CLAUDE.md", "Makefile") are matched
// against this form and no other: matching them against the raw path denies
// them at any depth, which is the M-2/M-4/M-5 false positive.
func repoRelative(p, cwd, repoRoot string) (string, bool) {
	if repoRoot == "" {
		return "", false
	}
	q := p
	if !filepath.IsAbs(q) {
		if cwd == "" {
			return "", false
		}
		q = filepath.Join(cwd, q)
	}
	// filepath.Rel, not prefix arithmetic: for repoRoot "/" the string root+"/"
	// is "//", so every absolute path is wrongly classified as outside the repo.
	rel, err := filepath.Rel(filepath.Clean(repoRoot), filepath.Clean(q))
	if err != nil {
		return "", false
	}
	rel = filepath.ToSlash(rel)
	// Rel returns "../etc/passwd" for a path outside the repo; that is not a
	// repo-relative form and must not be matched against root-only globs.
	if rel == "." || rel == ".." || strings.HasPrefix(rel, "../") {
		return "", false
	}
	return rel, true
}

func matchesScoped(c pathCandidate, anywhere, rootOnly []string) bool {
	raw := strings.TrimPrefix(c.path, "./")
	if matchesAnyGlob(raw, anywhere) {
		return true
	}
	resolved, haveResolved := resolvePathCandidate(c)
	if haveResolved && matchesAnyGlob(resolved, anywhere) {
		return true
	}
	// Root-only globs are tested against the repo-relative form of BOTH the
	// lexical path and its resolved form. Testing only the lexical form lets a
	// symlink whose target is /repo/CLAUDE.md through: its own name is not
	// CLAUDE.md, and the basename fallback that used to catch it is gone.
	if rel, ok := repoRelative(c.path, c.cwd, c.repoRoot); ok && matchesAnyGlob(rel, rootOnly) {
		return true
	}
	if haveResolved {
		if rel, ok := repoRelative(resolved, c.cwd, c.repoRoot); ok && matchesAnyGlob(rel, rootOnly) {
			return true
		}
	}
	return false
}
```

Then split the two mixed lists. `selfConfigRootOnly` takes `CLAUDE.md`, `AGENTS.md`, `.mcp.json`, `.envrc`, `guardrail.toml`, `opencode.json`; everything already `**/`-prefixed stays in `selfConfigAnywhere` (drop the now-redundant unprefixed duplicates of `guardrail.toml` and `opencode.json`). `ciInfraRootOnly` takes `.gitlab-ci.yml`, `Jenkinsfile`, `.pre-commit-config.yaml`, `azure-pipelines.yml`, `Dockerfile`, `docker-compose*.yml`, `*.tf`, `Makefile`, `justfile`, `Taskfile.yml`, `setup.py`, `conftest.py`, `noxfile.py` and every lockfile; `**/.github/workflows/**`, `**/.circleci/**`, `**/.buildkite/**` stay in `ciInfraAnywhere`. Replace the three `protected := … || …` blocks with `matchesScoped`.

- [ ] **Step 4: Run the full suite.** Any newly-failing case is a signal — confirm against the review before editing an expectation.

- [ ] **Step 5: Commit**

```bash
gofmt -w internal/engine/ && git add internal/engine/
git commit -m "fix(engine): scope root-only globs to the repo-relative form (M-2, M-4, M-5)"
```

---

### Task 2: Secret directories outrank filename allows

**Files:** `internal/policy/policy.go`, `internal/policy/base.toml`, `internal/engine/rules_path.go`, tests

**The actual defect (H-2).** `classifiedSecretPath` consults `secret_allow` first and returns on any match. `secret_allow` contains `**/.env.example`, and — verified by running it — `doublestar.Match("**/.env.example", "home/u/.ssh/.env.example")` is **true**. So a file merely *named* `.env.example` placed inside `~/.ssh/` suppresses the `**/.ssh/**` deny. Revision 1 claimed removing the basename fallback fixed this; it does not, because the allow glob matches the full path directly.

**The fix is precedence, not glob syntax.** A secret **directory** is unwaivable by a filename pattern: nothing inside `~/.ssh/` is public because of what it is called.

**Interfaces:**
- `policy.Slots` gains `SecretDirs []string` (TOML key `secret_dirs`), moved out of `secret_globs`: `**/.ssh/**`, `/root/.ssh/**`, `**/.aws/**`, `**/.config/gcloud/**`, `**/.gnupg/**`, `**/.docker/config.json`.
- `classifiedSecretPath` checks `SecretDirs` **first and unconditionally**; only if no directory matches does it apply the existing `SecretAllow`-then-`SecretGlobs` logic.
- Overlay merge treats `secret_dirs` like `secret_globs` — additive, tightening-only, no operator grant needed to add.

- [ ] **Step 1: Write the failing test**

```go
func TestSecretDirsAreUnwaivableByFilenameAllow(t *testing.T) {
	pol := pathPol()
	for _, p := range []string{
		"/home/u/.ssh/.env.example",
		"/home/u/.ssh/.env.sample",
		"/home/u/.aws/.env.example",
		"/home/u/.ssh/id_rsa.pub", // Task 3's *.pub allow must not reach into .ssh either
	} {
		tc := ToolCall{Tool: "Read", Paths: []string{p}, CWD: "/repo", RepoRoot: "/repo"}
		if v := checkPaths(tc, pol); v == nil || v.Decision != policy.Deny {
			t.Errorf("%q -> %+v, want deny — a filename must not waive a secret directory", p, v)
		}
	}
	// Outside a secret directory the allow still works.
	tc := ToolCall{Tool: "Read", Paths: []string{"/repo/.env.example"}, CWD: "/repo", RepoRoot: "/repo"}
	if v := checkPaths(tc, pol); v != nil && v.Decision == policy.Deny {
		t.Errorf("/repo/.env.example -> %+v, want not-deny", v)
	}
}
```

- [ ] **Step 2: Run to verify it fails** — expect all four to ALLOW.

- [ ] **Step 3: Implement**

```go
func classifiedSecretPath(candidate pathCandidate, pol *policy.Policy) (string, bool) {
	for _, form := range pathCandidateForms(candidate) {
		// A secret directory is unwaivable: nothing inside ~/.ssh is public
		// because of what it is named (review H-2).
		if matchesAnyGlob(form, pol.Slots.SecretDirs) {
			return form, true
		}
	}
	for _, form := range pathCandidateForms(candidate) {
		if matchesAnyGlob(form, pol.Slots.SecretAllow) {
			continue
		}
		if matchesAnyGlob(form, pol.Slots.SecretGlobs) {
			return form, true
		}
	}
	return "", false
}
```

- [ ] **Step 4: Run + commit**

```bash
gofmt -w internal/ && git add internal/
git commit -m "fix(policy): secret directories outrank filename allows (H-2)"
```

---

### Task 3: Narrow the over-broad globs; allow public keys and dry runs

**Files:** `internal/policy/base.toml`, `internal/engine/rules_bash.go:307`, tests

**The actual defect (M-2).** `*.key` is not a secret pattern — `.key` is used for translation catalogues, licence keys and Django `SECRET_KEY` *templates*. Prefixing it to `**/*.key` changes nothing (verified: it still matches `i18n/translations.key`). The glob itself must go, replaced by name-scoped forms. With Task 2 in place this is safe: real key material under `~/.ssh`, `~/.aws`, `~/.gnupg` is caught by `secret_dirs` regardless of extension.

**The actual defect (M-3) — and why Revision 2 did not fix it.** Revision 2 added `**/*.pub` and declared M-3 closed while keeping the two patterns that *cause* M-3. Verified by running them:

```
**/*.pem                 vs repo/docs/cert.pem                      -> true
**/service-account*.json vs repo/testdata/service-account-fake.json -> true
```

Those are M-3's own examples. But deleting the patterns is wrong too — a real `deploy.pem` committed to a repo is exactly what P4 exists to catch. The honest reading is that **these patterns are ambiguous**: the same glob matches real key material and ordinary fixtures, and nothing in the path separates them. The engine has three verdicts and this is what the middle one is for. Ambiguous evidence yields `ask`; definitive evidence yields `deny`.

**Interfaces (M-3):**
- `policy.Slots` gains `SecretAskGlobs []string` (TOML key `secret_ask_globs`), holding the patterns moved out of `secret_globs`: `**/*.pem`, `**/*.p12`, `**/*.pfx`, `**/*.keystore`, `**/service-account*.json`.
- `classifiedSecretPath` returns a tier rather than a bool: `func classifiedSecretPath(c pathCandidate, pol *policy.Policy) (string, policy.Decision, bool)` — `secret_dirs` → `Deny` (unwaivable, Task 2), `secret_globs` → `Deny` (waivable by `secret_allow`), `secret_ask_globs` → `Ask` (waivable by `secret_allow`). Its caller in `checkPaths` uses the returned decision, with rule ID `P4.secret-path` for deny and `P4.secret-path-ambiguous` for ask.
- Overlay merge treats `secret_ask_globs` like `secret_globs` — additive, tightening-only.

A repo cert therefore prompts once instead of hard-blocking, and `~/.ssh/server.pem` still denies via `secret_dirs`.

**Also fixes NF-1 (new, found live 2026-09-06).** `selfConfigAnywhere` contains `**/.claude/**`, which denies writes to the *entire* `~/.claude/` tree — including `~/.claude/projects/*/memory/**`, which is agent memory, not agent configuration. Verified against the deployed `v0.12.0-dev` binary: a `Write` to `~/.claude/projects/x/memory/note.md` exits 2, the same as a `Write` to `~/.claude/settings.json`. Phase 1 fixed the read case (that `Read` now exits 0); the write case was never in scope. Replace `**/.claude/**` with the actual config surfaces: `**/.claude/settings.json`, `**/.claude/settings.local.json`, `**/.claude/hooks/**`, `**/.claude/plugins/**`, `**/.claude/agents/**`, `**/.claude/commands/**`, `**/.claude/skills/**`, `**/.claude/CLAUDE.md`. This is the same over-broad-glob defect as `*.key`, on a different list.

**Interfaces:**
- `selfConfigAnywhere`: replace `**/.claude/**` with the eight scoped globs above (NF-1).
- `base.toml` `secret_globs`: drop bare `*.key`; **move `*.pem` and `service-account*.json` into `secret_ask_globs`**; add `**/*_rsa`, `**/*_ed25519`, `**/*_ecdsa`, `**/*.private.key`, `**/*-private-key.*`, `**/private*.key`. Prefix the remaining bare entries (`id_rsa*` → `**/id_rsa*`, `id_ed25519*` → `**/id_ed25519*`) — cosmetic given `**/` matches zero segments, but it removes the impression that bare entries mean "root only" now that Task 1 has given that phrase a meaning.
- `secret_allow` gains `**/*.pub` — a public key is public by definition, and Task 2 stops it reaching into `secret_dirs`.
- The `case "clean":` arm returns `nil` when `-n`/`--dry-run` is present, before the existing `hasAnyFlag(s.Argv, "fxd", "--force")` check.

- [ ] **Step 1: Write the failing test**

```go
func TestOverBroadGlobsNarrowed(t *testing.T) {
	pol := pathPol()
	allow := []string{
		"/repo/i18n/translations.key", "/repo/src/locale/en.key",
		"/repo/testdata/id_rsa.pub", "/repo/keys/server.pub",
	}
	for _, p := range allow {
		tc := ToolCall{Tool: "Read", Paths: []string{p}, CWD: "/repo", RepoRoot: "/repo"}
		if v := checkPaths(tc, pol); v != nil && v.Decision == policy.Deny {
			t.Errorf("%q -> %+v, want not-deny", p, v)
		}
	}
	deny := []string{
		"/repo/certs/private.key", "/repo/certs/server.private.key",
		"/repo/deploy_rsa", "/home/u/.ssh/id_rsa", "/home/u/.ssh/server.pem",
	}
	for _, p := range deny {
		tc := ToolCall{Tool: "Read", Paths: []string{p}, CWD: "/repo", RepoRoot: "/repo"}
		if v := checkPaths(tc, pol); v == nil || v.Decision != policy.Deny {
			t.Errorf("%q -> %+v, want deny", p, v)
		}
	}
	// M-3: ambiguous in-repo material asks rather than blocking. These are the
	// review's own examples; Revision 2 kept them denying while claiming M-3 fixed.
	for _, p := range []string{
		"/repo/docs/cert.pem", "/repo/testdata/service-account-fake.json",
		"/repo/testdata/tls/localhost.pem",
	} {
		tc := ToolCall{Tool: "Read", Paths: []string{p}, CWD: "/repo", RepoRoot: "/repo"}
		v := checkPaths(tc, pol)
		if v == nil || v.Decision != policy.Ask {
			t.Errorf("%q -> %+v, want ask (ambiguous, not definitive)", p, v)
		}
	}
	// NF-1: agent memory is not agent configuration.
	mem := ToolCall{Tool: "Write", Paths: []string{"/home/u/.claude/projects/x/memory/note.md"},
		CWD: "/repo", RepoRoot: "/repo"}
	if v := checkSelfConfig(mem); v != nil {
		t.Errorf("write to agent memory -> %+v, want nil", v)
	}
	for _, p := range []string{"/home/u/.claude/settings.json", "/home/u/.claude/hooks/pre.sh"} {
		cfg := ToolCall{Tool: "Write", Paths: []string{p}, CWD: "/repo", RepoRoot: "/repo"}
		if v := checkSelfConfig(cfg); v == nil || v.Decision != policy.Deny {
			t.Errorf("write to %q -> %+v, want deny", p, v)
		}
	}
	for _, c := range []string{`git clean -n`, `git clean -nxd`, `git clean --dry-run -d`} {
		if v := evalBash(t, c); v != nil && v.Decision == policy.Deny {
			t.Errorf("%q -> %+v, want not-deny (dry run removes nothing)", c, v)
		}
	}
	if v := evalBash(t, `git clean -fdx`); v == nil || v.Decision != policy.Deny {
		t.Errorf("git clean -fdx -> %+v, want deny", v)
	}
}
```

- [ ] **Step 2: Run to verify it fails.**

- [ ] **Step 3: Implement** the `base.toml` edits above, then:

```go
	case "clean":
		if hasAnyFlag(s.Argv, "n", "--dry-run") {
			return nil // a dry run lists what would be removed; nothing is deleted
		}
```

- [ ] **Step 4: Run + commit**

```bash
gofmt -w internal/ && git add internal/
git commit -m "fix(policy): narrow *.key and **/.claude/**, allow *.pub, permit git clean dry runs (M-2, M-3, M-6, NF-1)"
```

---

### Task 4: H-7 — case-insensitive glob matching

**Files:** `internal/engine/rules_path.go`, tests

**Interfaces:** `matchesAnyGlob` lowercases pattern and path before matching. On APFS and NTFS `~/.SSH/ID_RSA` opens the real key.

- [ ] **Step 1: Write the failing test**

```go
func TestGlobMatchingIsCaseInsensitive(t *testing.T) {
	pol := pathPol()
	for _, p := range []string{"/home/u/.SSH/ID_RSA", "/home/u/.Ssh/id_rsa", "/repo/.ENV"} {
		tc := ToolCall{Tool: "Read", Paths: []string{p}, CWD: "/repo", RepoRoot: "/repo"}
		if v := checkPaths(tc, pol); v == nil || v.Decision != policy.Deny {
			t.Errorf("Read %q -> %+v, want deny", p, v)
		}
	}
}
```

- [ ] **Step 2: Run to verify it fails.**

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
git commit -m "fix(engine): case-insensitive glob matching (H-7)"
```

---

### Task 5: CR-9 — recover flag-attached paths

**Files:** `internal/engine/rules_bash.go`, tests

**The actual defect.** `nonFlagArgs` drops every token starting with `-`. The review's own reproduction, `grep -f/home/u/.ssh/id_rsa`, is therefore invisible — and so are `--file=/home/u/.ssh/id_rsa`, `openssl rsa -in/path`, `tar --file=/path`. Revision 1 kept using `nonFlagArgs` and so did not close CR-9 at all.

**Interfaces:** New `func argPathValues(argv []string) []string` returns, for each argument after the executable: the argument itself when it is not a flag; the text after `=` for `--flag=value`; and the tail for a short flag with an attached value that looks like a path (`-f/abs/path`). `privatePathCandidates` uses this instead of `nonFlagArgs`. `nonFlagArgs` keeps its other callers.

- [ ] **Step 1: Write the failing test**

```go
func TestFlagAttachedPathsAreRecovered(t *testing.T) {
	for _, c := range []struct{ argv []string; want string }{
		{[]string{"grep", "-f/home/u/.ssh/id_rsa", "x"}, "/home/u/.ssh/id_rsa"},
		{[]string{"grep", "--file=/home/u/.ssh/id_rsa"}, "/home/u/.ssh/id_rsa"},
		{[]string{"openssl", "rsa", "-in/home/u/.ssh/id_rsa"}, "/home/u/.ssh/id_rsa"},
		{[]string{"cat", "/home/u/.ssh/id_rsa"}, "/home/u/.ssh/id_rsa"},
	} {
		got := argPathValues(c.argv)
		if !slices.Contains(got, c.want) {
			t.Errorf("argPathValues(%v) = %v, want it to contain %q", c.argv, got, c.want)
		}
	}
	// A bare flag contributes nothing.
	if got := argPathValues([]string{"ls", "-la", "--color=auto"}); slices.Contains(got, "auto") {
		t.Errorf("argPathValues picked up a non-path flag value: %v", got)
	}
}
```

- [ ] **Step 2: Run to verify it fails** (`argPathValues` undefined).

- [ ] **Step 3: Implement**

```go
// argPathValues yields the arguments that may name a path, including values
// attached to a flag. nonFlagArgs drops anything starting with "-", which hid
// `grep -f/home/u/.ssh/id_rsa` and `--file=/home/u/.ssh/id_rsa` (review CR-9).
func argPathValues(argv []string) []string {
	var out []string
	for _, a := range argv[1:] {
		if !strings.HasPrefix(a, "-") {
			out = append(out, a)
			continue
		}
		if i := strings.Index(a, "="); i > 0 {
			if v := a[i+1:]; looksLikePath(v) {
				out = append(out, v)
			}
			continue
		}
		// short flag with an attached value: -f/path, -in/path
		trimmed := strings.TrimLeft(a, "-")
		if j := strings.IndexAny(trimmed, "/~"); j > 0 {
			if v := trimmed[j:]; looksLikePath(v) {
				out = append(out, v)
			}
		}
	}
	return out
}

// looksLikePath keeps ordinary arguments — grep patterns, printf formats, jq
// filters — out of the path matcher. A path candidate has a separator or a
// home prefix; "*.pem" as a grep pattern does not.
func looksLikePath(v string) bool {
	return v != "" && (strings.ContainsAny(v, `/\`) || strings.HasPrefix(v, "~"))
}
```

- [ ] **Step 4: Run + commit**

```bash
gofmt -w internal/engine/ && git add internal/engine/
git commit -m "feat(engine): recover flag-attached path values for secret scanning (CR-9)"
```

---

### Task 6: CR-9 — scan path-shaped arguments and opaque-executor source

**Files:** `internal/engine/rules_path.go`, tests

**The actual defect.** `privatePathCandidates` consults a closed 14-command `pathReaders` map, so `cp`, `base64`, `tar`, `openssl`, `md5sum`, `dd` and everything unlisted read secrets freely. Revision 1 proposed scanning *every* argument — which introduces the false positives SOL identified (`grep '*.pem' log.txt`, `printf`, `jq` filters) and still misses `python3 -c "open('/home/u/.ssh/id_rsa')"`, because the whole script string never equals a path.

**`pathReaders` must NOT be deleted.** Revision 2 said to delete it and gate everything on `looksLikePath`. Probed against the deployed binary, that is a **regression**:

```
cat id_rsa       (cwd ~/.ssh)  exit=2   ← denies today
cp  id_rsa /tmp  (cwd ~/.ssh)  exit=0   ← the CR-9 gap
```

`looksLikePath("id_rsa")` is false — no separator — so deleting the reader list drops the candidate and turns the first line into exit 0. The list is demoted from **gate** to **hint** instead: for a known reader every operand is a path candidate, bare filename included (the known `cwd` resolves it); for any other command an operand must look like a path. That preserves today's behaviour exactly and adds the new coverage on top.

**Interfaces:**
- `pathReaders` is **kept, extended and renamed** `pathOperandCommands` to reflect its new role. Add `wc`, `diff`, `cmp`, `file`, `nl`, `tac`, `rev`, `cut`, `sort`, `uniq`, `tee`, `base32`, `base64`, `md5sum`, `sha1sum`, `sha256sum`, `cp`, `mv`, `install`, `rsync`, `scp`, `tar`, `zip`, `gzip`, `openssl`, `gpg`, `dd`, `jq`, `yq`.
- `privatePathCandidates` contributes, per simple: **every** `argPathValues` entry when `pathOperandCommands[head(s.Argv)]`, otherwise only those passing `looksLikePath`; plus, when `isOpaqueExecutor(head(s.Argv))`, every `visiblePathCandidates` token passing `looksLikePath`. Redirects and write targets stay as they are.

**The opaque-source boundary, stated and tested.** `visiblePathCandidates` extracts `/home/u/.ssh/id_rsa` from both `open('/home/u/.ssh/id_rsa')` and `print('/home/u/.ssh/id_rsa')`. Telling access from mention would mean parsing Python, Node, Perl and Ruby, which this engine will not do. The intended boundary is therefore explicit: **inside opaque source we match the literal presence of a secret path and do not attempt to distinguish access from mention.** Task 3's verdict tier makes that proportionate — a `secret_dirs` path in source denies, an ambiguous one asks. An agent writing a script that merely prints `~/.ssh/id_rsa` being asked about it is an acceptable, arguably correct, outcome. Step 1 tests both halves so this is a decision on record rather than an accident.

- [ ] **Step 1: Write the failing test**

```go
func TestSecretReadsViaAnyCommand(t *testing.T) {
	pol := pathPol()
	deny := []string{
		`cp /home/u/.ssh/id_rsa /tmp/x`, `mv /home/u/.ssh/id_rsa /tmp/x`,
		`base64 /home/u/.aws/credentials`, `tar cf - /home/u/.ssh/id_rsa`,
		`openssl rsa -in /home/u/.ssh/id_rsa`, `md5sum /home/u/.ssh/id_rsa`,
		`dd if=/home/u/.ssh/id_rsa`, `grep -f/home/u/.ssh/id_rsa x`,
		`python3 -c "print(open('/home/u/.ssh/id_rsa').read())"`,
		`node -e "require('fs').readFileSync('/home/u/.ssh/id_rsa')"`,
	}
	for _, c := range deny {
		tc := ToolCall{Tool: "Bash", Command: c, CWD: "/repo", RepoRoot: "/repo"}
		if v := checkPaths(tc, pol); v == nil || v.Decision != policy.Deny {
			t.Errorf("%q -> %+v, want deny", c, v)
		}
	}
}

func TestBareFilenameReadsAreNotRegressed(t *testing.T) {
	// Verified against the deployed v0.12.0-dev binary: these deny TODAY.
	// looksLikePath("id_rsa") is false, so the reader-command hint is the only
	// thing keeping them working once pathReaders stops being the gate.
	pol := pathPol()
	for _, c := range []string{`cat id_rsa`, `head -n1 id_rsa`, `base64 id_rsa`, `cp id_rsa /tmp/x`} {
		tc := ToolCall{Tool: "Bash", Command: c, CWD: "/home/u/.ssh", RepoRoot: "/repo"}
		if v := checkPaths(tc, pol); v == nil || v.Decision != policy.Deny {
			t.Errorf("%q (cwd ~/.ssh) -> %+v, want deny", c, v)
		}
	}
}

func TestOpaqueSourceBoundaryIsExplicit(t *testing.T) {
	pol := pathPol()
	// Inside opaque source we match the literal presence of a secret path and
	// do NOT distinguish access from mention. Both of these deny, deliberately.
	for _, c := range []string{
		`python3 -c "print(open('/home/u/.ssh/id_rsa').read())"`,
		`python3 -c "print('/home/u/.ssh/id_rsa')"`,
	} {
		tc := ToolCall{Tool: "Bash", Command: c, CWD: "/repo", RepoRoot: "/repo"}
		if v := checkPaths(tc, pol); v == nil || v.Decision != policy.Deny {
			t.Errorf("%q -> %+v, want deny (secret_dirs path in opaque source)", c, v)
		}
	}
	// An ambiguous path in source asks rather than denying (Task 3's tier).
	tc := ToolCall{Tool: "Bash", Command: `python3 -c "print('/repo/docs/cert.pem')"`,
		CWD: "/repo", RepoRoot: "/repo"}
	if v := checkPaths(tc, pol); v == nil || v.Decision != policy.Ask {
		t.Errorf("ambiguous path in source -> %+v, want ask", v)
	}
	// Source mentioning no path at all is untouched.
	tc = ToolCall{Tool: "Bash", Command: `python3 -c "print('hello world')"`,
		CWD: "/repo", RepoRoot: "/repo"}
	if v := checkPaths(tc, pol); v != nil && v.Decision != policy.Allow {
		t.Errorf("ordinary source -> %+v, want allow", v)
	}
}

func TestOrdinaryArgumentsAreNotPaths(t *testing.T) {
	pol := pathPol()
	allow := []string{
		`go build ./...`, `npm test`, `grep -r TODO src/`,
		`grep '*.pem' /repo/build.log`, `printf '%s.key\n' name`,
		`jq '.env' /repo/pkg.json`, `cp src/a.go src/b.go`,
		`docker compose up -d`, `echo "id_rsa is a filename"`,
	}
	for _, c := range allow {
		tc := ToolCall{Tool: "Bash", Command: c, CWD: "/repo", RepoRoot: "/repo"}
		if v := checkPaths(tc, pol); v != nil && v.Decision == policy.Deny {
			t.Errorf("%q -> %+v, want not-deny", c, v)
		}
	}
}
```

- [ ] **Step 2: Run to verify it fails** — the deny set ALLOWs.

- [ ] **Step 3: Implement** — in `privatePathCandidates`, replace the `pathReaders[head(s.Argv)]` block:

```go
			// The reader list is a hint, not a gate (review CR-9). For a known
			// reader every operand is a candidate — including a bare "id_rsa",
			// which the known cwd resolves and which looksLikePath would drop.
			// For anything else the operand must look like a path, which keeps
			// grep patterns and printf formats out of the matcher.
			knownReader := pathOperandCommands[head(s.Argv)]
			for _, arg := range argPathValues(s.Argv) {
				if knownReader || looksLikePath(arg) {
					candidates = append(candidates, pathCandidate{
						path: arg, cwd: s.Cwd, cwdUnknown: s.cwdUnknown, repoRoot: tc.RepoRoot})
				}
			}
			// python3 -c / node -e carry the path inside a source string, where
			// no whole-argument match can see it.
			if isOpaqueExecutor(head(s.Argv)) {
				for _, arg := range s.Argv[1:] {
					for _, tok := range visiblePathCandidates(arg) {
						if looksLikePath(tok) {
							candidates = append(candidates, pathCandidate{
								path: tok, cwd: s.Cwd, cwdUnknown: s.cwdUnknown, repoRoot: tc.RepoRoot})
						}
					}
				}
			}
```

`pathOperandCommands` is the renamed, extended `pathReaders` — it stays.

- [ ] **Step 4: Run the full suite verbosely.** This is the highest false-positive risk in the plan. Read every new failure before changing anything.

- [ ] **Step 5: Commit**

```bash
gofmt -w internal/engine/ && git add internal/engine/
git commit -m "fix(engine): scan path-shaped args and opaque-executor source for secrets (CR-9)"
```

---

### Task 7: Corpus, docs, tag

- [ ] **Step 1: Extend the corpus** with every reproduction above as `deny`, and every false positive as `allow`: `Read /repo/i18n/translations.key`, `Read /repo/testdata/id_rsa.pub`, `Write /repo/tests/unit/conftest.py`, `Write /repo/vendor/x/Makefile`, `Write /repo/docs/templates/CLAUDE.md`, `git clean -nxd`, `grep '*.pem' /repo/build.log`, `printf '%s.key\n' name`, `jq '.env' /repo/pkg.json`, `go build ./...`, `cp src/a.go src/b.go`. Add the new `ask` tier as `ask`: `Read /repo/docs/cert.pem`, `Read /repo/testdata/service-account-fake.json`. Add the regression locks as `deny`: `cat id_rsa` and `cp id_rsa /tmp/x` with cwd `~/.ssh`.
- [ ] **Step 2:** Update `guardrail.toml.example` with commented `secret_dirs` and `secret_ask_globs` entries, and `CONTEXT.md`'s **Guardrail Policy** entry to name the three secret tiers.
- [ ] **Step 3:** `make check && /usr/local/go/bin/go test ./... -count=1` → green, zero corpus entries relaxed.
- [ ] **Step 4:** Annotate the review with `**[FIXED — Phase 4]**` on CR-9/RC4, H-2, H-7, M-2, M-3, M-4, M-5, M-6, NF-1. Update the response-report ledger. **H-6, H-10 and M-7 remain open and must be recorded as such** — they are Phase 5.
- [ ] **Step 5:**
```bash
git add -A && git commit -m "docs: Phase 4 landed — path matching corrected; H-6/H-10/M-7 remain"
git push origin main && git tag v0.13.0-dev && git push origin v0.13.0-dev
```

> Do **not** describe the review as fully closed, and do not bump the installer pins — those live in the chezmoi repo and are Carlitos's call.

---

## Self-Review

**1. Finding coverage.** M-4/M-5 → Task 1 (root-only scoping, lexical *and* resolved); H-2 → Task 2 (precedence); M-2 → Task 3 (narrowing `*.key`); M-3 → Task 3 (the `ask` tier — the patterns are ambiguous, not wrong); NF-1 → Task 3; M-6 → Task 3; H-7 → Task 4; CR-9 → Tasks 5 and 6 (flag-attached values, then the reader hint plus opaque source). H-6, H-10, M-7 are explicitly out of scope and carried to Phase 5.

**2. Placeholder scan.** None.

**3. Type consistency.** `pathCandidate` gains `repoRoot` (Task 1), set by Task 6's new candidates. `policy.Slots` gains `SecretDirs` (Task 2) and `SecretAskGlobs` (Task 3). `classifiedSecretPath` changes signature in Task 3 to return `(string, policy.Decision, bool)`; its only caller is `checkPaths`. New helpers: `repoRelative`, `matchesScoped` (Task 1), `argPathValues`, `looksLikePath` (Task 5). `pathReaders` is **renamed** `pathOperandCommands` and kept, not deleted (Task 6). `nonFlagArgs` retained for its other callers. `matchesAnyGlob` keeps its signature; semantics change in Tasks 1 and 4.

**4. Ordering.** Task 1 before Task 6 — Task 6 feeds many more candidates into the matcher Task 1 rewrites. Task 2 before Task 3 — Task 3's `**/*.pub` allow and its `ask` tier are only safe once secret directories are unwaivable. Task 5 before Task 6 (`argPathValues` is its input). Task 3 before Task 6 — Task 6's opaque-source test asserts the `ask` tier exists. Task 4 is independent.

**5. Residual risk, stated rather than implied.**
- A bare filename operand of an **unlisted** command (`somenewtool id_rsa` from `~/.ssh`) contributes no candidate, because `looksLikePath` needs a separator and the command is not in `pathOperandCommands`. Known readers and any path-shaped operand are covered; this residue is not.
- `writeTargets` still enumerates a fixed list of mutating commands, so a novel mutating binary is caught only when its target hits a secret or self-config glob.
- The opaque-source scan cannot distinguish access from mention; that boundary is deliberate, documented in Task 6, and tested.
- Moving `*.pem` and `service-account*.json` to the `ask` tier is a **deliberate reduction in strictness** for in-repo certificates. Real key material in `secret_dirs` still denies. If Carlitos would rather these keep denying, the tier is one list move to reverse — flag it rather than deciding unilaterally.

---

## Revision History

Both prior revisions were reviewed before execution and stopped. No code was ever written against either. Recorded so the same errors are not reintroduced.

### Revision 2 to 3 — five findings, all confirmed by executable probe

1. **`matchesScoped` tested only the lexical path against root-only globs.** A symlink resolving to `/repo/CLAUDE.md` has repo-relative form `notes.md` and slips through once the basename fallback is gone. Both the lexical *and* the resolved form must be tested. Fixed in Task 1.
2. **`repoRelative` broke for `repoRoot == "/"`.** `root+"/"` is `"//"`, so `HasPrefix("/CLAUDE.md", "//")` is `false` and every path in a repo rooted at `/` is classified as outside it. Verified. Replaced with `filepath.Rel` plus explicit `..` rejection. Fixed in Task 1.
3. **Task 3 claimed M-3 fixed while keeping the patterns that cause it.** Verified: `**/*.pem` matches `repo/docs/cert.pem`, and `**/service-account*.json` matches `repo/testdata/service-account-fake.json` — the review's own examples. Adding `**/*.pub` addressed only `id_rsa.pub`. Fixed by moving the ambiguous patterns to an `ask` tier rather than deleting them.
4. **Deleting `pathReaders` would have regressed a working protection.** Probed against the deployed `v0.12.0-dev`: `cat id_rsa` from cwd `~/.ssh` exits 2 today, and `looksLikePath("id_rsa")` is `false`, so gating on it alone turns that into exit 0. The list is demoted from gate to hint instead of deleted. Fixed in Task 6.
5. **The opaque-source scan had an undefined false-positive boundary.** `visiblePathCandidates` cannot tell `open('/home/u/.ssh/id_rsa')` from `print('/home/u/.ssh/id_rsa')`. The boundary is now stated explicitly, made proportionate by Task 3's verdict tier, and tested in both directions. Fixed in Task 6.

### Revision 1 to 2 — five findings

1. **Removing the basename fallback does not fix H-2.** `doublestar.Match("**/.env.example", "home/u/.ssh/.env.example")` is `true` — the allow glob matches the full path directly. H-2 is a *precedence* defect, now Task 2.
2. **Prefixing `*.key` to `**/*.key` does not fix M-2.** `**/` matches zero or more leading segments, so it still matches `i18n/translations.key`. The glob had to be narrowed, now Task 3.
3. **Adding a repo-relative form alongside the raw match does not fix M-4/M-5.** A relative `CLAUDE.md` written from a subdirectory still matches the bare glob directly. Root-only globs had to *stop* being matched against the raw form, now Task 1.
4. **Scanning every argument does not close CR-9 and adds false positives.** `nonFlagArgs` drops `-f/home/u/.ssh/id_rsa` entirely, and whole-argument matching never sees a path inside `python3 -c`. Now Tasks 5 and 6.
5. **Task 8 could not truthfully have closed the review.** H-6, H-10 and M-7 were each only partly addressed; they are now Phase 5.

### The two lessons, now Global Constraints

- **Verify glob and path behaviour by executing it, never by reading it.** `**/` matching zero segments hid two Revision 1 errors; `root+"/"` becoming `"//"` hid a Revision 2 error.
- **Probe the deployed binary for what already works before changing a gate.** Revision 2's Task 6 was a regression no amount of reading would have revealed — only running `cat id_rsa` against the installed `v0.12.0-dev` showed it.
