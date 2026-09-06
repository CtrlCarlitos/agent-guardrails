# Adversarial Remediation — Phase 4: Path Matching Correctness

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

> **Revision 2 (2026-09-06).** Revision 1 was reviewed before execution and five load-bearing premises were disproved. Nothing was committed against it. The corrections are recorded in `## Revision History` at the foot of this document; the fixes below are the corrected ones. Phase 4 now covers **path matching only**; plane coverage and session integrity moved to `2026-09-06-remediation-phase5.md`.

**Goal:** Make the path matcher say what it means. Today one glob list is asked to express three different intents — "anywhere", "at the repo root", "unless allowed" — and a single basename fallback stands in for all three. That produces false positives and a bypass at the same time.

**Architecture:** Three separate corrections, not one. (1) Repo-root-only globs get matched against a repo-relative form and nothing else. (2) Secret **directories** become unwaivable by filename-pattern allows, which is what H-2 actually needs. (3) Argument scanning becomes path-shaped rather than exhaustive, which is what CR-9 actually needs. The over-broad base globs (`*.key`) are narrowed rather than prefixed.

**Tech Stack:** Go 1.23+, existing deps only.

**Spec:** `../reviews/2026-09-04-adversarial-review.md`. Findings addressed: **CR-9/RC4, H-2, H-7, M-2, M-3, M-4, M-5, M-6**, plus **NF-1** (new, found live 2026-09-06 — see Task 3). Deferred to Phase 5: **H-6, H-10, M-7**.

## Global Constraints

- **Verify glob behaviour empirically, never by reading.** Revision 1 asserted that prefixing `*.key` → `**/*.key` would stop it matching `i18n/translations.key`. It does not: `doublestar.Match("**/*.key", "i18n/translations.key")` is `true`, because `**/` matches zero or more leading segments. The same error hid H-2. Before you rely on a glob narrowing anything, write a two-line test and run it.
- **This phase changes matching in both directions.** Every task adds `want: "allow"` corpus entries as well as `want: "deny"` ones. A fix that closes a bypass while making `conftest.py` prompt on every test file has not improved safety — M-2/M-4/M-6 are in scope precisely because false positives are why guardrails get switched off.
- **Zero corpus entries may be relaxed.** If an existing test starts failing, decide whether the *new* behaviour is correct per the review before touching the expectation. Never edit an expectation to make a suite green.
- **If a premise here is wrong, stop and say so** rather than working around it. That is how Revision 1 was caught.
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
- New `func repoRelative(p, cwd, repoRoot string) (string, bool)`: resolves `p` against `cwd` when relative, cleans and slash-normalizes, returns the path relative to `repoRoot` when inside it, else `("", false)`.
- Each of the three lists splits in two: `selfConfigAnywhere` / `selfConfigRootOnly`, `ciInfraAnywhere` / `ciInfraRootOnly`, and `gitProtectedGlobs` (already all-`**/`, stays as one).
- New `func matchesScoped(c pathCandidate, anywhere, rootOnly []string) bool`: tests raw and resolved forms against `anywhere`; tests **only** the repo-relative form against `rootOnly`.
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
	q := filepath.ToSlash(p)
	if !path.IsAbs(q) && !filepath.IsAbs(p) {
		if cwd == "" {
			return "", false
		}
		q = path.Join(filepath.ToSlash(cwd), q)
	}
	root := path.Clean(filepath.ToSlash(repoRoot))
	q = path.Clean(q)
	if q == root || !strings.HasPrefix(q, root+"/") {
		return "", false
	}
	return strings.TrimPrefix(q, root+"/"), true
}

func matchesScoped(c pathCandidate, anywhere, rootOnly []string) bool {
	raw := strings.TrimPrefix(c.path, "./")
	if matchesAnyGlob(raw, anywhere) {
		return true
	}
	if resolved, ok := resolvePathCandidate(c); ok && matchesAnyGlob(resolved, anywhere) {
		return true
	}
	if rel, ok := repoRelative(c.path, c.cwd, c.repoRoot); ok && matchesAnyGlob(rel, rootOnly) {
		return true
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

**The actual defect (M-2, M-3).** `*.key` is not a secret pattern — `.key` is used for translation catalogues, licence keys and Django `SECRET_KEY` *templates*. Prefixing it to `**/*.key` changes nothing (verified: it still matches `i18n/translations.key`). The glob itself must go, replaced by name-scoped forms. With Task 2 in place this is safe: real key material under `~/.ssh`, `~/.aws`, `~/.gnupg` is caught by `secret_dirs` regardless of extension.

**Also fixes NF-1 (new, found live 2026-09-06).** `selfConfigAnywhere` contains `**/.claude/**`, which denies writes to the *entire* `~/.claude/` tree — including `~/.claude/projects/*/memory/**`, which is agent memory, not agent configuration. Verified against the deployed `v0.12.0-dev` binary: a `Write` to `~/.claude/projects/x/memory/note.md` exits 2, the same as a `Write` to `~/.claude/settings.json`. Phase 1 fixed the read case (that `Read` now exits 0); the write case was never in scope. Replace `**/.claude/**` with the actual config surfaces: `**/.claude/settings.json`, `**/.claude/settings.local.json`, `**/.claude/hooks/**`, `**/.claude/plugins/**`, `**/.claude/agents/**`, `**/.claude/commands/**`, `**/.claude/skills/**`, `**/.claude/CLAUDE.md`. This is the same over-broad-glob defect as `*.key`, on a different list.

**Interfaces:**
- `selfConfigAnywhere`: replace `**/.claude/**` with the eight scoped globs above (NF-1).
- `base.toml` `secret_globs`: drop bare `*.key`; add `**/*_rsa`, `**/*_ed25519`, `**/*_ecdsa`, `**/*.private.key`, `**/*-private-key.*`, `**/private*.key`. Prefix the remaining bare entries (`id_rsa*` → `**/id_rsa*`, `id_ed25519*` → `**/id_ed25519*`, `*.pem` → `**/*.pem`, `service-account*.json` → `**/service-account*.json`) — cosmetic given `**/` matches zero segments, but it removes the impression that bare entries mean "root only" now that Task 1 has given that phrase a meaning.
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
		"/repo/deploy_rsa", "/repo/certs/server.pem", "/home/u/.ssh/id_rsa",
	}
	for _, p := range deny {
		tc := ToolCall{Tool: "Read", Paths: []string{p}, CWD: "/repo", RepoRoot: "/repo"}
		if v := checkPaths(tc, pol); v == nil || v.Decision != policy.Deny {
			t.Errorf("%q -> %+v, want deny", p, v)
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

**The fix has two halves.** Scan every **path-shaped** argument (not every argument), and for opaque executors scan the *inside* of the argument with the existing `visiblePathCandidates` extractor — the same machinery `containsOperatorConfigPath` already uses for this exact problem.

**Interfaces:** `pathReaders` is deleted. `privatePathCandidates` contributes, per simple: every `argPathValues` entry passing `looksLikePath`; plus, when `isOpaqueExecutor(head(s.Argv))`, every `visiblePathCandidates` token of every argument that passes `looksLikePath`. Redirects and write targets stay as they are.

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
			// A closed list of "reader" commands failed open on cp, base64,
			// tar, openssl and everything unlisted (review CR-9). Scan every
			// path-shaped argument instead; looksLikePath keeps grep patterns
			// and printf formats out of the matcher.
			for _, arg := range argPathValues(s.Argv) {
				if looksLikePath(arg) {
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

then delete `pathReaders`.

- [ ] **Step 4: Run the full suite verbosely.** This is the highest false-positive risk in the plan. Read every new failure before changing anything.

- [ ] **Step 5: Commit**

```bash
gofmt -w internal/engine/ && git add internal/engine/
git commit -m "fix(engine): scan path-shaped args and opaque-executor source for secrets (CR-9)"
```

---

### Task 7: Corpus, docs, tag

- [ ] **Step 1: Extend the corpus** with every reproduction above as `deny`, and every false positive as `allow`: `Read /repo/i18n/translations.key`, `Read /repo/testdata/id_rsa.pub`, `Write /repo/tests/unit/conftest.py`, `Write /repo/vendor/x/Makefile`, `Write /repo/docs/templates/CLAUDE.md`, `git clean -nxd`, `grep '*.pem' /repo/build.log`, `printf '%s.key\n' name`, `jq '.env' /repo/pkg.json`, `go build ./...`, `cp src/a.go src/b.go`.
- [ ] **Step 2:** `make check && /usr/local/go/bin/go test ./... -count=1` → green, zero corpus entries relaxed.
- [ ] **Step 3:** Annotate the review with `**[FIXED — Phase 4]**` on CR-9/RC4, H-2, H-7, M-2, M-3, M-4, M-5, M-6. Update the response-report ledger. **H-6, H-10 and M-7 remain open and must be recorded as such** — they are Phase 5.
- [ ] **Step 4:**
```bash
git add -A && git commit -m "docs: Phase 4 landed — path matching corrected; H-6/H-10/M-7 remain"
git push origin main && git tag v0.13.0-dev && git push origin v0.13.0-dev
```

> Do **not** describe the review as fully closed, and do not bump the installer pins — those live in the chezmoi repo and are Carlitos's call.

---

## Self-Review

**1. Finding coverage.** M-2/M-4/M-5 → Tasks 1 and 3 (two distinct causes: root-only scoping, and an over-broad glob); H-2 → Task 2 (precedence); M-3/M-6 → Task 3; H-7 → Task 4; CR-9 → Tasks 5 and 6 (flag-attached values, then path-shaped scanning plus opaque source). H-6, H-10, M-7 are explicitly out of scope and carried to Phase 5.

**2. Placeholder scan.** None.

**3. Type consistency.** `pathCandidate` gains `repoRoot` (Task 1), set by Task 6's new candidates. `policy.Slots` gains `SecretDirs` (Task 2). New helpers: `repoRelative`, `matchesScoped` (Task 1), `argPathValues`, `looksLikePath` (Task 5). `pathReaders` deleted (Task 6). `nonFlagArgs` retained for its other callers. `matchesAnyGlob` keeps its signature; semantics change in Tasks 1 and 4.

**4. Ordering.** Task 1 before Task 6 — Task 6 feeds many more candidates into the matcher Task 1 rewrites. Task 2 before Task 3 — Task 3's `**/*.pub` allow is only safe once secret directories are unwaivable. Task 5 before Task 6 (`argPathValues` is its input). Task 4 is independent.

**5. Residual risk, stated rather than implied.** `looksLikePath` requires a separator, so a bare `cat id_rsa` executed with an *unknown* cwd contributes no candidate — `cwdUnknown` already suppresses resolution there, so this is not a regression, but it is not closed either. `writeTargets` still enumerates a fixed list of mutating commands, so a novel mutating binary is caught only when its target hits a secret or self-config glob. Both are narrower than the original finding and are recorded here deliberately.

---

## Revision History

**Revision 2 (2026-09-06)** — Revision 1 was reviewed before any execution; five load-bearing premises were disproved and no code was written against it. Recorded so the same errors are not reintroduced:

1. **Removing the basename fallback does not fix H-2.** `doublestar.Match("**/.env.example", "home/u/.ssh/.env.example")` is `true` — the allow glob matches the full path directly. H-2 is a *precedence* defect, now Task 2.
2. **Prefixing `*.key` → `**/*.key` does not fix M-2.** `**/` matches zero or more leading segments, so it still matches `i18n/translations.key`. The glob had to be narrowed, now Task 3.
3. **Adding a repo-relative form alongside the raw match does not fix M-4/M-5.** A relative `CLAUDE.md` written from a subdirectory still matches the bare glob directly. Root-only globs had to *stop* being matched against the raw form, now Task 1.
4. **Scanning every argument does not close CR-9 and adds false positives.** `nonFlagArgs` drops `-f/home/u/.ssh/id_rsa` entirely, and whole-argument matching never sees a path inside `python3 -c`. Now Tasks 5 and 6, gated by `looksLikePath`.
5. **Task 8 could not have truthfully closed the review.** H-6, H-10 and M-7 were each only partly addressed; they are now Phase 5, and Phase 4 explicitly does not claim them.

The general lesson, now a Global Constraint: **verify glob behaviour by running it, not by reading it.**
