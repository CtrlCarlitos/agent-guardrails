# Adversarial Remediation — Phase 4: Path Matching Correctness

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

> **Revision 5 (2026-09-06).** Revisions 1–3 specified literal implementation code and were each stopped with four or five disproved premises. Revision 4 dropped implementation code and specified behaviour through tests; it was stopped because two tests were wrong and seven required behaviours were missing — most seriously, that moving globs between slots would silently remove them from the generated Claude/opencode **declarative floors**. Revision 5 corrects all of that. **This revision specifies behaviour only**: the defect, the required behaviour, the tests that define it, the corpus locks, the files in scope, and the constraints. The executor owns the implementation. Tests here are the contract; if a test is wrong, stop and say so, as before.

**Goal:** Make the path matcher say what it means. One glob list currently expresses three intents — "anywhere", "at the repo root", "unless allowed" — through a single basename fallback, producing false positives and a bypass at once.

**Tech Stack:** Go 1.23+, existing deps only.

**Spec:** `../reviews/2026-09-04-adversarial-review.md`. Findings addressed: **CR-9/RC4, H-2, H-7, M-2, M-3, M-4, M-5, M-6, NF-1**. Deferred to Phase 5: **H-6, H-10, M-7**.

**Policy schema change:** Task 2 adds `secret_dirs`, Task 3 adds `secret_ask_globs`. Each is a new `[slots]` list and touches **`internal/policy/base.go`, `policy.go`, `config.go`, `merge.go` and their tests** — the same places `SecretGlobs` is wired today. Both are additive and tightening-only: no Operator grant needed, old Overlays keep working.

**Tests verified on HEAD code (`c46ef67`), Revision 5 plan.** Every engine test below (17 functions: `wantAllow` + 16 tests) was extracted from this document into `internal/engine/` in a scratch worktree of HEAD, with `argPathValues` stubbed to `nonFlagArgs`; the three `internal/policy`/`internal/genconfig` tests were excluded because they reference slots that do not exist yet. Result: **all compile; 15 fail on HEAD for the defect their task describes; `TestRootOnlyGlobsFollowSymlinks` passes and is a regression lock.** Failures confirmed: root-only globs deny at depth and `/etc/CLAUDE.md` denies (M-4/M-5); `~/.ssh/.env.example` and `~/.aws/.env.example` allow (H-2); `translations.key` and `id_rsa.pub` deny, `cert.pem` denies rather than asks (M-2/M-3); agent memory write denies (NF-1); `git clean -nxd` denies (M-6); `.SSH/ID_RSA` allows (H-7); every flag-attached form is dropped (T5); `cp`/`mv`/`base64`/`tar`/`openssl`/`dd`/`somenewtool` and both `python3 -c` forms allow (CR-9); `grep '*.pem'`, `grep -r id_rsa`, `grep -e '*.pem'`, `grep /repo/log -e '*.pem'` and `awk -F: '/id_rsa/'` all deny (existing false positives — the awk case is the Revision 4 wrong-test, reproduced); `jq -f <secret>` and `dd if=<symlink→secret>` allow. Within `TestStrongestVerdictAcrossRules`, only "waived ask alone → allow" fails on HEAD; the other assertions pass trivially today and become meaningful when the ask tier lands. Assertions that pass on HEAD are regression locks and are labelled as such.

*Method note, so the executor does not repeat the author's mistake: a `git worktree` checks out **HEAD**, so extracting tests from the worktree's copy of this plan verifies the last **committed** revision, not the file being edited. Read the plan from the working tree.*

## Global Constraints

- **Verify glob and path behaviour by executing it, never by reading it.** `**/` matches zero segments; `root+"/"` becomes `"//"` at the root; `filepath.Rel` returns `../…` rather than an error. Each of these hid a prior-revision error.
- **Never let a fix weaken something that works today.** Probe the deployed binary (`~/.local/bin/guardrail`, `v0.12.0-dev`) for what it already catches before changing a gate, and lock it as a test first.
- **Allow means allow.** Every "want allow" assertion is `v == nil || v.Decision == policy.Allow`. Revision 3 used "not deny", which let an accidental `ask` pass silently. Use one helper:
  ```go
  func wantAllow(t *testing.T, label string, v *policy.Verdict) {
  	t.Helper()
  	if v != nil && v.Decision != policy.Allow {
  		t.Errorf("%s -> %+v, want allow", label, v)
  	}
  }
  ```
- **Zero corpus entries may be relaxed.** If an existing test fails, decide whether the new behaviour is correct per the review before touching the expectation.
- **If a premise is wrong, stop and say so.** Three revisions were caught this way before any code was written.
- `gofmt -w` before every commit. Conventional Commits, one commit per task.

**Verified current state** (read from the tree; items marked ▶ executed against the deployed binary):

- `matchesAnyGlob` tries the full cleaned path **and** its basename against every glob.
- `checkPaths` (`rules_path.go:41`) **returns on the first classified candidate**. Candidate order follows command order.
- `classifiedSecretPath` returns on any `secret_allow` match before consulting `secret_globs`.
- `checkSelfConfig`, `checkCIInfraLockfile`, `checkGitProtectedPaths` match raw and resolved paths only; no repo-relative form exists.
- `pathReaders` = `cat head tail grep egrep fgrep sed awk less more bat xxd od strings`. It is the gate for read-side candidates. `nonFlagArgs` drops every `-`-prefixed token.
- `visiblePathCandidates(string) []string` extracts quoted literals and path-shaped tokens; `isOpaqueExecutor` covers python/node/perl/ruby/php/lua/awk/powershell.
- ▶ `cat id_rsa` with cwd `~/.ssh` → exit 2. `cp id_rsa /tmp/x` with cwd `~/.ssh` → exit 0.
- ▶ `grep '*.pem' /repo/build.log` → exit 2 — an **existing** false positive: the pattern operand is treated as a path.
- ▶ `Write ~/.claude/projects/x/memory/note.md` → exit 2; `Read` of the same → exit 0.

---

### Task 1: Root-only globs match at the repo root and nowhere else

**Files:** `internal/engine/rules_path.go`, `internal/engine/rules_git.go`, tests.

**Defect (M-4, M-5).** `CLAUDE.md`, `Makefile`, `conftest.py`, `Dockerfile` and the lockfiles are meant to match only at the repository root, but they match any path with that basename — absolute (`/repo/vendor/x/Makefile`) via the basename fallback, and relative (`Makefile` from cwd `/repo/vendor/x`) directly.

**Required behaviour.**
- Each protected list separates *anywhere* globs (`**/…`) from *root-only* globs.
- Root-only globs match **only** a repo-relative form, derived from **both** the lexical path (resolved against cwd if relative) **and** the filesystem-resolved path — a symlink whose target is `/repo/CLAUDE.md` must be caught.
- Repo containment must not use `root+"/"` prefix arithmetic (breaks for repoRoot `/`), must reject any `../` escape, and must be **case-insensitive** (Task 4's rationale: on APFS/NTFS `/REPO/CLAUDE.md` is the same file).
- The basename fallback is removed from `matchesAnyGlob`.

- [ ] **Step 1: Tests (must fail first)**

```go
func TestRootOnlyGlobsMatchOnlyAtRepoRoot(t *testing.T) {
	deep := []struct{ path, cwd string }{
		{"CLAUDE.md", "/repo/docs/templates"}, {"/repo/docs/templates/CLAUDE.md", "/repo"},
		{"Makefile", "/repo/vendor/x"}, {"/repo/vendor/x/Makefile", "/repo"},
		{"conftest.py", "/repo/tests/unit"}, {"/repo/tests/unit/conftest.py", "/repo"},
	}
	for _, d := range deep {
		tc := ToolCall{Tool: "Write", Paths: []string{d.path}, CWD: d.cwd, RepoRoot: "/repo"}
		wantAllow(t, "selfConfig "+d.path+" cwd "+d.cwd, checkSelfConfig(tc))
		wantAllow(t, "ciInfra "+d.path+" cwd "+d.cwd, checkCIInfraLockfile(tc))
	}
	for _, r := range []struct{ path, cwd, root string }{
		{"CLAUDE.md", "/repo", "/repo"}, {"/repo/CLAUDE.md", "/repo", "/repo"}, {"./CLAUDE.md", "/repo", "/repo"},
		{"/CLAUDE.md", "/", "/"}, // repoRoot "/" — must not be rejected by containment
	} {
		tc := ToolCall{Tool: "Write", Paths: []string{r.path}, CWD: r.cwd, RepoRoot: r.root}
		if v := checkSelfConfig(tc); v == nil || v.Decision != policy.Deny {
			t.Errorf("selfConfig %q (root %s) -> %+v, want deny", r.path, r.root, v)
		}
	}
	tc := ToolCall{Tool: "Write", Paths: []string{"/home/u/.bashrc"}, CWD: "/repo", RepoRoot: "/repo"}
	if v := checkSelfConfig(tc); v == nil || v.Decision != policy.Deny {
		t.Errorf("~/.bashrc -> %+v, want deny (anywhere glob unaffected)", v)
	}
	// Containment is case-insensitive; an escape is never repo-relative.
	up := ToolCall{Tool: "Write", Paths: []string{"/REPO/CLAUDE.md"}, CWD: "/REPO", RepoRoot: "/repo"}
	if v := checkSelfConfig(up); v == nil || v.Decision != policy.Deny {
		t.Errorf("/REPO/CLAUDE.md with root /repo -> %+v, want deny", v)
	}
	esc := ToolCall{Tool: "Write", Paths: []string{"/etc/CLAUDE.md"}, CWD: "/repo", RepoRoot: "/repo"}
	wantAllow(t, "/etc/CLAUDE.md is outside the repo", checkSelfConfig(esc))
}

func TestRootOnlyGlobsFollowSymlinks(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "CLAUDE.md"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(root, "CLAUDE.md"), filepath.Join(root, "notes.md")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	tc := ToolCall{Tool: "Write", Paths: []string{filepath.Join(root, "notes.md")}, CWD: root, RepoRoot: root}
	if v := checkSelfConfig(tc); v == nil || v.Decision != policy.Deny {
		t.Errorf("symlink to CLAUDE.md -> %+v, want deny", v)
	}
}
```

- [ ] **Step 2:** Run → the `deep` cases and `/etc/CLAUDE.md` fail (deny); `/REPO/…` and the symlink fail after the fallback is removed.
- [ ] **Step 3:** Implement. Split lists: root-only = `CLAUDE.md AGENTS.md .mcp.json guardrail.toml opencode.json .gitlab-ci.yml Jenkinsfile .pre-commit-config.yaml azure-pipelines.yml Dockerfile docker-compose*.yml *.tf Makefile justfile Taskfile.yml setup.py conftest.py noxfile.py` + lockfiles; everything `**/`-prefixed stays anywhere. **`.envrc` becomes `**/.envrc` (anywhere), not root-only** — direnv executes the `.envrc` of every directory you enter, so a nested one is exactly as dangerous as the root one. Add a test: `Write /repo/sub/.envrc` → deny.
- [ ] **Step 4:** Full suite. Any newly-failing case is a signal, not noise.
- [ ] **Step 5:** `git commit -m "fix(engine): root-only globs match the repo-relative form only, lexical and resolved (M-4, M-5)"`

---

### Task 2: Secret directories outrank filename allows

**Files:** `internal/engine/rules_path.go`, `internal/policy/{base.go,policy.go,config.go,merge.go,base.toml}` and their tests.

**Defect (H-2).** ▶ `doublestar.Match("**/.env.example", "home/u/.ssh/.env.example")` is `true`. `secret_allow` is consulted first, so a file merely *named* `.env.example` inside `~/.ssh/` suppresses the `**/.ssh/**` deny. This is precedence, not glob syntax.

**Required behaviour.**
- New slot `secret_dirs` (`Slots.SecretDirs`), wired through all five policy files exactly as `SecretGlobs` is. Move out of `secret_globs`: `**/.ssh/**`, `/root/.ssh/**`, `**/.aws/**`, `**/.config/gcloud/**`, `**/.docker/config.json`; add `**/.gnupg/**`.
- A `secret_dirs` match denies **unconditionally** — no `secret_allow` entry, of any form, can waive it.
- Overlay merge: additive, tightening-only.
- **The declarative floors must not lose these entries.** `genconfig/claude.go:60` (`secretDenyGlobs`) builds Claude's native `Read(...)`/`Edit(...)` deny list from `Slots.SecretGlobs` **only**. Moving `**/.ssh/**` out of `secret_globs` without touching the generator silently removes it from `settings.json` — the engine gets stronger while the floor gets weaker. `secretDenyGlobs` must also emit every `SecretDirs` entry, and unlike `secret_globs` entries these are **never** skipped by `collidesWithAllow`. Apply the same to the opencode generator (`genconfig/opencode.go`) wherever it consumes secret slots. Regenerate goldens and **read the diff**: the only acceptable change is that no `.ssh`/`.aws`/`.gnupg`/gcloud/docker-config entry disappears.

Add to `internal/genconfig`:

```go
func TestSecretDirsReachTheDeclarativeFloor(t *testing.T) {
	pol := &policy.Policy{Slots: policy.Slots{
		SecretDirs:  []string{"**/.ssh/**"},
		SecretGlobs: []string{"**/.env"},
		SecretAllow: []string{"**/.ssh/**"}, // an allow can never remove a secret dir from the floor
	}}
	got := secretDenyGlobs(pol)
	for _, want := range []string{"Read(**/.ssh/**)", "Edit(**/.ssh/**)", "Read(**/.env)"} {
		if !slices.Contains(got, want) {
			t.Errorf("floor = %v, want to contain %q", got, want)
		}
	}
}
```

- [ ] **Step 1: Tests**

```go
func TestSecretDirsAreUnwaivableByFilenameAllow(t *testing.T) {
	pol := pathPol()
	for _, p := range []string{
		"/home/u/.ssh/.env.example", "/home/u/.ssh/.env.sample",
		"/home/u/.aws/.env.example", "/home/u/.ssh/id_rsa.pub",
	} {
		tc := ToolCall{Tool: "Read", Paths: []string{p}, CWD: "/repo", RepoRoot: "/repo"}
		if v := checkPaths(tc, pol); v == nil || v.Decision != policy.Deny {
			t.Errorf("%q -> %+v, want deny", p, v)
		}
	}
	tc := ToolCall{Tool: "Read", Paths: []string{"/repo/.env.example"}, CWD: "/repo", RepoRoot: "/repo"}
	wantAllow(t, "/repo/.env.example", checkPaths(tc, pol))
}

// In internal/policy/merge_test.go — uses the existing mergeNoOp helper.
// An Overlay may add a secret dir and can never remove one.
func TestSecretDirsMergeIsAdditiveOnly(t *testing.T) {
	base := &Policy{Slots: Slots{SecretDirs: []string{"**/.ssh/**"}}}
	ov := &Overlay{SecretDirs: []string{"**/.vault/**"}}
	m, _ := mergeNoOp(t, base, ov)
	for _, want := range []string{"**/.ssh/**", "**/.vault/**"} {
		if !slices.Contains(m.Slots.SecretDirs, want) {
			t.Errorf("merged SecretDirs = %v, want to contain %q", m.Slots.SecretDirs, want)
		}
	}
}
```

- [ ] **Step 2:** Run → the four ALLOW.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** `git commit -m "feat(policy): secret_dirs — secret directories outrank filename allows (H-2)"`

---

### Task 3: An `ask` tier for ambiguous patterns; strongest verdict wins

**Files:** `internal/engine/rules_path.go`, `internal/engine/rules_bash.go`, `internal/policy/{base.go,policy.go,config.go,merge.go,base.toml}` and their tests.

**Defects.**
- **M-2:** `*.key` matches `i18n/translations.key`; ▶ so does `**/*.key`. The glob is wrong, not its prefix.
- **M-3:** ▶ `**/*.pem` matches `repo/docs/cert.pem`; `**/service-account*.json` matches `repo/testdata/service-account-fake.json`. These are the review's own examples, and they are *ambiguous* — the same glob matches real key material and ordinary fixtures. Ambiguous evidence should yield `ask`, not `deny`.
- **Aggregation:** `checkPaths` returns on the first candidate. With an `ask` tier, `cat /repo/docs/cert.pem /home/u/.ssh/id_rsa` would return `ask` before seeing the definitive deny. **Every path rule must evaluate all candidates and return the strongest verdict.**
- **NF-1:** `**/.claude/**` denies writes to agent *memory* (`~/.claude/projects/*/memory/`), not just agent config.
- **M-6:** `git clean -n` / `--dry-run` removes nothing.

**Required behaviour.**
- New slot `secret_ask_globs` (`Slots.SecretAskGlobs`), five policy files. Holds `**/*.pem **/*.p12 **/*.pfx **/*.keystore **/service-account*.json`, moved out of `secret_globs`. Waivable by `secret_allow`; `secret_dirs` still wins.
- `secret_globs`: drop `*.key`; **retain the suffix-preserving forms as explicit anywhere globs** — `**/id_rsa* **/id_ed25519* **/id_ecdsa* **/id_dsa*` — because the basename fallback that made bare `id_rsa*` match at depth is gone, and `**/*_rsa` does not cover `id_rsa_work` or `id_rsa.old`; add `**/*_rsa **/*_ed25519 **/*_ecdsa **/*.private.key **/*-private-key.* **/private*.key`. `secret_allow` gains `**/*.pub`.
- **The `ask` tier is in-repo only.** An ask-tier pattern matching a path *outside* `RepoRoot` (e.g. `/home/u/certs/client.pem`) **denies**, exactly as today. The stated intent is to stop hard-blocking *in-repo* fixtures; a global downgrade would weaken protection for every certificate on the machine, which the no-weakening rule forbids.
- Rule IDs: `P4.secret-path` (deny), `P4.secret-path-ambiguous` (ask). Both waivable by ID.
- `checkPaths` aggregates across all candidates: deny > ask > nil.
- `**/.claude/**` is replaced with `**/.claude/settings.json **/.claude/settings.local.json **/.claude/hooks/** **/.claude/plugins/** **/.claude/agents/** **/.claude/commands/** **/.claude/skills/** **/.claude/CLAUDE.md`.
- `git clean` with `-n`/`--dry-run` returns nil before the force-flag check.
- **Declarative floors follow the tiers and the scoped `.claude` list.** Claude's generator emits an `"ask"` permission list alongside `"deny"` (`claude.go`, the `"ask": ask` entry): every `SecretAskGlobs` entry becomes `Read(<glob>)`/`Edit(<glob>)` under **ask**, not deny. The hand-duplicated `selfConfigGlobsFloor` (`claude.go:94`, currently `.claude/**`) is narrowed to the same eight scoped entries as the engine, in the floor's project-relative form (`.claude/settings.json`, `.claude/hooks/**`, …) — the comment above it says the two lists are kept in sync by hand, so this task is where that happens. Opencode's generator gets the equivalent treatment. Regenerate goldens; the diff must show `*.pem`/`service-account*.json` moving from deny to ask and `.claude/**` replaced by the scoped entries, and nothing else.

Add to `internal/genconfig`:

```go
func TestAskTierAndScopedClaudeReachTheFloor(t *testing.T) {
	pol := &policy.Policy{Slots: policy.Slots{SecretAskGlobs: []string{"**/*.pem"}}}
	cfg := ClaudeConfig("guardrail", pol) // match the real constructor signature
	perms := cfg["permissions"].(map[string]any)
	ask, deny := perms["ask"].([]string), perms["deny"].([]string)
	if !slices.Contains(ask, "Read(**/*.pem)") || slices.Contains(deny, "Read(**/*.pem)") {
		t.Errorf("ask-tier glob must be under ask, not deny: ask=%v deny=%v", ask, deny)
	}
	if slices.Contains(deny, "Edit(.claude/**)") || !slices.Contains(deny, "Edit(.claude/settings.json)") {
		t.Errorf("self-config floor must be scoped: deny=%v", deny)
	}
}
```
(Adjust the traversal to `ClaudeConfig`'s real return shape; the golden test in `test/` shows it.)

- [ ] **Step 1: Tests**

```go
func TestSecretTiers(t *testing.T) {
	pol := pathPol()
	read := func(p string) *policy.Verdict {
		return checkPaths(ToolCall{Tool: "Read", Paths: []string{p}, CWD: "/repo", RepoRoot: "/repo"}, pol)
	}
	for _, p := range []string{"/repo/i18n/translations.key", "/repo/testdata/id_rsa.pub", "/repo/keys/server.pub"} {
		wantAllow(t, p, read(p))
	}
	for _, p := range []string{"/repo/docs/cert.pem", "/repo/testdata/service-account-fake.json", "/repo/testdata/tls/localhost.pem"} {
		if v := read(p); v == nil || v.Decision != policy.Ask || v.RuleID != "P4.secret-path-ambiguous" {
			t.Errorf("%q -> %+v, want ask/P4.secret-path-ambiguous", p, v)
		}
	}
	for _, p := range []string{
		"/repo/certs/private.key", "/repo/deploy_rsa", "/home/u/.ssh/id_rsa", "/home/u/.ssh/server.pem",
		"/repo/keys/id_rsa_work", "/repo/keys/id_ed25519.old", // suffix-preserving forms survive the fallback removal
		"/home/u/certs/client.pem", "/opt/svc/service-account.json", // ask tier is in-repo only; outside the repo these still deny
	} {
		if v := read(p); v == nil || v.Decision != policy.Deny {
			t.Errorf("%q -> %+v, want deny", p, v)
		}
	}
}

func TestStrongestVerdictWinsAcrossCandidates(t *testing.T) {
	// ▶ On HEAD the three deny cases pass trivially (cert.pem denies today).
	// They become the real aggregation check the moment the ask tier lands,
	// which is why this test lives in the same task as the tier.
	pol := pathPol()
	for _, c := range []string{
		`cat /repo/docs/cert.pem /home/u/.ssh/id_rsa`, // ask first, deny second
		`cat /home/u/.ssh/id_rsa /repo/docs/cert.pem`, // deny first
		`cat /repo/README.md /repo/docs/cert.pem /home/u/.ssh/id_rsa`,
	} {
		tc := ToolCall{Tool: "Bash", Command: c, CWD: "/repo", RepoRoot: "/repo"}
		if v := checkPaths(tc, pol); v == nil || v.Decision != policy.Deny {
			t.Errorf("%q -> %+v, want deny (strongest across candidates)", c, v)
		}
	}
	tc := ToolCall{Tool: "Bash", Command: `cat /repo/README.md /repo/docs/cert.pem`, CWD: "/repo", RepoRoot: "/repo"}
	if v := checkPaths(tc, pol); v == nil || v.Decision != policy.Ask {
		t.Errorf("ask-only -> %+v, want ask", v)
	}
}

func TestStrongestVerdictAcrossRules(t *testing.T) {
	// Aggregation is not only within secret candidates: an ambiguous ask must
	// never mask a deny from a sibling rule, in either operand order, and a
	// waiver of the ask rule must not waive the deny.
	pol := pathPol()
	root := t.TempDir()
	secret := filepath.Join(root, "outside", "id_rsa")
	if err := os.MkdirAll(filepath.Dir(secret), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(secret, []byte("k"), 0o600); err != nil {
		t.Fatal(err)
	}
	repo := filepath.Join(root, "repo")
	if err := os.MkdirAll(filepath.Join(repo, "docs"), 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(repo, "link")
	if err := os.Symlink(secret, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	pem := filepath.Join(repo, "docs", "cert.pem")
	for _, c := range []string{
		"cat " + pem + " " + link, // ask (pem) then symlink-escape deny
		"cat " + link + " " + pem, // deny then ask
	} {
		tc := ToolCall{Tool: "Bash", Command: c, CWD: repo, RepoRoot: repo}
		if v := checkPaths(tc, pol); v == nil || v.Decision != policy.Deny {
			t.Errorf("%q -> %+v, want deny (symlink escape outranks ambiguous ask)", c, v)
		}
	}
	// Self-config deny beside an ambiguous read, through the whole engine.
	tc := ToolCall{Tool: "Bash", Command: "cat " + pem + " > " + filepath.Join(repo, "CLAUDE.md"), CWD: repo, RepoRoot: repo}
	if v := Evaluate(tc, pol); v.Decision != policy.Deny {
		t.Errorf("ambiguous read + self-config write -> %+v, want deny", v)
	}
	// Waiving the ask rule does not waive the deny.
	waived := *pol
	waived.Waived = map[string]bool{"P4.secret-path-ambiguous": true}
	tc = ToolCall{Tool: "Bash", Command: "cat " + pem + " " + link, CWD: repo, RepoRoot: repo}
	if v := Evaluate(tc, &waived); v.Decision != policy.Deny {
		t.Errorf("waived ask + deny -> %+v, want deny", v)
	}
	tc = ToolCall{Tool: "Bash", Command: "cat " + pem, CWD: repo, RepoRoot: repo}
	if v := Evaluate(tc, &waived); v.Decision != policy.Allow {
		t.Errorf("waived ask alone -> %+v, want allow", v)
	}
}

func TestAgentMemoryIsNotAgentConfig(t *testing.T) {
	mem := ToolCall{Tool: "Write", Paths: []string{"/home/u/.claude/projects/x/memory/note.md"}, CWD: "/repo", RepoRoot: "/repo"}
	wantAllow(t, "agent memory", checkSelfConfig(mem))
	for _, p := range []string{"/home/u/.claude/settings.json", "/home/u/.claude/hooks/pre.sh", "/repo/.claude/settings.local.json"} {
		tc := ToolCall{Tool: "Write", Paths: []string{p}, CWD: "/repo", RepoRoot: "/repo"}
		if v := checkSelfConfig(tc); v == nil || v.Decision != policy.Deny {
			t.Errorf("%q -> %+v, want deny", p, v)
		}
	}
}

func TestGitCleanDryRun(t *testing.T) {
	for _, c := range []string{`git clean -n`, `git clean -nxd`, `git clean --dry-run -d`} {
		wantAllow(t, c, evalBash(t, c))
	}
	if v := evalBash(t, `git clean -fdx`); v == nil || v.Decision != policy.Deny {
		t.Errorf("git clean -fdx -> %+v, want deny", v)
	}
}
```

- [ ] **Step 2:** Run → fails on the tiers, the aggregation, the memory write, and the dry run.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** `git commit -m "feat(policy): secret_ask_globs tier, strongest-verdict aggregation, scoped .claude globs, git clean -n (M-2, M-3, M-6, NF-1)"`

---

### Task 4: Case-insensitive matching

**Files:** `internal/engine/rules_path.go`, tests.

**Defect (H-7).** On APFS/NTFS `~/.SSH/ID_RSA` opens the real key; matching is case-sensitive. Task 1 already made *containment* case-insensitive; this makes *glob matching* consistent with it.

- [ ] **Step 1: Test**

```go
func TestGlobMatchingIsCaseInsensitive(t *testing.T) {
	pol := pathPol()
	for _, p := range []string{"/home/u/.SSH/ID_RSA", "/home/u/.Ssh/id_rsa", "/repo/.ENV", "/home/u/.AWS/credentials"} {
		tc := ToolCall{Tool: "Read", Paths: []string{p}, CWD: "/repo", RepoRoot: "/repo"}
		if v := checkPaths(tc, pol); v == nil || v.Decision != policy.Deny {
			t.Errorf("Read %q -> %+v, want deny", p, v)
		}
	}
}
```
- [ ] **Step 2–3:** Run, implement.
- [ ] **Step 4:** `git commit -m "fix(engine): case-insensitive glob matching (H-7)"`

---

### Task 5: Recover flag-attached path values without corrupting them

**Files:** `internal/engine/rules_bash.go`, tests.

**Defect (CR-9, part 1).** `nonFlagArgs` drops `-f/home/u/.ssh/id_rsa` and `--file=/home/u/.ssh/id_rsa` entirely. Revision 3's proposed helper found the *first* `/` in `-f../secrets/id_rsa` and yielded `/secrets/id_rsa` — a corrupted path that matches nothing.

**Required behaviour.** A new `argPathValues(argv []string) []string` yields: every non-flag operand; the value of `--flag=value`; and for a short flag with an attached value, **everything after the flag letters**, intact — `..`, `.`, `~`, `\`, and `C:` drive prefixes preserved. Flag values that are not path-shaped (`--color=auto`, `-n5`) contribute nothing.

- [ ] **Step 1: Test**

```go
func TestArgPathValues(t *testing.T) {
	for _, c := range []struct {
		argv []string
		want string
	}{
		{[]string{"grep", "-f/home/u/.ssh/id_rsa", "x"}, "/home/u/.ssh/id_rsa"},
		{[]string{"grep", "-f../secrets/id_rsa", "x"}, "../secrets/id_rsa"},
		{[]string{"grep", "-f./id_rsa", "x"}, "./id_rsa"},
		{[]string{"grep", "-f~/.ssh/id_rsa", "x"}, "~/.ssh/id_rsa"},
		{[]string{"grep", `-fC:\Users\u\.ssh\id_rsa`, "x"}, `C:\Users\u\.ssh\id_rsa`},
		{[]string{"grep", "--file=../secrets/id_rsa"}, "../secrets/id_rsa"},
		{[]string{"sed", "-f/home/u/.ssh/id_rsa", "x"}, "/home/u/.ssh/id_rsa"}, // openssl's -in does not accept an attached value; sed -f does
		{[]string{"cat", "/home/u/.ssh/id_rsa"}, "/home/u/.ssh/id_rsa"},
	} {
		if got := argPathValues(c.argv); !slices.Contains(got, c.want) {
			t.Errorf("argPathValues(%q) = %q, want to contain %q", c.argv, got, c.want)
		}
	}
	for _, c := range []struct {
		argv    []string
		notWant string
	}{
		{[]string{"ls", "-la", "--color=auto"}, "auto"},
		{[]string{"head", "-n5", "file"}, "5"},
		{[]string{"grep", "-f../secrets/id_rsa"}, "/secrets/id_rsa"}, // the Revision 3 corruption
	} {
		if got := argPathValues(c.argv); slices.Contains(got, c.notWant) {
			t.Errorf("argPathValues(%q) = %q, must not contain %q", c.argv, got, c.notWant)
		}
	}
}
```
- [ ] **Step 2–3:** Run, implement.
- [ ] **Step 4:** `git commit -m "feat(engine): argPathValues recovers flag-attached paths intact (CR-9)"`

---

### Task 6: Every path-shaped operand is a candidate; patterns and filters are not

**Files:** `internal/engine/rules_path.go`, `internal/engine/rules_bash.go`, tests.

**Defect (CR-9, part 2).** `pathReaders` is a closed gate: `cp`, `base64`, `tar`, `openssl`, `dd` and everything unlisted read secrets freely. But ▶ `cat id_rsa` from `~/.ssh` denies today *because* of that list, and `looksLikePath("id_rsa")` is false — so the list must not be deleted. And ▶ `grep '*.pem' file` denies today because grep's *pattern* operand is treated as a path; with `jq` added as a reader, `jq '.env' file` would deny on `**/.env*`.

**Required behaviour.**
- The reader list becomes a **hint**, renamed `pathOperandCommands`, extended with `wc diff cmp file nl tac rev cut sort uniq tee base32 base64 md5sum sha1sum sha256sum cp mv install rsync scp tar zip gzip openssl gpg dd jq yq`. For a listed command every operand from `argPathValues` is a candidate, bare filenames included. For any other command an operand must be path-shaped (contains a separator or starts with `~`).
- **Program/pattern/filter operands are excluded.** For `grep`/`egrep`/`fgrep`: the token consumed by `-e`/`--regexp` is the pattern and is excluded; the token consumed by `-f`/`--file` **is a path** and is included; when neither flag is present the first non-flag operand is the pattern and is excluded. For `sed`: the token consumed by `-e` is the script (excluded), by `-f` a path (included); otherwise the first operand is the script. For `awk`: `-f` consumes a path; otherwise the first operand is the program. For `jq`/`yq`: the first operand is the filter. (▶ On HEAD, `grep -e '*.pem' file` denies because `*.pem` is seen as an operand — the `-e` value must be excluded explicitly, not just "first operand".)
- For `isOpaqueExecutor` commands, every `visiblePathCandidates` token that is path-shaped is a candidate. **Boundary, stated:** inside opaque source we match the literal presence of a secret path and do not distinguish access from mention; a `secret_dirs` path denies, an ambiguous one asks, source with no path is untouched.
- **`awk` is the exception to opaque scanning.** `isOpaqueExecutor` lists awk, but an awk *program* is a pattern language whose `/regex/` delimiters look like paths — `awk '/id_rsa/ {print}'` would extract `/id_rsa/` and deny. The awk program operand (first non-flag operand unless `-f` is given) is excluded from both operand scanning and opaque-source scanning; `awk -f <file>` treats `<file>` as a path. This is a deliberate, tested carve-out from the mention-equals-access boundary.
- Redirects and `writeTargets` unchanged.

- [ ] **Step 1: Tests**

```go
func TestSecretReadsViaAnyCommand(t *testing.T) {
	pol := pathPol()
	for _, c := range []string{
		`cp /home/u/.ssh/id_rsa /tmp/x`, `mv /home/u/.ssh/id_rsa /tmp/x`,
		`base64 /home/u/.aws/credentials`, `tar cf - /home/u/.ssh/id_rsa`,
		`openssl rsa -in /home/u/.ssh/id_rsa`, `md5sum /home/u/.ssh/id_rsa`,
		`dd if=/home/u/.ssh/id_rsa`, `grep -f/home/u/.ssh/id_rsa x`, `grep -f../.ssh/id_rsa x`,
		`somenewtool /home/u/.ssh/id_rsa`, // unlisted command, path-shaped operand
		`python3 -c "print(open('/home/u/.ssh/id_rsa').read())"`,
		`python3 -c "print('/home/u/.ssh/id_rsa')"`, // mention == access, by decision
		`node -e "require('fs').readFileSync('/home/u/.ssh/id_rsa')"`,
	} {
		tc := ToolCall{Tool: "Bash", Command: c, CWD: "/repo", RepoRoot: "/repo"}
		if v := checkPaths(tc, pol); v == nil || v.Decision != policy.Deny {
			t.Errorf("%q -> %+v, want deny", c, v)
		}
	}
}

func TestBareFilenameReadsAreNotRegressed(t *testing.T) {
	// ▶ `cat id_rsa` and `head -n1 id_rsa` deny on HEAD and on the deployed
	// binary — those two are REGRESSION LOCKS. `base64` and `cp` are new
	// coverage from the extended reader list; on HEAD they allow.
	pol := pathPol()
	for _, c := range []string{`cat id_rsa`, `head -n1 id_rsa`, `base64 id_rsa`, `cp id_rsa /tmp/x`} {
		tc := ToolCall{Tool: "Bash", Command: c, CWD: "/home/u/.ssh", RepoRoot: "/repo"}
		if v := checkPaths(tc, pol); v == nil || v.Decision != policy.Deny {
			t.Errorf("%q (cwd ~/.ssh) -> %+v, want deny", c, v)
		}
	}
}

func TestPatternAndFilterOperandsAreNotPaths(t *testing.T) {
	pol := pathPol()
	for _, c := range []string{
		`grep '*.pem' /repo/build.log`, // ▶ denies today — this is a fix
		`grep -r id_rsa /repo/src`,     // pattern, not a file
		`grep -e '*.pem' /repo/build.log`,
		`jq '.env' /repo/pkg.json`,
		`jq '.ssh.keys[]' /repo/cfg.json`,
		`sed 's/.env/.cfg/' /repo/a.txt`,
		`awk '/id_rsa/ {print}' /repo/log`,
		`printf '%s.key\n' name`,
		`echo "id_rsa is a filename"`,
		`go build ./...`, `npm test`, `cp src/a.go src/b.go`, `docker compose up -d`,
	} {
		tc := ToolCall{Tool: "Bash", Command: c, CWD: "/repo", RepoRoot: "/repo"}
		wantAllow(t, c, checkPaths(tc, pol))
	}
	// -f makes the pattern come from a file, so that operand IS a path again
	tc := ToolCall{Tool: "Bash", Command: `grep -f /home/u/.ssh/id_rsa /repo/log`, CWD: "/repo", RepoRoot: "/repo"}
	if v := checkPaths(tc, pol); v == nil || v.Decision != policy.Deny {
		t.Errorf("grep -f <secret> -> %+v, want deny", v)
	}
}

func TestOperandRolesUnderOptionOrderAndTerminators(t *testing.T) {
	pol := pathPol()
	allow := []string{
		`grep /repo/build.log -e '*.pem'`,           // late -e: pattern still excluded
		`sed /repo/a.txt -e 's/.env/.cfg/'`,         // late -e: script still excluded
		`jq --arg k '.env' '.[$k]' /repo/x.json`,    // --arg value and filter are not paths
		`tar --exclude='*.pem' -cf /tmp/a.tar /repo/src`, // exclusion pattern is not a path
		`awk -F: '/id_rsa/' /repo/passwd.txt`,       // program excluded even with a preceding flag
	}
	for _, c := range allow {
		tc := ToolCall{Tool: "Bash", Command: c, CWD: "/repo", RepoRoot: "/repo"}
		wantAllow(t, c, checkPaths(tc, pol))
	}
	deny := []string{
		`jq -f /home/u/.ssh/id_rsa /repo/x.json`,  // -f is a path, unlike --arg
		`awk -f /home/u/.ssh/id_rsa /repo/log`,    // -f is a path; program operand rule does not apply
		`cat -- /home/u/.ssh/id_rsa`,              // -- terminates options; operand is still a path
		`grep -- id_rsa /home/u/.ssh/id_rsa`,      // pattern after --, then a real secret path
	}
	for _, c := range deny {
		tc := ToolCall{Tool: "Bash", Command: c, CWD: "/repo", RepoRoot: "/repo"}
		if v := checkPaths(tc, pol); v == nil || v.Decision != policy.Deny {
			t.Errorf("%q -> %+v, want deny", c, v)
		}
	}
}

func TestDDInputFollowsSymlinks(t *testing.T) {
	root := t.TempDir()
	secret := filepath.Join(root, "outside", "id_rsa")
	if err := os.MkdirAll(filepath.Dir(secret), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(secret, []byte("k"), 0o600); err != nil {
		t.Fatal(err)
	}
	repo := filepath.Join(root, "repo")
	if err := os.MkdirAll(repo, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(repo, "innocent.bin")
	if err := os.Symlink(secret, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	tc := ToolCall{Tool: "Bash", Command: "dd if=" + link + " of=/tmp/x", CWD: repo, RepoRoot: repo}
	if v := checkPaths(tc, pathPol()); v == nil || v.Decision != policy.Deny {
		t.Errorf("dd if=<symlink to secret> -> %+v, want deny", v)
	}
}

func TestOpaqueSourceBoundary(t *testing.T) {
	pol := pathPol()
	tc := ToolCall{Tool: "Bash", Command: `python3 -c "print('/repo/docs/cert.pem')"`, CWD: "/repo", RepoRoot: "/repo"}
	if v := checkPaths(tc, pol); v == nil || v.Decision != policy.Ask {
		t.Errorf("ambiguous path in source -> %+v, want ask", v)
	}
	tc = ToolCall{Tool: "Bash", Command: `python3 -c "print('hello world')"`, CWD: "/repo", RepoRoot: "/repo"}
	wantAllow(t, "ordinary source", checkPaths(tc, pol))
}
```

- [ ] **Step 2:** Run → the deny set allows; `grep '*.pem'` denies; bare-filename set passes (must keep passing).
- [ ] **Step 3:** Implement. Run the full suite verbosely; this is the highest false-positive-risk task in the phase.
- [ ] **Step 4:** `git commit -m "fix(engine): scan path-shaped operands of any command; exclude pattern/filter operands (CR-9)"`

---

### Task 7: Corpus, docs, tag

- [ ] **Step 1: Corpus.** Corpus `want` values are **whole-Engine verdicts**, not focused-check results. Every `deny` above as `deny`. Every `wantAllow` case as `allow` **except** where a sibling rule fires under full evaluation: `Write /etc/CLAUDE.md` and `Write ~/.claude/projects/x/memory/note.md` are out-of-repo writes and receive `P5.out-of-repo` → record them as `ask`, with a note that self-config no longer fires. The M-3 examples as `ask`; the aggregation case `cat /repo/docs/cert.pem /home/u/.ssh/id_rsa` as `deny`; `cat id_rsa` and `cp id_rsa /tmp/x` with cwd `~/.ssh` as `deny`; `grep '*.pem' /repo/build.log` as `allow` (a fix to an existing false positive — note it as such).
- [ ] **Step 2: Docs.** `guardrail.toml.example` gains commented `secret_dirs` and `secret_ask_globs`. `CONTEXT.md`'s **Guardrail Policy** entry names the three secret tiers (directory → deny unwaivable; file → deny waivable; ambiguous → ask).
- [ ] **Step 3:** `make check && /usr/local/go/bin/go test ./... -count=1` → green, zero corpus entries relaxed.
- [ ] **Step 4:** Annotate the review `**[FIXED — Phase 4]**` on CR-9/RC4, H-2, H-7, M-2, M-3, M-4, M-5, M-6, NF-1. Update the response-report ledger. **H-6, H-10, M-7 remain open** — Phase 5.
- [ ] **Step 5:**
```bash
git add -A && git commit -m "docs: Phase 4 landed — path matching corrected; H-6/H-10/M-7 remain"
git push origin main && git tag v0.13.0-dev && git push origin v0.13.0-dev
```

> Do **not** describe the review as fully closed. Do **not** bump the installer pins — chezmoi repo, Carlitos's call.

---

## Self-Review

**Coverage.** M-4/M-5 → T1. H-2 → T2. M-2, M-3, M-6, NF-1, aggregation → T3. H-7 → T4 (with containment in T1). CR-9 → T5 + T6. H-6/H-10/M-7 → Phase 5.

**Ordering.** T1 → T2 → T3 → T5 → T6; T4 after T1. T3 before T6 (T6's tests assert the ask tier). T2 before T3 (the `*.pub` allow is only safe once `secret_dirs` is unwaivable).

**Residual risk, stated.** A bare-filename operand of an *unlisted* command (`somenewtool id_rsa` from `~/.ssh`) is not a candidate. `writeTargets` is still a fixed list. Opaque-source matching cannot tell access from mention — by decision. Moving `*.pem`/`service-account*.json` to `ask` is a **deliberate reduction in strictness for in-repo certificates**; `secret_dirs` still denies. Reversible by one list move; flagged for Carlitos.

**What this revision does not contain.** Implementation code. The executor has found fourteen errors in three revisions of it, every one by running something the author only read. The tests are the contract.

---

## Revision History

### Revision 4 → 5 (two wrong tests, seven omissions; all confirmed)

**Wrong tests.** (1) `awk '/id_rsa/ {print}' f` cannot be `allow` under the mention-equals-access boundary — awk is an opaque executor and `/id_rsa/` extracts as a path. Resolved by carving awk's program operand out of opaque scanning, explicitly. (2) `openssl rsa -in/path` is not valid OpenSSL (`Unknown cipher: in/path`); the attached-value helper test now uses `sed -f/path`.

**Omissions.** (3) **Declarative floors:** `genconfig/claude.go:62` builds the native deny list from `Slots.SecretGlobs` only, so moving `.ssh` into `secret_dirs` would drop it from `settings.json`. Tasks 2 and 3 now require the generators, goldens and unit tests to follow the tiers. (4) A global ask tier downgrades `/home/u/certs/client.pem` — the tier is now **in-repo only**; outside the repo it denies. (5) `.envrc` root-only weakened nested direnv files — now `**/.envrc`. (6) `**/*_rsa` does not cover `id_rsa_work`; the suffix-preserving `**/id_rsa*` family is retained explicitly. (7) Aggregation tests now cover ask-vs-symlink-escape, ask-vs-self-config through `Evaluate`, waiver interaction, and both orders. (8) Operand-role tests now cover late `-e`, `jq -f` vs `--arg`, `tar --exclude`, `--`, `dd if=` through a symlink. (9) Corpus wants are whole-Engine verdicts: `/etc/CLAUDE.md` and out-of-repo memory writes are `P5.out-of-repo` **ask**, not allow.

### Revision 3 → 4 (four findings + one scope omission, all confirmed)

1. **The `ask` tier could downgrade a later deny.** `checkPaths` returns on the first classified candidate; `cat /repo/docs/cert.pem /home/u/.ssh/id_rsa` would return `ask`. Now: strongest verdict across all candidates (T3).
2. **The reader hint treated patterns and filters as paths.** `grep '*.pem' f` → ask, `jq '.env' f` → deny. ▶ The grep case denies on the deployed binary *today*. Now: first operand of grep/sed/awk/jq is excluded unless a flag moves it (T6). Revision 3's "not deny" assertions would have hidden the `ask`; now `wantAllow` is strict.
3. **`argPathValues` corrupted attached relative paths.** `-f../secrets/id_rsa` → `/secrets/id_rsa`. Now: everything after the flag letters, intact, with Windows drive prefixes (T5).
4. **Containment was case-sensitive while matching was not.** `repoRelative("/REPO/CLAUDE.md", …, "/repo")` rejected the path before Task 4 ran. Now: containment case-insensitive (T1).
5. **Tasks 2 and 3 omitted the policy schema files.** A new slot touches `base.go`, `policy.go`, `config.go`, `merge.go` and tests. Now listed.

### Revision 2 → 3 (five findings)

1. `matchesScoped` tested only the lexical path against root-only globs; a symlink to `/repo/CLAUDE.md` slipped through. 2. `repoRelative` broke for repoRoot `/` (`root+"/"` = `"//"`). 3. Task 3 claimed M-3 fixed while keeping `**/*.pem` and `**/service-account*.json`. 4. Deleting `pathReaders` regressed ▶ `cat id_rsa` from `~/.ssh`. 5. The opaque-source boundary was undefined.

### Revision 1 → 2 (five findings)

1. Removing the basename fallback does not fix H-2 (`**/.env.example` matches the full path). 2. `**/*.key` still matches `i18n/translations.key`. 3. Adding a repo-relative form alongside the raw match leaves relative `CLAUDE.md` denied from any cwd. 4. Scanning every argument misses `-f/path` and adds false positives. 5. H-6/H-10/M-7 were not closable in one phase.

### The lessons

- Verify glob and path behaviour by executing it. `**/` matches zero segments; `root+"/"` is `"//"` at root; `filepath.Rel` returns `../…` not an error; `IndexAny("/~")` finds the wrong slash in `../x`.
- Probe the deployed binary for what already works before changing a gate.
- Allow means allow — never assert "not deny".
- **A plan author who cannot run the code should not write the code.** Specify behaviour; let the side with ground truth implement.
