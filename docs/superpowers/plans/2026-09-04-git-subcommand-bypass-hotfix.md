# `git -C`/`-c` Subcommand-Parsing Bypass Hotfix — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix `gitSubcommand` so `git -C <path> <verb>` and `git -c <key>=<value> <verb>` (repeatable `-c`) are parsed correctly instead of returning the flag's *value* as if it were the subcommand — a bug that currently bypasses **all** git-safety rules (P1's `push --force`/`clean -f`, live in the installed `v0.3.1`, and every P2 rule from Plan 4) for any git invocation prefixed with `-C` or `-c`. Ship a real point release and recommend bumping the installer pin.

**Architecture:** One function fix in `internal/engine`, shared by both `checkGit` (P1) and `checkGitSafety` (P2) since both call `gitSubcommand`. A comprehensive regression matrix locks every git rule against `{bare, -C ., -c x=y, both}` prefixes so this class of bug can't silently reopen. No architecture change.

**Tech Stack:** Go 1.23+, no new dependencies, no new files beyond tests.

**Spec:** Plan 4's escalated finding (`docs/superpowers/plans/2026-09-04-git-safety-fs-scope-egress.md`, "Parked gaps" #1). `../../../DESIGN.md` — this closes part of the long-standing "`git -C`/`-c` parsing" gap tracked since Plan 1; the *separate* concern of validating what `-C <path>` points at (operating on a different repo entirely) stays parked, unrelated to this bug.

## Global Constraints

- **Scope is exactly the parsing bug.** Do not expand into validating `-C`'s target path (that's the separate, harder "git -C escape to a different repo" gap — still parked).
- The fix must not change behavior for any command that was already correctly classified — this is a **monotonic widening** (previously-missed denies/asks now fire; nothing that was denied/asked becomes allowed).
- Every code step is literal. `gofmt -w` before every commit. Conventional Commits, one commit per task.
- Verified current buggy code (`internal/engine/rules_bash.go`, introduced Plan 1 Task 7, unchanged since):
  ```go
  func gitSubcommand(argv []string) string {
  	for _, a := range argv[1:] {
  		if strings.HasPrefix(a, "-") {
  			continue
  		}
  		if a == "-C" { // dead code: -C already matched the HasPrefix branch above
  			continue
  		}
  		return a
  	}
  	return ""
  }
  ```
  Called by `checkGit` (P1, Plan 1) and `checkGitSafety` (P2, Plan 4) — both `func(s Simple) *policy.Verdict`, both do `sub := gitSubcommand(s.Argv)` then `switch sub { ... }`.

---

### Task 1: Fix `gitSubcommand` to skip `-C <path>` and `-c <key>=<val>`

**Files:**
- Modify: `internal/engine/rules_bash.go`
- Modify: `internal/engine/rules_bash_test.go` (or wherever `gitSubcommand` is currently tested — search for it; add if untested)

**Interfaces:**
- `func gitSubcommand(argv []string) string` — same signature, corrected body: walks `argv[1:]` by index; `-C` and `-c` (and, defensively, `--namespace`) each consume **two** tokens (the flag and its value) before continuing; any other token starting with `-` (single-token flags, including `--flag=value` forms like `--git-dir=x`) consumes one; the first token not starting with `-` is returned as the subcommand.

- [ ] **Step 1: Write the failing test**

Add to `internal/engine/rules_bash_test.go` (or create `internal/engine/rules_git_subcommand_test.go` if `gitSubcommand` has no direct test yet):

```go
func TestGitSubcommandSkipsValueFlags(t *testing.T) {
	cases := []struct {
		argv []string
		want string
	}{
		{[]string{"git", "push"}, "push"},
		{[]string{"git", "-C", ".", "push"}, "push"},
		{[]string{"git", "-c", "user.email=x@y", "push"}, "push"},
		{[]string{"git", "-C", "/tmp/other-repo", "-c", "a=b", "push", "--force"}, "push"},
		{[]string{"git", "-c", "a=1", "-c", "b=2", "config", "user.email", "x"}, "config"},
		{[]string{"git", "--git-dir=/tmp/x", "push"}, "push"},
		{[]string{"git", "-p", "log"}, "log"},
		{[]string{"git"}, ""},
		{[]string{"git", "-C"}, ""}, // malformed (missing value) must not panic or misparse
	}
	for _, c := range cases {
		if got := gitSubcommand(c.argv); got != c.want {
			t.Errorf("gitSubcommand(%v) = %q, want %q", c.argv, got, c.want)
		}
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `/usr/local/go/bin/go test ./internal/engine/ -run TestGitSubcommandSkipsValueFlags -v`
Expected: FAIL — `git -C . push` and `git -c user.email=x@y push` return `"."` / `"user.email=x@y"` instead of `"push"`.

- [ ] **Step 3: Write minimal implementation**

Replace `gitSubcommand` in `internal/engine/rules_bash.go`:

```go
// gitSubcommand returns the git subcommand (e.g. "push", "config"), correctly
// skipping global options that take a separate value token — "-C <path>" and
// "-c <key>=<value>" (repeatable) — before it. Getting this wrong previously
// made "git -C . push --force" return "." as the subcommand, silently
// bypassing every git-safety rule (checkGit and checkGitSafety both key off
// this function's return value).
func gitSubcommand(argv []string) string {
	valueFlags := map[string]bool{"-C": true, "-c": true, "--namespace": true}
	for i := 1; i < len(argv); {
		a := argv[i]
		if !strings.HasPrefix(a, "-") {
			return a
		}
		if valueFlags[a] {
			i += 2
			continue
		}
		i++
	}
	return ""
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `/usr/local/go/bin/go test ./internal/engine/ -run TestGitSubcommandSkipsValueFlags -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
gofmt -w internal/engine/
git add internal/engine/
git commit -m "fix(engine): gitSubcommand skips -C/-c value flags — closes a total git-safety bypass"
```

---

### Task 2: Regression matrix — every git rule × every `-C`/`-c` prefix

**Files:**
- Modify: `internal/engine/rules_git_test.go` (P2 rules) and `internal/engine/rules_bash_test.go` (P1's `checkGit`)

**Interfaces:**
- A table-driven test iterating every existing git-rule test case with four prefix variants prepended to the command: `""`, `"-C . "`, `"-c a.b=c "`, `"-C . -c a.b=c "` — reusing `evalGitSafety`/`evalBash`-style harnesses already in those files. Every case must resolve to the **same** `Decision` + `RuleID` regardless of prefix.

- [ ] **Step 1: Write the failing test**

Add to `internal/engine/rules_git_test.go`:

```go
func TestGitRulesSurvivePrefixes(t *testing.T) {
	prefixes := []string{"", "-C . ", "-c a.b=c ", "-C . -c a.b=c "}
	cases := map[string]struct {
		decision policy.Decision
		ruleID   string
	}{
		"git push --force origin main": {policy.Deny, "P1.git-push-force"},
		"git clean -fd":                 {policy.Deny, "P1.git-clean"},
		"git reset --hard":              {policy.Deny, "P2.git-reset-hard"},
		"git config user.email x@y.com": {policy.Deny, "P2.git-config-write"},
		"git checkout .":                {policy.Ask, "P2.git-checkout-restore"},
		"git branch -D feature/x":       {policy.Ask, "P2.git-branch-delete"},
		"git commit --amend":            {policy.Ask, "P2.git-history-rewrite"},
		"git remote add origin https://x": {policy.Ask, "P2.git-remote-add"},
		"git stash clear":               {policy.Ask, "P2.git-stash-clear"},
		"git push origin main":          {policy.Ask, "P2.git-push-protected"},
	}
	for cmd, want := range cases {
		for _, pfx := range prefixes {
			full := "git " + pfx + cmd[len("git "):]
			v := evalGitSafety(t, full)
			if v == nil {
				t.Errorf("%q -> nil, want %s/%s", full, want.decision, want.ruleID)
				continue
			}
			if v.Decision != want.decision || v.RuleID != want.ruleID {
				t.Errorf("%q -> %s/%s, want %s/%s", full, v.Decision, v.RuleID, want.decision, want.ruleID)
			}
		}
	}
}
```

- [ ] **Step 2: Run the test to verify it fails without the Task 1 fix, passes with it**

Run: `/usr/local/go/bin/go test ./internal/engine/ -run TestGitRulesSurvivePrefixes -v`
Expected: PASS (Task 1 is already applied at this point in the plan — this step is confirming the fix's coverage is complete, not re-deriving it). If any case fails, the prefix construction or a rule's flag-detection (not just `gitSubcommand`) has a second gap — investigate before proceeding; do not weaken the test.

- [ ] **Step 3: Add the non-panic / no-false-positive guard**

Add to the same file:

```go
func TestGitPrefixesDontCreateFalsePositives(t *testing.T) {
	prefixes := []string{"", "-C . ", "-c a.b=c "}
	safe := []string{"git status", "git log --oneline -5", "git diff", "git fetch"}
	for _, cmd := range safe {
		for _, pfx := range prefixes {
			full := "git " + pfx + cmd[len("git "):]
			if v := evalGitSafety(t, full); v != nil {
				t.Errorf("%q -> %+v, want nil", full, v)
			}
		}
	}
}
```

- [ ] **Step 4: Run the full engine suite**

Run: `/usr/local/go/bin/go test ./internal/engine/ -v`
Expected: PASS, all tests including the new matrix and false-positive guard.

- [ ] **Step 5: Commit**

```bash
gofmt -w internal/engine/
git add internal/engine/
git commit -m "test: git-safety regression matrix — every rule x every -C/-c prefix combination"
```

---

### Task 3: End-to-end contract fixture + full suite

**Files:**
- Create: `test/fixtures/claude/git-c-bypass.json`
- Modify: `test/fixtures/claude/expected.json`

**Interfaces:**
- One fixture proving the fix through the real `guardrail hook claude` path, not just the unit-level `checkBash`.

- [ ] **Step 1: Write the fixture**

`test/fixtures/claude/git-c-bypass.json`:
```json
{"session_id":"s1","cwd":"/tmp","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"git -C . push --force origin main"}}
```

- [ ] **Step 2: Add to `expected.json`**

Add the entry `"git-c-bypass.json": {"exit": 2}` to `test/fixtures/claude/expected.json`.

- [ ] **Step 3: Run the contract + full suite**

Run: `make check && make contract && /usr/local/go/bin/go test ./...`
Expected: all green, vet clean, gofmt clean. The new fixture exits 2 (denied — was previously exit 0, the bypass).

- [ ] **Step 4: Commit**

```bash
git add test/fixtures/claude/
git commit -m "test: contract fixture proving git -C . push --force is now denied end-to-end"
```

---

### Task 4: Release `v0.4.1`

**Files:** none (release action).

- [ ] **Step 1: Push, confirm CI**

```bash
git push origin main
gh run list --branch main --limit 2   # CI: completed / success
```

- [ ] **Step 2: Tag and release**

```bash
git tag v0.4.1
git push origin v0.4.1
gh run list --workflow Release --limit 1   # completed / success
gh release view v0.4.1                      # 7 assets: 6 binaries + SHA256SUMS
```

- [ ] **Step 3: Spot-check**

```bash
gh release download v0.4.1 -p 'guardrail_linux_amd64' -p SHA256SUMS -D /tmp/grv41
( cd /tmp/grv41 && sha256sum -c --ignore-missing SHA256SUMS )
/tmp/grv41/guardrail_linux_amd64 version   # -> guardrail v0.4.1
echo '{"cwd":"/tmp","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"git -C . push --force origin main"}}' \
  | /tmp/grv41/guardrail_linux_amd64 hook claude; echo "exit=$?"   # expect exit=2
```
Expected: checksum `OK`, version `v0.4.1`, the live bypass command now exits `2`.

---

### Task 5: Bump the installer's pinned version (chezmoi, direct commit)

**Files (in `~/.local/share/chezmoi`):**
- Modify: `run_onchange_install_packages.sh.tmpl` (`GUARDRAIL_VERSION`)
- Modify: `run_onchange_install_packages.ps1.tmpl` (`$guardrailVersion`)
- Modify: `scripts/update_ai_tools.sh` (`GUARDRAIL_VERSION`)
- Modify: `scripts/update_ai_tools.ps1` (`$guardrailVersion`)

- [ ] **Step 1: Bump all four**

```bash
cd ~/.local/share/chezmoi
git checkout main && git pull --ff-only
sed -i 's/GUARDRAIL_VERSION="v0.3.1"/GUARDRAIL_VERSION="v0.4.1"/' run_onchange_install_packages.sh.tmpl scripts/update_ai_tools.sh
sed -i 's/\$guardrailVersion = "v0.3.1"/$guardrailVersion = "v0.4.1"/' run_onchange_install_packages.ps1.tmpl scripts/update_ai_tools.ps1
grep -rn 'GUARDRAIL_VERSION\|guardrailVersion' run_onchange_install_packages.sh.tmpl run_onchange_install_packages.ps1.tmpl scripts/update_ai_tools.sh scripts/update_ai_tools.ps1
```
Expected: all four now show `v0.4.1`; no stray `v0.3.1` remains in these four files.

- [ ] **Step 2: Validate render**

```bash
chezmoi execute-template < run_onchange_install_packages.sh.tmpl > /tmp/rendered.sh && grep 'GUARDRAIL_VERSION=' /tmp/rendered.sh
```
Expected: `GUARDRAIL_VERSION="v0.4.1"`.

- [ ] **Step 3: Commit directly to `main`**

This is a one-line-times-four data change to an already-reviewed, already-landed installer (Plan 3b) — no new logic, no toggle change. Safe for a direct commit (not a branch), same as any other version-pin bump in this repo (`ANTIGRAVITY_VERSION`, `LAZYGIT_VERSION` pattern).

```bash
git add run_onchange_install_packages.sh.tmpl run_onchange_install_packages.ps1.tmpl scripts/update_ai_tools.sh scripts/update_ai_tools.ps1
git commit -m "packages: bump pinned guardrail to v0.4.1 (closes a git -C/-c safety bypass, see agent-guardrails v0.4.1)"
```

- [ ] **Step 4: Leave `chezmoi apply` for Carlitos**

Print, do not run:

```
Installer now pins guardrail v0.4.1 (was v0.3.1). To pick it up:

  cd ~/.local/share/chezmoi
  chezmoi diff      # expect: guardrail re-downloaded + settings.json re-merged (safe, idempotent)
  chezmoi apply
  guardrail version  # expect: guardrail v0.4.1
  guardrail doctor   # expect: "guardrail hook registered", no WARNING
```

---

## Self-Review

**1. Spec coverage.** The escalated finding (Plan 4 parked gap #1) is fully addressed: `gitSubcommand` fixed (Task 1), proven across every existing git rule and both prefix forms including combined/repeated `-c` (Task 2), proven end-to-end through the real hook path (Task 3), shipped as a real release (Task 4), and the currently-installed version is scheduled to move off the vulnerable `v0.3.1` (Task 5). Explicitly **not** in scope: validating what a `-C <path>` target actually points at (the separate "operate on a different repo via -C" gap) — still parked, unaffected by this fix.

**2. Placeholder scan.** No `TBD`/"handle appropriately". Every test case is literal; the malformed-input case (`git -C` with no value) is included specifically because a naive index-based fix can panic or double-skip past the end of `argv` — the implementation's `for i < len(argv)` loop bound guards this, and the test locks it in.

**3. Type consistency.** `gitSubcommand(argv []string) string` — signature unchanged (Task 1), so `checkGit` and `checkGitSafety` need no changes at their call sites. No other function's signature or the `Simple`/`ToolCall`/`Verdict` types are touched.

---

## Execution Handoff

**Plan complete and saved to `docs/superpowers/plans/2026-09-04-git-subcommand-bypass-hotfix.md`. Given the severity, recommend executing this ahead of Plan 4b regardless of which approach:**

**1. Subagent-Driven (recommended)** — fresh subagent per task via `superpowers:subagent-driven-development`.

**2. Inline Execution** — `superpowers:executing-plans`, batch with checkpoints.

**Which approach?**
