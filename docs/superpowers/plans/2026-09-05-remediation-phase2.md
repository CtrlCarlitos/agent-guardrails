# Adversarial Remediation — Phase 2: Token Normalization, Part 2

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the remaining reproduced bypasses from `docs/reviews/2026-09-04-adversarial-review.md` that need real parsing work rather than a table or a one-liner — `cd` tracking, redirect-only statements, git global-option and refspec parsing, docker argument parsing, the deny→ask downgrade, the wrapper/privesc list holes, and the uncovered destructive primitives.

**Architecture:** No new subsystems. This builds directly on Phase 1's foundations: `Simple.Unresolved` (the fail-closed marker), `head()` (basename matching), and the `consumeX` option-consumer pattern already established in `stripAndUnwrap`. The largest conceptual change is threading a *running working directory* through a command's statements so relative operands resolve against where the shell will actually be, not where the hook was invoked.

**Tech Stack:** Go 1.23+, existing deps only.

**Spec:** `../reviews/2026-09-04-adversarial-review.md`. Findings addressed: **CR-3, CR-4, CR-5, CR-6, CR-13, H-1, H-3, H-4**, plus the one evidence gap the remediation response flagged under H-5 (an authorized `SecretAllow` combined with an in-repository symlink escape has no regression lock).

**Prerequisite:** Phases 1 and 3 have landed (`v0.9.0-dev`, `v0.11.0-dev`). This plan was written against the post-Phase-1 tree and its literal code matches it.

## Global Constraints

- **Every fix ships with an entry in `test/adversarial/corpus.json`** (147 entries today: 113 deny / 29 allow / 5 ask). A fix without its lock is not done. Never relax an existing entry to get green — if one starts failing, that is a finding.
- **Fail closed, but do not over-deny.** Several fixes here broaden matching; each task adds `"want": "allow"` corpus entries for the adjacent legitimate cases so an over-correction shows up as a red test rather than as friction found later in daily use.
- **Reuse Phase 1's machinery.** `Unresolved` is the established way to say "cannot verify — fail closed"; `head()` is the established way to compare a command name; the `consumeX(argv []string) ([]string, error)` helpers are the established way to skip a wrapper's own options and fail closed on an unrecognized one. Do not invent parallel mechanisms.
- Every code step is literal. `gofmt -w` before every commit. Conventional Commits, one commit per task.
- **Out of scope** (Phase 4): inverting the closed allowlists (`pathReaders` → every argument; complete `writeCandidates` coverage), unknown-tool default-deny, WebFetch/WebSearch egress gating, `secret_allow` basename fallback, case-insensitive matching, and the M-2..M-7 false positives.
- Verified current state (read from the tree, not memory): `Simple{Argv, Redirects, Unresolved}` (`tokenize.go:10`); `head(argv []string) string` (`rules_bash.go:12`); `stripAndUnwrap` switches on `head(argv)` over `env/timeout/nice/nohup/xargs/exec/command/time/eval/builtin` with `consumeX` helpers that return an error on an unrecognized option (`tokenize.go`); `gitSubcommand` **and** `gitSubcommandArg` each hold their own `valueFlags := map[string]bool{"-C","-c","--namespace"}` (`rules_bash.go:139`, `:161`); `checkDocker` prefix-matches `strings.Join(s.Argv[1:], " ")` (`rules_bash.go`); `shellDashC` covers `sh,bash,zsh,dash,ksh` (`tokenize.go`); `checkBash` returns a single `tokenize-failed` Ask for the whole call on any `Normalize` error.

---

### Task 1: H-1 — a failing statement must not downgrade another statement's deny

**Files:** Modify `internal/engine/tokenize.go`, `internal/engine/rules_bash.go`, and their tests

**Interfaces:** `Normalize` stops aborting the whole command when one statement's wrapper parsing fails. A parse failure of the *source* (`syntax.Parse`) still returns an error — nothing is knowable then. But a per-statement `stripAndUnwrap` error now marks that statement `Unresolved` and keeps it (with its un-stripped argv) in the result, so the other statements are still evaluated and Phase 1 Task 2's `P3.unresolved` Ask covers the unknowable one.

- [ ] **Step 1: Write the failing test**

```go
func TestFailingStatementDoesNotMaskAnotherDeny(t *testing.T) {
	// `env -Z x` is an unrecognized env option -> that statement is unknowable.
	// The rm -rf / in the same command must still deny.
	for _, c := range []string{`rm -rf /; env -Z x`, `env -Z x; rm -rf /`} {
		v := evalBash(t, c)
		if v == nil || v.Decision != policy.Deny {
			t.Errorf("%q -> %+v, want deny (a junk wrapper must not soften a real deny)", c, v)
		}
	}
}

func TestUnknowableStatementAloneStillAsks(t *testing.T) {
	v := evalBash(t, `env -Z x`)
	if v == nil || v.Decision != policy.Ask {
		t.Fatalf("-> %+v, want ask", v)
	}
}

func TestSourceParseFailureStillFailsClosed(t *testing.T) {
	v := evalBash(t, `echo "unterminated`)
	if v == nil || v.Decision != policy.Ask || v.RuleID != "tokenize-failed" {
		t.Fatalf("-> %+v, want ask/tokenize-failed", v)
	}
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `/usr/local/go/bin/go test ./internal/engine/ -run 'TestFailingStatement|TestUnknowable|TestSourceParse' -v`
Expected: FAIL — `rm -rf /; env -Z x` currently returns a single `tokenize-failed` Ask.

- [ ] **Step 3: Implement**

In `internal/engine/tokenize.go`, change `Normalize` so a per-simple error degrades that simple instead of aborting:

```go
func Normalize(command string) ([]Simple, error) {
	base, err := splitSimples(command)
	if err != nil {
		return nil, err // the source itself does not parse: nothing is knowable
	}
	var out []Simple
	for _, s := range base {
		expanded, err := stripAndUnwrap(s)
		if err != nil {
			// This statement's wrappers could not be understood. Keep it,
			// marked unknowable, so sibling statements are still evaluated
			// and P3.unresolved covers this one. (review H-1)
			degraded := s
			degraded.Unresolved = true
			out = append(out, degraded)
			continue
		}
		out = append(out, expanded...)
	}
	return out, nil
}
```

- [ ] **Step 4: Run + prove**

Run: `/usr/local/go/bin/go test ./internal/engine/ -v` → PASS. Then:
```bash
/usr/local/go/bin/go build -o /tmp/gr ./cmd/guardrail
printf '%s' '{"cwd":"/repo","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"rm -rf /; env -Z x"}}' \
  | env XDG_STATE_HOME=$(mktemp -d) GUARDRAIL_CONFIG= /tmp/gr hook claude >/dev/null 2>&1; echo "exit=$?"
```
Expected: `exit=2` (was 0 with an ask).

- [ ] **Step 5: Commit**

```bash
gofmt -w internal/engine/ && git add internal/engine/
git commit -m "fix(engine): a statement that fails to normalize no longer downgrades a sibling statement's deny (H-1)"
```

---

### Task 2: CR-5 — one shared git global-option table, fail closed on the unknown

**Files:** Modify `internal/engine/rules_bash.go`, `internal/engine/rules_git.go`, and their tests

**Interfaces:**
- `var gitValueFlags = map[string]bool{"-C","-c","--namespace","--git-dir","--work-tree","--exec-path","--attr-source","--super-prefix","--config-env"}` — one package-level map, replacing the two duplicated literals in `gitSubcommand` and `gitSubcommandArg`.
- Both functions consume two tokens for a `gitValueFlags` entry, one for any other `-`-prefixed token, and return the first non-flag token.
- **New:** `gitSubcommandUnknownFlag(argv []string) string` returns the first `--`-prefixed token before the subcommand that is neither in `gitValueFlags` nor a known valueless global (`--no-pager`, `--paginate`, `-P`, `--bare`, `--literal-pathspecs`, `--no-replace-objects`, `--help`, `--version`). `checkGitSafety` returns `ask` (`P2.git-unknown-global`) when one is present, so a future git option cannot silently reopen this class.

- [ ] **Step 1: Write the failing test**

```go
func TestGitSpaceFormGlobalOptions(t *testing.T) {
	deny := []string{
		`git --git-dir /r/.git push --force origin main`,
		`git --work-tree /r --git-dir /r/.git clean -fdx`,
		`git --git-dir /r/.git config --global core.hooksPath /tmp/evil`,
		`git --work-tree /r reset --hard`,
		`git --exec-path /x clean -fdx`,
		`git --attr-source HEAD push --force`,
		`git --super-prefix x reset --hard`,
		`git --config-env=k=V push --force`,
	}
	for _, c := range deny {
		v := evalBash(t, c)
		if v == nil || v.Decision != policy.Deny {
			t.Errorf("%q -> %+v, want deny", c, v)
		}
	}
}

func TestGitKnownValuelessGlobalsStillParse(t *testing.T) {
	for _, c := range []string{`git --no-pager reset --hard`, `git -P reset --hard`, `git --bare reset --hard`} {
		v := evalBash(t, c)
		if v == nil || v.Decision != policy.Deny {
			t.Errorf("%q -> %+v, want deny (valueless global must not shift the subcommand)", c, v)
		}
	}
}

func TestGitUnknownGlobalFailsClosed(t *testing.T) {
	v := evalBash(t, `git --some-future-option x reset --hard`)
	if v == nil || (v.Decision != policy.Deny && v.Decision != policy.Ask) {
		t.Fatalf("-> %+v, want deny or ask, never allow", v)
	}
}

func TestGitReadOnlyStillAllowed(t *testing.T) {
	for _, c := range []string{`git status`, `git --no-pager log --oneline`, `git -C . diff`} {
		if v := evalBash(t, c); v != nil {
			t.Errorf("%q -> %+v, want nil", c, v)
		}
	}
}
```

- [ ] **Step 2: Run to verify it fails** → every space-form case ALLOWs.

- [ ] **Step 3: Implement**

In `internal/engine/rules_bash.go`, replace both inline maps with one package-level table and add the unknown-flag probe:

```go
// gitValueFlags are git global options that consume a following token.
// Missing one shifts subcommand parsing and silently disables every git rule
// — exactly the class the v0.4.1 hotfix closed for -C/-c and the 2026-09-04
// review reopened through --git-dir. Keep this list complete.
var gitValueFlags = map[string]bool{
	"-C": true, "-c": true, "--namespace": true,
	"--git-dir": true, "--work-tree": true, "--exec-path": true,
	"--attr-source": true, "--super-prefix": true, "--config-env": true,
}

// gitValuelessGlobals are global options that take no following token.
var gitValuelessGlobals = map[string]bool{
	"-P": true, "--no-pager": true, "--paginate": true, "--bare": true,
	"--literal-pathspecs": true, "--no-replace-objects": true,
	"--help": true, "--version": true, "--no-optional-locks": true,
}
```

Rewrite both `gitSubcommand` and `gitSubcommandArg` to use `gitValueFlags` (delete their local literals), and add:

```go
// gitSubcommandUnknownFlag returns the first --flag preceding the subcommand
// that this code does not recognise. A new git global option must fail closed
// rather than silently shift the subcommand.
func gitSubcommandUnknownFlag(argv []string) string {
	for i := 1; i < len(argv); {
		a := argv[i]
		if !strings.HasPrefix(a, "-") {
			return ""
		}
		base := a
		if eq := strings.Index(a, "="); eq >= 0 {
			base = a[:eq]
		}
		if gitValueFlags[base] {
			if strings.Contains(a, "=") {
				i++
			} else {
				i += 2
			}
			continue
		}
		if gitValuelessGlobals[base] {
			i++
			continue
		}
		return a
	}
	return ""
}
```

In `internal/engine/rules_git.go`, at the top of `checkGitSafety` (after the `head(s.Argv) != "git"` guard):

```go
	if unknown := gitSubcommandUnknownFlag(s.Argv); unknown != "" {
		return &policy.Verdict{Decision: policy.Ask, RuleID: "P2.git-unknown-global",
			Reason: "unrecognized git global option " + unknown + " before the subcommand; cannot verify what this runs"}
	}
```

- [ ] **Step 4: Run + commit**

Run: `/usr/local/go/bin/go test ./... -v` → PASS.
```bash
gofmt -w internal/engine/ && git add internal/engine/
git commit -m "fix(engine): complete git global-option table, shared, with unknown flags failing closed (CR-5)"
```

---

### Task 3: CR-6 — parse the refspec

**Files:** Modify `internal/engine/rules_git.go`, `internal/engine/rules_git_test.go`

**Interfaces:** `checkGitSafety`'s `push` case inspects the refspec operands: a leading `+` on any refspec → deny `P2.git-push-force` (it *is* a force push); a leading `:` or an empty source (`:main`) → ask `P2.git-push-delete`; the protected-branch check matches the **destination** side of `src:dst`, not the whole token.

- [ ] **Step 1: Write the failing test**

```go
func TestGitPushRefspecForms(t *testing.T) {
	deny := []string{`git push origin +main`, `git push origin +HEAD:refs/heads/main`}
	for _, c := range deny {
		v := evalBash(t, c)
		if v == nil || v.Decision != policy.Deny {
			t.Errorf("%q -> %+v, want deny (+refspec is a force push)", c, v)
		}
	}
	ask := map[string]string{
		`git push origin :main`:      "P2.git-push-delete",
		`git push origin main:main`:  "P2.git-push-protected",
		`git push origin dev:main`:   "P2.git-push-protected",
	}
	for c, id := range ask {
		v := evalBash(t, c)
		if v == nil || v.Decision != policy.Ask || v.RuleID != id {
			t.Errorf("%q -> %+v, want ask/%s", c, v, id)
		}
	}
	if v := evalBash(t, `git push origin dev:feature-x`); v != nil {
		t.Errorf("non-protected refspec -> %+v, want nil", v)
	}
}
```

- [ ] **Step 2: Run to verify it fails.**

- [ ] **Step 3: Implement** — replace `checkGitSafety`'s `case "push":` body:

```go
	case "push":
		if hasAnyFlag(s.Argv, "f", "--force", "--force-with-lease") {
			return nil // P1.git-push-force (checkGit) already denies this
		}
		for _, a := range nonFlagArgs(s.Argv) {
			if strings.HasPrefix(a, "+") {
				return &policy.Verdict{Decision: policy.Deny, RuleID: "P2.git-push-force",
					Reason: "a leading + in a refspec is a force push: " + a}
			}
			if strings.HasPrefix(a, ":") {
				return &policy.Verdict{Decision: policy.Ask, RuleID: "P2.git-push-delete",
					Reason: "an empty source in a refspec deletes the remote ref: " + a}
			}
			dst := a
			if i := strings.LastIndex(a, ":"); i >= 0 {
				dst = a[i+1:]
			}
			dst = strings.TrimPrefix(dst, "refs/heads/")
			if dst == "main" || dst == "master" {
				return &policy.Verdict{Decision: policy.Ask, RuleID: "P2.git-push-protected",
					Reason: "push to a protected branch"}
			}
		}
		if hasAnyFlag(s.Argv, "", "--tags") {
			return &policy.Verdict{Decision: policy.Ask, RuleID: "P2.git-push-protected",
				Reason: "pushing tags can overwrite released versions"}
		}
```

- [ ] **Step 4: Run + commit**

```bash
gofmt -w internal/engine/ && git add internal/engine/
git commit -m "fix(engine): parse push refspecs — +force, :delete, and dst-side protected-branch matching (CR-6)"
```

---

### Task 4: CR-4 — redirect-only statements

**Files:** Modify `internal/engine/tokenize.go`, `internal/engine/rules_bash.go`, and their tests

**Interfaces:** `splitSimples` emits a `Simple` with empty `Argv` and populated `Redirects` for a statement that has redirections but no command words (`> /etc/passwd`, `exec 3> /etc/passwd`). `stripAndUnwrap` passes such a `Simple` through unchanged rather than returning `nil`. `checkBash`'s loop no longer `continue`s on `len(s.Argv) == 0` — it skips the argv-based rules but still runs the redirect check in `checkAskTier`.

- [ ] **Step 1: Write the failing test**

```go
func TestRedirectOnlyStatements(t *testing.T) {
	for _, c := range []string{`> /etc/passwd`, `>/etc/passwd`, `exec 3> /etc/passwd`, `>> /etc/passwd`} {
		v := evalBash(t, c)
		if v == nil {
			t.Errorf("%q -> nil, want a verdict (a bare redirect truncates the file)", c)
		}
	}
	if v := evalBash(t, `> /repo/build.log`); v != nil {
		t.Errorf("in-repo redirect -> %+v, want nil", v)
	}
}
```

- [ ] **Step 2: Run to verify it fails** → all ALLOW.

- [ ] **Step 3: Implement**

In `splitSimples`, replace the early `if !ok || len(ce.Args) == 0 { return true }` so a redirect-carrying statement is still emitted. Work from the `*syntax.Stmt` (it already is — `stmt.Redirs` is read there):

```go
		ce, ok := stmt.Cmd.(*syntax.CallExpr)
		if !ok {
			return true
		}
		if len(ce.Args) == 0 && len(stmt.Redirs) == 0 {
			return true // nothing to inspect
		}
```

(the existing argv loop naturally produces an empty `Argv` when `ce.Args` is empty; the redirect loop below it already runs.)

In `stripAndUnwrap`, before the wrapper loop, pass a redirect-only simple straight through:

```go
	if len(s.Argv) == 0 {
		if len(s.Redirects) == 0 {
			return nil, nil
		}
		return []Simple{s}, nil
	}
```

In `checkBash`'s loop, replace `if len(s.Argv) == 0 { continue }` with a guarded dispatch so the redirect rule still runs:

```go
		if len(s.Argv) == 0 {
			take(checkAskTier(s, tc, pol)) // redirect targets only
			continue
		}
```

(`checkAskTier` already guards its argv-based switch behind `head(s.Argv)`, which is empty here, and then falls through to its `for _, r := range s.Redirects` loop — verify that ordering holds and reorder if the switch would panic on an empty argv.)

- [ ] **Step 4: Run + commit**

```bash
gofmt -w internal/engine/ && git add internal/engine/
git commit -m "fix(engine): evaluate redirect-only statements — '> /etc/passwd' no longer slips through (CR-4)"
```

---

### Task 5: H-3 — close the wrapper and privesc list holes

**Files:** Modify `internal/engine/tokenize.go`, `internal/engine/rules_bash.go`, and their tests

**Interfaces:**
- `stripAndUnwrap` gains cases for `setsid`, `stdbuf`, `ionice`, `chroot`, `watch`, `parallel` — each using a `consumeX` helper in the established style, failing closed on an unrecognized option. `chroot` and `parallel` take a positional argument before the command, so their helpers must consume it.
- `checkAskTier`'s privesc case gains `pkexec`, `run0`, `systemd-run`, `flatpak-spawn`, `toolbox`, `distrobox-host-exec`.
- `shellDashC` gains `fish`, `csh`, `tcsh`, `mksh`, `ash`.

- [ ] **Step 1: Write the failing test**

```go
func TestWrapperHoles(t *testing.T) {
	deny := []string{
		`setsid rm -rf /`, `stdbuf -o0 rm -rf /`, `ionice rm -rf /`,
		`chroot / rm -rf /`, `watch rm -rf /`,
		`pkexec rm -rf /`, `run0 rm -rf /`, `systemd-run rm -rf /`,
		`flatpak-spawn --host rm -rf /`,
		`fish -c "rm -rf /"`, `csh -c "rm -rf /"`, `tcsh -c "rm -rf /"`,
	}
	for _, c := range deny {
		v := evalBash(t, c)
		if v == nil || v.Decision == policy.Allow {
			t.Errorf("%q -> %+v, want deny or ask, never allow", c, v)
		}
	}
}

func TestWrapperUnknownOptionFailsClosed(t *testing.T) {
	v := evalBash(t, `stdbuf --future-option rm -rf /`)
	if v == nil || v.Decision == policy.Allow {
		t.Fatalf("-> %+v, want a non-allow verdict", v)
	}
}
```

- [ ] **Step 2: Run to verify it fails.**

- [ ] **Step 3: Implement**

Add helpers alongside the existing `consumeX` functions, following their exact shape (return the remaining argv, or an error naming the unrecognized option):

```go
// consumeSetsid handles `setsid [-f|-w|--fork|--wait|-c|--ctty]`.
func consumeSetsid(argv []string) ([]string, error) {
	known := map[string]bool{"-f": true, "--fork": true, "-w": true, "--wait": true, "-c": true, "--ctty": true}
	return consumeKnownFlags("setsid", argv, known, nil)
}

// consumeStdbuf handles `stdbuf -iL -oL -e0` and their long forms, all of
// which take a value either attached or as the next token.
func consumeStdbuf(argv []string) ([]string, error) {
	valued := map[string]bool{"-i": true, "-o": true, "-e": true,
		"--input": true, "--output": true, "--error": true}
	return consumeKnownFlags("stdbuf", argv, nil, valued)
}

// consumeIonice handles `ionice -c N -n N -t` (values may be attached).
func consumeIonice(argv []string) ([]string, error) {
	known := map[string]bool{"-t": true, "--ignore": true}
	valued := map[string]bool{"-c": true, "-n": true, "--class": true, "--classdata": true}
	return consumeKnownFlags("ionice", argv, known, valued)
}

// consumeWatch handles `watch -n 2 -d` etc.
func consumeWatch(argv []string) ([]string, error) {
	known := map[string]bool{"-d": true, "--differences": true, "-t": true, "--no-title": true, "-b": true, "-e": true}
	valued := map[string]bool{"-n": true, "--interval": true}
	return consumeKnownFlags("watch", argv, known, valued)
}

// consumeChroot handles `chroot [--userspec=U] NEWROOT CMD...` — the new root
// is a positional argument that must be consumed before the command.
func consumeChroot(argv []string) ([]string, error) {
	valued := map[string]bool{"--userspec": true, "--groups": true}
	rest, err := consumeKnownFlags("chroot", argv, nil, valued)
	if err != nil {
		return nil, err
	}
	if len(rest) == 0 {
		return nil, fmt.Errorf("chroot: missing new-root argument; failing closed")
	}
	return rest[1:], nil // drop NEWROOT
}
```

Add the shared helper if one does not already exist in the file (match the existing style if it does):

```go
// consumeKnownFlags skips a wrapper's own options. valued flags consume a
// following token unless the value is attached with '='. An unrecognized
// option is an error: an unknown flag may take a value, and guessing wrong
// shifts which word is the command.
func consumeKnownFlags(name string, argv []string, known, valued map[string]bool) ([]string, error) {
	i := 0
	for i < len(argv) {
		a := argv[i]
		if !strings.HasPrefix(a, "-") || a == "--" {
			if a == "--" {
				i++
			}
			break
		}
		base := a
		attached := false
		if eq := strings.Index(a, "="); eq >= 0 {
			base, attached = a[:eq], true
		}
		switch {
		case known[base]:
			i++
		case valued[base]:
			if attached || len(base) < len(a) {
				i++ // -oL or --output=L
			} else {
				i += 2
			}
		default:
			return nil, fmt.Errorf("%s: unrecognized option %q; failing closed", name, a)
		}
	}
	return argv[i:], nil
}
```

Wire the new cases into `stripAndUnwrap`'s switch:

```go
		case "setsid":
			rest, err = consumeSetsid(argv[1:])
		case "stdbuf":
			rest, err = consumeStdbuf(argv[1:])
		case "ionice":
			rest, err = consumeIonice(argv[1:])
		case "watch":
			rest, err = consumeWatch(argv[1:])
		case "chroot":
			rest, err = consumeChroot(argv[1:])
```

In `rules_bash.go`'s `checkAskTier`, extend the privesc case:

```go
	case "sudo", "su", "doas", "pkexec", "run0", "systemd-run", "flatpak-spawn", "toolbox", "distrobox-host-exec":
```

In `tokenize.go`'s `shellDashC`, extend the shell list:

```go
	case "sh", "bash", "zsh", "dash", "ksh", "fish", "csh", "tcsh", "mksh", "ash":
```

> `parallel` is deliberately **not** unwrapped — its `:::` argument syntax means the command and its data are interleaved, and a wrong guess about which is which is worse than failing closed. Leave it out of the strip list so it reaches `checkAskTier` as an unknown head; add a corpus entry asserting `parallel rm -rf ::: /` is **not** allowed, and if it currently is, add `parallel` to the privesc list rather than trying to parse it.

- [ ] **Step 4: Run + commit**

```bash
gofmt -w internal/engine/ && git add internal/engine/
git commit -m "fix(engine): close wrapper strip-list and privesc holes; recognize fish/csh/tcsh -c (H-3)"
```

---

### Task 6: CR-13 — parse docker's argument vector

**Files:** Modify `internal/engine/rules_bash.go`, `internal/engine/tokenize.go`, and their tests

**Interfaces:**
- `func dockerSubcommandChain(argv []string) []string` — skips docker's global options (and their values) to return the subcommand words in order (`["compose","down"]`, `["image","prune"]`, `["volume","rm"]`).
- `checkDocker` matches on that chain rather than a string prefix, and accepts `docker`, `docker-compose`, `podman`, `nerdctl` as heads.
- `runnerInner`'s docker branch consumes values for docker's valued flags (`-v --volume -e --env -p --publish -w --workdir -u --user --mount --network --name --entrypoint`) before treating a token as the image.

- [ ] **Step 1: Write the failing test**

```go
func TestDockerFlagsDoNotDefeatMatching(t *testing.T) {
	deny := []string{
		`docker compose -f d.yml down`,
		`docker compose --file d.yml down -v`,
		`docker-compose down`,
		`docker container prune -f`,
		`docker image prune -af`,
		`docker builder prune -af`,
		`podman system prune -af`,
		`docker --context foo compose down`,
	}
	for _, c := range deny {
		v := evalBash(t, c)
		if v == nil || v.Decision != policy.Deny {
			t.Errorf("%q -> %+v, want deny", c, v)
		}
	}
	if v := evalBash(t, `docker compose up -d`); v != nil {
		t.Errorf("compose up -> %+v, want nil", v)
	}
	if v := evalBash(t, `docker ps -a`); v != nil {
		t.Errorf("docker ps -> %+v, want nil", v)
	}
}

func TestDockerRunValuedFlagsFindTheRealCommand(t *testing.T) {
	deny := []string{
		`docker run --rm -v /:/host alpine rm -rf /`,
		`docker run -e A=b alpine rm -rf /`,
		`docker run -v /:/host -w /host --name x alpine rm -rf /`,
	}
	for _, c := range deny {
		v := evalBash(t, c)
		if v == nil || v.Decision != policy.Deny {
			t.Errorf("%q -> %+v, want deny (the inner command must be found)", c, v)
		}
	}
}
```

- [ ] **Step 2: Run to verify it fails.**

- [ ] **Step 3: Implement**

```go
var dockerValuedFlags = map[string]bool{
	"-f": true, "--file": true, "-v": true, "--volume": true,
	"-e": true, "--env": true, "-p": true, "--publish": true,
	"-w": true, "--workdir": true, "-u": true, "--user": true,
	"--mount": true, "--network": true, "--name": true, "--entrypoint": true,
	"--context": true, "--host": true, "-H": true, "--log-level": true,
	"--project-name": true, "-c": true,
}

// dockerSubcommandChain returns the subcommand words, skipping global options
// and their values. Prefix-matching the joined argv instead let any flag
// between `compose` and `down` defeat the rule (review CR-13).
func dockerSubcommandChain(argv []string) []string {
	var chain []string
	for i := 1; i < len(argv); {
		a := argv[i]
		if !strings.HasPrefix(a, "-") {
			chain = append(chain, a)
			i++
			continue
		}
		base := a
		attached := strings.Contains(a, "=")
		if eq := strings.Index(a, "="); eq >= 0 {
			base = a[:eq]
		}
		if dockerValuedFlags[base] && !attached {
			i += 2
			continue
		}
		i++
	}
	return chain
}

func chainHasPrefix(chain, want []string) bool {
	if len(chain) < len(want) {
		return false
	}
	for i, w := range want {
		if chain[i] != w {
			return false
		}
	}
	return true
}
```

Rewrite `checkDocker`'s head guard and matching:

```go
func checkDocker(s Simple, rawCmd string) *policy.Verdict {
	switch head(s.Argv) {
	case "docker", "docker-compose", "podman", "nerdctl":
	default:
		return nil
	}
	chain := dockerSubcommandChain(s.Argv)
	if head(s.Argv) == "docker-compose" {
		chain = append([]string{"compose"}, chain...)
	}
	if chainHasPrefix(chain, []string{"compose", "down"}) {
		return &policy.Verdict{Decision: policy.Deny, RuleID: "P1.docker-down",
			Reason: "docker compose down tears down a whole stack"}
	}
	if len(chain) >= 2 && chain[1] == "prune" {
		return &policy.Verdict{Decision: policy.Deny, RuleID: "P1.docker-prune",
			Reason: "docker " + chain[0] + " prune removes resources with unverifiable scope"}
	}
	if len(chain) >= 1 && chain[0] == "prune" {
		return &policy.Verdict{Decision: policy.Deny, RuleID: "P1.docker-prune",
			Reason: "docker prune removes resources with unverifiable scope"}
	}
	destructive := chainHasPrefix(chain, []string{"rm"}) || chainHasPrefix(chain, []string{"kill"}) ||
		chainHasPrefix(chain, []string{"volume", "rm"}) || chainHasPrefix(chain, []string{"network", "rm"})
	if destructive && commandHasSubstitution(rawCmd) {
		return &policy.Verdict{Decision: policy.Deny, RuleID: "P1.docker-substituted",
			Reason: "docker rm/kill with a command-substituted target list"}
	}
	return nil
}
```

In `tokenize.go`'s `runnerInner`, replace the docker branch's flag scan with one that consumes valued-flag values before taking the image token:

```go
	case "docker", "podman", "nerdctl":
		chainStart := 1
		if len(argv) > 1 && (argv[1] == "run" || argv[1] == "exec") {
			i := 2
			for i < len(argv) {
				a := argv[i]
				if !strings.HasPrefix(a, "-") {
					break
				}
				base := a
				attached := strings.Contains(a, "=")
				if eq := strings.Index(a, "="); eq >= 0 {
					base = a[:eq]
				}
				if dockerValuedFlags[base] && !attached {
					i += 2
					continue
				}
				i++
			}
			if i+1 < len(argv) {
				return argv[i+1:], nil // skip the image/container token
			}
		}
		_ = chainStart
```

- [ ] **Step 4: Run + commit**

```bash
gofmt -w internal/engine/ && git add internal/engine/
git commit -m "fix(engine): parse docker's argument vector — flags no longer defeat compose/prune matching or hide the inner command (CR-13)"
```

---

### Task 7: H-4 — the uncovered destructive primitives

**Files:** Modify `internal/engine/rules_bash.go`, `internal/engine/rules_git.go`, `internal/engine/rules_net.go`, and their tests

**Interfaces:**
- `checkDestinationWrites(s Simple, tc ToolCall, pol *policy.Policy) *policy.Verdict` — for `mv`, `cp`, `ln`, `tee`, `install`, and `rsync` with `--delete`, any write destination that fails `withinSafe` → ask `P1.out-of-repo-write`. Reuses `writeTargets` from Phase 1 Task 6 for target identification.
- `checkAskTier`'s `find` case matches any `-exec`/`-execdir`/`-ok`/`-okdir` whose following command's **basename** is destructive (`rm`, `shred`, `truncate`, `dd`), not only the literal `rm`.
- `checkGitSafety` gains `update-ref` with `-d` → ask, `worktree` with `remove` → ask, `switch` with `--discard-changes` → ask, `rm` with `-r`/`-f` → ask.
- `netTools` gains `ssh` and `sftp`; `extractHost` handles `ssh user@host cmd` and `ssh host cmd`.

- [ ] **Step 1: Write the failing test**

```go
func TestUncoveredDestructivePrimitives(t *testing.T) {
	nonAllow := []string{
		`mv /etc /tmp/gone`,
		`cp /dev/null /etc/passwd`,
		`tee /etc/passwd`,
		`ln -sf /dev/null /etc/passwd`,
		`rsync --delete /empty/ /etc/`,
		`find . -execdir rm -rf {} +`,
		`find . -exec /bin/rm -rf {} +`,
		`git update-ref -d refs/heads/main`,
		`git worktree remove --force x`,
		`git switch --discard-changes x`,
		`git rm -rf .`,
		`ssh localhost rm -rf /`,
	}
	for _, c := range nonAllow {
		v := evalBash(t, c)
		if v == nil || v.Decision == policy.Allow {
			t.Errorf("%q -> %+v, want deny or ask, never allow", c, v)
		}
	}
}

func TestInRepoWritesStillAllowed(t *testing.T) {
	for _, c := range []string{`cp a.txt b.txt`, `mv src/a.go src/b.go`, `tee build.log`} {
		if v := evalBash(t, c); v != nil && v.Decision != policy.Allow {
			t.Errorf("%q -> %+v, want allow (ordinary in-repo work)", c, v)
		}
	}
}
```

- [ ] **Step 2: Run to verify it fails.**

- [ ] **Step 3: Implement** — add `checkDestinationWrites` and wire it into `checkBash`'s loop:

```go
func checkDestinationWrites(s Simple, tc ToolCall, pol *policy.Policy) *policy.Verdict {
	switch head(s.Argv) {
	case "mv", "cp", "ln", "tee", "install":
	case "rsync":
		if !hasAnyFlag(s.Argv, "", "--delete", "--delete-after", "--delete-before") {
			return nil
		}
	default:
		return nil
	}
	for _, t := range writeTargets(s) {
		if !withinSafe(resolvePath(t, tc.CWD), tc.RepoRoot, pol.Slots.SafeRoots) {
			return ask("P1.out-of-repo-write",
				"writes to a path outside the repo and configured safe roots: "+t)
		}
	}
	return nil
}
```

Extend `checkAskTier`'s `find` case:

```go
	case "find":
		destructive := map[string]bool{"rm": true, "shred": true, "truncate": true, "dd": true}
		for i, a := range s.Argv {
			if a == "-delete" {
				return ask("P1.find-delete", "find -delete is a bulk deletion primitive")
			}
			if a == "-exec" || a == "-execdir" || a == "-ok" || a == "-okdir" {
				if i+1 < len(s.Argv) && destructive[path.Base(s.Argv[i+1])] {
					return ask("P1.find-delete", "find "+a+" invokes a destructive command")
				}
			}
		}
```

Extend `checkGitSafety`'s switch:

```go
	case "update-ref":
		if hasAnyFlag(s.Argv, "d") {
			return ask("P2.git-ref-delete", "git update-ref -d deletes a ref")
		}
	case "worktree":
		if gitSubcommandArg(s.Argv) == "remove" {
			return ask("P2.git-worktree-remove", "git worktree remove discards a working tree")
		}
	case "switch":
		if hasAnyFlag(s.Argv, "", "--discard-changes") {
			return ask("P2.git-discard", "git switch --discard-changes throws away uncommitted work")
		}
	case "rm":
		if hasAnyFlag(s.Argv, "rf", "--force") {
			return ask("P2.git-rm", "git rm -r/-f removes tracked files")
		}
```

In `rules_net.go`, add `"ssh": true, "sftp": true` to `netTools` and handle them in `extractHost`:

```go
	case "ssh", "sftp":
		for _, a := range args {
			if i := strings.Index(a, "@"); i >= 0 {
				return stripPort(a[i+1:])
			}
			return stripPort(a) // first non-flag arg is the host
		}
```

- [ ] **Step 4: Run + commit**

```bash
gofmt -w internal/engine/ && git add internal/engine/
git commit -m "fix(engine): cover mv/cp/ln/tee/install/rsync --delete destinations, find -execdir, four git verbs, and ssh (H-4)"
```

---

### Task 8: CR-3 — track `cd` across a command's statements

**Files:** Modify `internal/engine/tokenize.go`, `internal/engine/rules_bash.go`, and their tests

**Interfaces:**
- `Simple` gains `Cwd string` — the working directory in effect for that statement, empty when unknown.
- `Normalize` walks the simples in order maintaining a running cwd seeded from the caller: a `cd <literal>` sets it (absolute replaces, relative joins); a `cd` with an unresolvable or absent argument, or `pushd`/`popd`, sets a sentinel that marks every subsequent statement `Unresolved`.
- **Signature change:** `Normalize(command string) ([]Simple, error)` → `Normalize(command, cwd string) ([]Simple, error)`. Callers: `checkBash`, `checkPaths`, `IsPrivateDataAccess`, `IsNetworkAttempt`, `writeCandidates` — pass `tc.CWD`.
- `resolvePath` uses `s.Cwd` when non-empty, else `tc.CWD`.

- [ ] **Step 1: Write the failing test**

```go
func TestCdIsTracked(t *testing.T) {
	deny := []string{
		`cd /etc && rm -rf .`,
		`cd /etc; rm -rf *`,
		`cd / && rm -rf .`,
		`bash -c "cd /; rm -rf ."`,
	}
	for _, c := range deny {
		v := evalBash(t, c)
		if v == nil || v.Decision == policy.Allow {
			t.Errorf("%q -> %+v, want deny or ask, never allow", c, v)
		}
	}
}

func TestCdWithinRepoStillAllows(t *testing.T) {
	if v := evalBash(t, `cd src && rm -rf build`); v != nil && v.Decision == policy.Deny {
		t.Errorf("in-repo cd + rm -> %+v, want not-deny", v)
	}
}

func TestUnresolvableCdFailsClosed(t *testing.T) {
	v := evalBash(t, `cd $TARGET && rm -rf .`)
	if v == nil || v.Decision == policy.Allow {
		t.Fatalf("-> %+v, want a non-allow verdict", v)
	}
}
```

- [ ] **Step 2: Run to verify it fails** → the `cd` cases ALLOW.

- [ ] **Step 3: Implement**

Add `Cwd string` to `Simple`. In `Normalize`, after expanding each simple, thread the running cwd:

```go
func Normalize(command, cwd string) ([]Simple, error) {
	base, err := splitSimples(command)
	if err != nil {
		return nil, err
	}
	running := cwd
	cwdUnknown := false
	var out []Simple
	for _, s := range base {
		expanded, err := stripAndUnwrap(s)
		if err != nil {
			degraded := s
			degraded.Unresolved = true
			degraded.Cwd = running
			out = append(out, degraded)
			continue
		}
		for _, e := range expanded {
			e.Cwd = running
			if cwdUnknown {
				e.Unresolved = true
			}
			out = append(out, e)
		}
		// A cd in this statement changes the cwd for every later statement.
		for _, e := range expanded {
			switch head(e.Argv) {
			case "cd":
				args := nonFlagArgs(e.Argv)
				if e.Unresolved || len(args) == 0 {
					cwdUnknown = true // `cd $X` or bare `cd` (home): unknowable
					continue
				}
				if filepath.IsAbs(args[0]) {
					running = filepath.Clean(args[0])
				} else {
					running = filepath.Clean(filepath.Join(running, args[0]))
				}
			case "pushd", "popd":
				cwdUnknown = true
			}
		}
	}
	return out, nil
}
```

In `rules_bash.go`, add a helper and use it wherever `tc.CWD` is currently passed to `resolvePath`:

```go
func simpleCwd(s Simple, tc ToolCall) string {
	if s.Cwd != "" {
		return s.Cwd
	}
	return tc.CWD
}
```

Update every `resolvePath(x, tc.CWD)` call in `checkRmRf`, `checkAskTier`, and `checkDestinationWrites` to `resolvePath(x, simpleCwd(s, tc))`.

Update all `Normalize(...)` call sites to pass a cwd: `checkBash` and `checkDestinationWrites` use `tc.CWD`; `checkPaths`, `writeCandidates`, `IsPrivateDataAccess`, `IsNetworkAttempt` likewise.

> `bash -c "cd /; rm -rf ."` works because `normalizeShellDashC` re-tokenizes the inner script — pass the *current* running cwd into that recursive `Normalize` call rather than the original `tc.CWD`.

- [ ] **Step 4: Run + prove**

Run: `/usr/local/go/bin/go test ./... -v` → PASS, then rebuild and confirm `cd /etc && rm -rf .` exits 2.

- [ ] **Step 5: Commit**

```bash
gofmt -w internal/engine/ && git add internal/engine/
git commit -m "fix(engine): track cd across statements so relative operands resolve where the shell will be (CR-3)"
```

---

### Task 9: The H-5 evidence gap and the corpus

**Files:** Modify `test/adversarial/overlay_test.go`, `test/adversarial/corpus.json`

**Interfaces:** The remediation response flagged one missing lock: an **authorized** `SecretAllow` grant combined with an in-repository symlink escaping the repository. The implementation is believed correct; this task proves it.

- [ ] **Step 1: Write the missing lock**

Add to `test/adversarial/overlay_test.go`:

```go
// An authorized secret_allow grant must not also disable symlink-escape
// checking: a repo-internal symlink pointing at a secret outside the repo is
// still an escape, even when the operator has widened secret_allow.
func TestAuthorizedSecretAllowStillBlocksSymlinkEscape(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation is privileged on Windows")
	}
	bin := buildAdversarialBinary(t)

	repo := t.TempDir()
	exec.Command("git", "-C", repo, "init", "-q").Run()
	os.WriteFile(filepath.Join(repo, "guardrail.toml"),
		[]byte("[slots]\nsecret_allow = [\"**\"]\n"), 0o644)

	secretDir := t.TempDir()
	secret := filepath.Join(secretDir, "id_rsa")
	os.WriteFile(secret, []byte("PRIVATE KEY"), 0o600)
	link := filepath.Join(repo, "innocent.txt")
	if err := os.Symlink(secret, link); err != nil {
		t.Fatal(err)
	}

	// Operator config that DOES authorize secret_allow for this repo.
	cfgHome := t.TempDir()
	os.MkdirAll(filepath.Join(cfgHome, "guardrail"), 0o700)
	os.WriteFile(filepath.Join(cfgHome, "guardrail", "waivers.toml"),
		[]byte("[\""+repo+"\"]\nsecret_allow = true\n"), 0o600)

	payload, _ := json.Marshal(map[string]any{
		"session_id": "adv", "cwd": repo, "hook_event_name": "PreToolUse",
		"tool_name": "Read", "tool_input": map[string]any{"file_path": link},
	})
	cmd := exec.Command(bin, "hook", "claude")
	cmd.Stdin = bytes.NewReader(payload)
	cmd.Env = append(os.Environ(),
		"XDG_STATE_HOME="+t.TempDir(),
		"XDG_CONFIG_HOME="+cfgHome,
		"GUARDRAIL_CONFIG="+filepath.Join(repo, "guardrail.toml"))
	_ = cmd.Run()
	if cmd.ProcessState.ExitCode() != 2 {
		t.Fatalf("exit %d, want 2 — an authorized secret_allow must not disable symlink-escape checking",
			cmd.ProcessState.ExitCode())
	}
}
```

- [ ] **Step 2: Run**

Run: `/usr/local/go/bin/go test ./test/adversarial/ -run TestAuthorizedSecretAllow -v`
Expected: PASS. **If it fails, that is a real bypass** — stop, fix `checkPaths` so the symlink-escape check runs regardless of a `SecretAllow` match, and report it.

- [ ] **Step 3: Add every Phase 2 reproduction to the corpus**

Append `"want": "deny"` (or `"ask"` where the rule is ask-tier) entries for: `cd /etc && rm -rf .`, `> /etc/passwd`, `git --git-dir /r/.git push --force`, `git push origin +main`, `git push origin :main`, `docker compose -f d.yml down`, `docker image prune -af`, `docker run --rm -v /:/host alpine rm -rf /`, `setsid rm -rf /`, `stdbuf -o0 rm -rf /`, `chroot / rm -rf /`, `pkexec rm -rf /`, `fish -c "rm -rf /"`, `mv /etc /tmp/gone`, `tee /etc/passwd`, `find . -execdir rm -rf {} +`, `git update-ref -d refs/heads/main`, `ssh localhost rm -rf /`, `rm -rf /; env -Z x`.

And `"want": "allow"` entries for the adjacent legitimate cases: `docker compose up -d`, `docker ps -a`, `git status`, `git --no-pager log --oneline`, `cp a.txt b.txt`, `mv src/a.go src/b.go`, `cd src && rm -rf build`, `> /repo/build.log`, `git clean -n`.

- [ ] **Step 4: Run the whole corpus**

Run: `/usr/local/go/bin/go test ./test/adversarial/ -v`
Expected: PASS with **zero** existing entries relaxed. If an existing entry now fails, that is a Phase 2 over-correction — fix the code, not the corpus.

- [ ] **Step 5: Commit**

```bash
git add test/adversarial/
git commit -m "test: lock every Phase 2 reproduction and close the H-5 symlink/secret_allow evidence gap"
```

---

### Task 10: docs, review annotation, tag

- [ ] **Step 1:** `make check && /usr/local/go/bin/go test ./... -count=1` → all green.
- [ ] **Step 2:** Annotate the review with `**[FIXED — Phase 2]**` on CR-3, CR-4, CR-5, CR-6, CR-13, H-1, H-3, H-4; update the H-5 row to fully fixed now its lock exists.
- [ ] **Step 3:** Update `docs/reviews/2026-09-05-remediation-response.md`'s ledger to the new counts, and README Status.
- [ ] **Step 4:**
```bash
git add -A && git commit -m "docs: Phase 2 landed — token normalization complete"
git push origin main && git tag v0.12.0-dev && git push origin v0.12.0-dev
```

> **The installer pin may now be advanced.** Phases 1, 2 and 3 are complete; only Phase 4 (inverting the closed allowlists, unknown-tool default-deny, native-web gating, and the M-2..M-7 false positives) remains, and none of it is a reproduced bypass of the kind Phases 1–3 closed. Advancing the pin is Carlitos's call — see the Roadmap note in the Phase 1 plan.

---

## Self-Review

**1. Finding coverage.** CR-3 → Task 8; CR-4 → Task 4; CR-5 → Task 2; CR-6 → Task 3; CR-13 → Task 6; H-1 → Task 1; H-3 → Task 5; H-4 → Task 7; the H-5 evidence gap → Task 9. Phase 4's contents are listed in Global Constraints as explicitly out of scope. Nothing from the review is silently dropped.

**2. Placeholder scan.** No `TBD`. Task 5's note on `parallel` is a deliberate decision (fail closed rather than parse `:::` wrongly) with a concrete fallback instruction, not a hedge. Task 4's parenthetical about `checkAskTier`'s ordering is a real "verify this holds and reorder if not" instruction.

**3. Type consistency.** `Simple` gains `Cwd string` (Task 8) after gaining `Unresolved bool` in Phase 1 — both additive. **`Normalize` gains a `cwd` parameter** — the one breaking change, with all call sites (`checkBash`, `checkPaths`, `writeCandidates`, `IsPrivateDataAccess`, `IsNetworkAttempt`, `normalizeShellDashC`) updated in the same task. New unexported: `consumeSetsid/Stdbuf/Ionice/Watch/Chroot`, `consumeKnownFlags`, `gitValueFlags`, `gitValuelessGlobals`, `gitSubcommandUnknownFlag`, `dockerValuedFlags`, `dockerSubcommandChain`, `chainHasPrefix`, `checkDestinationWrites`, `simpleCwd`. Reuses Phase 1's `head()`, `writeTargets`, `withinSafe`, `resolvePath`, `ask()`. No exported signature outside `internal/engine` changes.

**4. Risk.** Tasks 5, 7 and 8 broaden matching the most, and Task 8 changes how *every* relative path resolves — the highest-regression-risk change in the plan. Task 9's `"want": "allow"` entries (`cd src && rm -rf build`, `cp a.txt b.txt`, `docker compose up -d`, `git clean -n`) exist specifically so an over-correction there fails a test rather than becoming daily friction.

---

## Execution Handoff

**Plan complete and saved to `docs/superpowers/plans/2026-09-05-remediation-phase2.md`. Two execution options:**

**1. Subagent-Driven (recommended)** — fresh subagent per task via `superpowers:subagent-driven-development`, review between tasks.

**2. Inline Execution** — `superpowers:executing-plans`, batch with checkpoints.

**Which approach?**
