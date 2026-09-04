# Owned-Entry Hook Merge + CI Release Workflow — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `guardrail gen-config claude --merge` safe for repeated, unattended, changing-`--binary` runs (marker-based owned-entry replacement instead of union-append, per Plan 2 ruling 8), fix the `--print=false` no-op bug and two `doctor` papercuts, and stand up CI that on every `v*` tag publishes checksummed cross-platform `guardrail` binaries to GitHub Releases — culminating in a real `v0.3.0` release.

**Architecture:** `internal/genconfig` gains a `hooks`-specific merge path: guardrail-owned hook groups carry a stable `"id": "guardrail-claude-*"` marker; on merge, any dst group with a `guardrail-`-prefixed id is dropped and replaced by ours, while user-authored groups (no such id) are union-appended untouched. `permissions` arrays keep union-append (stale deny entries are fail-safe). Two GitHub Actions workflows: `ci.yml` (build/test/vet/gofmt gate on push + PR) and `release.yml` (tag-triggered cross-compile → `SHA256SUMS` → `gh release create`). Test helpers stop hardcoding the local Go path so CI works.

**Tech Stack:** Go 1.23+ (`/usr/local/go/bin/go` locally, 1.25.0, not on PATH). Existing deps only. GitHub Actions: `actions/checkout@v4`, `actions/setup-go@v5` (pin these exact majors). No goreleaser, no third-party release action — plain `go build` matrix + `gh` (preinstalled on runners).

**Spec:** `../../../DESIGN.md`. This is the agent-guardrails half of the renumbered "Plan 3"; the chezmoi installer + real-Claude smoke test are **Plan 3b** (written after this runs green). Terminology `../../../CONTEXT.md`; decisions `../../adr/`.

## Global Constraints

- Module path `github.com/CtrlCarlitos/agent-guardrails`, Go floor `go 1.23`. **No new dependencies.**
- **Owned-entry rule:** a hook group is "guardrail-owned" iff it has a string `id` field with prefix `guardrail-`. Only owned groups are ever replaced/removed by a merge. Anything without that marker is user data — never mutated, only union-appended against.
- **`permissions` stays union-append.** Do not add markers to permission strings (no room) — stale deny/ask entries are safe; a future `guardrail sync --prune` (Plan 7) is the cleanup path. Note this in ADR-0004.
- **Idempotence contract, tightened:** `gen-config claude --merge P` run N times with the *same* `--binary` ⇒ P is byte-identical after run 1. Run with `--binary A` then `--binary B` ⇒ exactly one owned Pre group and one owned Post group, both referencing B.
- CI must not assume the local Go path. Introduce a `goCmd()` test helper: `$GUARDRAIL_GO` env override → else `go` if on `PATH` → else `/usr/local/go/bin/go`.
- `release.yml` builds with `CGO_ENABLED=0 -trimpath -ldflags "-s -w -X main.version=<tag>"`. Asset names: `guardrail_<goos>_<goarch>` (+ `.exe` for windows). Matrix: linux/amd64, linux/arm64, darwin/amd64, darwin/arm64, windows/amd64, windows/arm64.
- Every code step is literal. Minimal TDD implementations. `gofmt -w` before every commit. Conventional Commits. Commit per task.
- Verified current state (recon at `HEAD fc6be61`, tag `v0.2.0-dev`):
  - `genconfig.claudeHooks(binary string) map[string]any` — PreToolUse group `{matcher:"Bash|Read|Edit|Write|MultiEdit", hooks:[{type:"command",command:<binary>+" hook claude",timeout:10}]}`; PostToolUse group `{matcher:"Write|Edit|MultiEdit", hooks:[{type:"command",command:...}]}`. **No `id` field yet.**
  - `genconfig.deepMerge(dst, src map[string]any)` — recurse on map/map; `unionAppend` on slice/slice (dedup by `json.Marshal` string); else src wins. `toAnySlice` accepts `[]any` and `[]string`.
  - `genconfig.MergeInto(path string, frag Fragment) error` — atomic temp+rename, final mode `0600` (documented intentional), refuses non-object / `null` JSON.
  - `cmd/guardrail/genconfig.go` — `cmdGenConfig(args []string, stdout, stderr io.Writer) int`; `doPrint` parsed but dead (`_ = doPrint`), stdout write is unconditional when `--merge` empty.
  - `cmd/guardrail/doctor.go` — `claudeSettingsState()` uses `os.ReadFile` + `strings.Contains(raw, "guardrail hook claude")`; treats any read error as "no settings.json". Inlines waiver collect+`slices.Sort`.
  - `cmd/guardrail/hook.go` — `waivedList(p *policy.Policy) []string` already sorts (ruling 5).
  - `test/contract_test.go` — `buildBinary(t *testing.T) string` hardcodes `/usr/local/go/bin/go`, builds `../cmd/guardrail` with no ldflags. `package test`. `test/genconfig_test.go` reuses it; `var updateGolden = flag.Bool("update", ...)`.
  - `Makefile` targets: `build test fmt contract golden`. `GO ?= /usr/local/go/bin/go`. No `vet`.
  - `docs/adr/` has `0001`–`0003`. Next is `0004`.
  - `./guardrail` is a **tracked** file (mistake — `.gitignore` has `/guardrail`).
  - `.gitignore`: `/guardrail`, `/dist/`, `*.test`, `*.out`, `.DS_Store`, `node_modules/`.

---

## Arc A — safe merge

### Task 1: ADR-0004 — marker-based owned hook entries

**Files:**
- Create: `docs/adr/0004-marker-based-owned-hook-entries.md`

**Interfaces:** none (documentation).

- [ ] **Step 1: Write the ADR**

`docs/adr/0004-marker-based-owned-hook-entries.md`:

```markdown
# Marker-based owned hook entries in generated plane config

`guardrail gen-config <plane> --merge <settings>` runs unattended from the dotfiles
installer on every `chezmoi apply`, and the `--binary` path it registers can change
(a version bump moves the install path, or a user hand-edits). The Plan 2 merge
union-appended hook entries keyed by their exact JSON. Empirically that *forks* the
hook: a changed `--binary` adds a second entry, so the engine is invoked twice per
tool call and the stale path errors on every call, forever.

Decision: guardrail-owned hook groups carry a stable marker — a string `id` field
with the prefix `guardrail-` (`guardrail-claude-pre`, `guardrail-claude-post`). The
`hooks` merge path is special-cased: for each event, dst groups whose `id` has that
prefix are dropped and replaced wholesale by the generated groups; dst groups
without the marker are user data and are union-appended against, never mutated.

`permissions.deny` / `permissions.ask` stay union-append — permission entries are
bare strings with nowhere to hang a marker, and a stale *deny* is fail-safe. A
`guardrail sync --prune` (Plan 7) is the eventual cleanup for drifted permission
lists.

## Consequences

- Claude Code ignores unknown keys in a hook group, so the `id` is inert to it.
- Re-running `--merge` with a different `--binary` converges to exactly one owned
  group per event.
- If a user copies a guardrail group and edits it without removing the `id`, the
  next merge will replace their copy. Documented; the `id` prefix is reserved.
```

- [ ] **Step 2: Commit**

```bash
git add docs/adr/0004-marker-based-owned-hook-entries.md
git commit -m "docs(adr): 0004 — marker-based owned hook entries"
```

---

### Task 2: Add `id` markers to guardrail-owned hook groups

**Files:**
- Modify: `internal/genconfig/claude.go`
- Modify: `internal/genconfig/claude_test.go`
- Modify: `test/fixtures/claude/settings-floor.golden.json` (regenerated)

**Interfaces:**
- `claudeHooks(binary string) map[string]any` — the PreToolUse group gains `"id": "guardrail-claude-pre"`, the PostToolUse group gains `"id": "guardrail-claude-post"`. Group key order in the map literal is irrelevant (JSON marshals sorted).

- [ ] **Step 1: Update the failing test**

In `internal/genconfig/claude_test.go`, extend `TestClaudeHooks`:

```go
func TestClaudeHooks(t *testing.T) {
	h := claudeHooks("/usr/local/bin/guardrail")
	pre := h["PreToolUse"].([]any)[0].(map[string]any)
	if pre["id"] != "guardrail-claude-pre" {
		t.Errorf("pre id = %v, want guardrail-claude-pre", pre["id"])
	}
	if pre["matcher"].(string) != "Bash|Read|Edit|Write|MultiEdit" {
		t.Errorf("matcher = %v", pre["matcher"])
	}
	hk := pre["hooks"].([]any)[0].(map[string]any)
	if hk["command"].(string) != "/usr/local/bin/guardrail hook claude" {
		t.Errorf("command = %v", hk["command"])
	}
	post := h["PostToolUse"].([]any)[0].(map[string]any)
	if post["id"] != "guardrail-claude-post" {
		t.Errorf("post id = %v", post["id"])
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `/usr/local/go/bin/go test ./internal/genconfig/ -run TestClaudeHooks -v`
Expected: FAIL — `pre["id"]` is `nil`.

- [ ] **Step 3: Write minimal implementation**

In `internal/genconfig/claude.go`, `claudeHooks`:

```go
func claudeHooks(binary string) map[string]any {
	cmd := binary + " hook claude"
	return map[string]any{
		"PreToolUse": []any{
			map[string]any{
				"id":      "guardrail-claude-pre",
				"matcher": "Bash|Read|Edit|Write|MultiEdit",
				"hooks": []any{
					map[string]any{"type": "command", "command": cmd, "timeout": 10},
				},
			},
		},
		"PostToolUse": []any{
			map[string]any{
				"id":      "guardrail-claude-post",
				"matcher": "Write|Edit|MultiEdit",
				"hooks": []any{
					map[string]any{"type": "command", "command": cmd},
				},
			},
		},
	}
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `/usr/local/go/bin/go test ./internal/genconfig/ -v`
Expected: PASS.

- [ ] **Step 5: Regenerate the golden**

Run: `/usr/local/go/bin/go test ./test/ -run Golden -update && /usr/local/go/bin/go test ./test/ -run Golden -v`
Expected: `settings-floor.golden.json` now has `"id": "guardrail-claude-pre"` / `-post`; the second run PASSES. Eyeball the diff — only the two `id` lines added.

- [ ] **Step 6: Commit**

```bash
gofmt -w internal/genconfig/
git add internal/genconfig/ test/fixtures/claude/settings-floor.golden.json
git commit -m "feat(genconfig): mark guardrail-owned Claude hook groups with a stable id"
```

---

### Task 3: `mergeHooks` — replace owned groups, union-append user groups

**Files:**
- Modify: `internal/genconfig/merge.go`
- Modify: `internal/genconfig/merge_test.go`

**Interfaces:**
- `deepMerge` special-cases the key `"hooks"`: when both `dv` and `sv` are `map[string]any`, call `mergeHooks(dm, sm)` and `continue` (do not fall through to the generic recurse).
- `func mergeHooks(dst, src map[string]any)` — for each event key in `src`: take dst's groups for that event, keep only the non-owned ones, then append: every owned group from `src` verbatim, and every non-owned `src` group that is not JSON-equal to something already kept.
- `func ownedByGuardrail(group any) bool` — `group` is `map[string]any` with a string `id` beginning `"guardrail-"`.
- `func jsonKey(v any) string` — extracted from `unionAppend`'s inline closure; `b, _ := json.Marshal(v); return string(b)`. `unionAppend` now uses it.

- [ ] **Step 1: Write the failing test**

Add to `internal/genconfig/merge_test.go`:

```go
func hookFrag(binary string) Fragment {
	return Fragment{"hooks": map[string]any{
		"PreToolUse": []any{
			map[string]any{
				"id": "guardrail-claude-pre", "matcher": "Bash",
				"hooks": []any{map[string]any{"type": "command", "command": binary + " hook claude"}},
			},
		},
	}}
}

func preGroups(t *testing.T, p string) []any {
	m := readJSON(t, p)
	return m["hooks"].(map[string]any)["PreToolUse"].([]any)
}

func TestMergeHooksReplacesOwnedOnRerun(t *testing.T) {
	p := filepath.Join(t.TempDir(), "settings.json")
	if err := MergeInto(p, hookFrag("/a/guardrail")); err != nil {
		t.Fatal(err)
	}
	if err := MergeInto(p, hookFrag("/a/guardrail")); err != nil {
		t.Fatal(err)
	}
	g := preGroups(t, p)
	if len(g) != 1 {
		t.Fatalf("want exactly 1 PreToolUse group after 2 identical merges, got %d: %v", len(g), g)
	}
}

func TestMergeHooksRebindsBinary(t *testing.T) {
	p := filepath.Join(t.TempDir(), "settings.json")
	MergeInto(p, hookFrag("/old/guardrail"))
	if err := MergeInto(p, hookFrag("/new/guardrail")); err != nil {
		t.Fatal(err)
	}
	g := preGroups(t, p)
	if len(g) != 1 {
		t.Fatalf("want 1 owned group, got %d", len(g))
	}
	cmd := g[0].(map[string]any)["hooks"].([]any)[0].(map[string]any)["command"].(string)
	if cmd != "/new/guardrail hook claude" {
		t.Fatalf("command = %q, want the new binary path", cmd)
	}
}

func TestMergeHooksPreservesUserGroups(t *testing.T) {
	p := filepath.Join(t.TempDir(), "settings.json")
	os.WriteFile(p, []byte(`{"hooks":{"PreToolUse":[{"matcher":"Task","hooks":[{"type":"command","command":"my-own-hook"}]}]}}`), 0o644)
	if err := MergeInto(p, hookFrag("/x/guardrail")); err != nil {
		t.Fatal(err)
	}
	g := preGroups(t, p)
	if len(g) != 2 {
		t.Fatalf("want user group + owned group = 2, got %d: %v", len(g), g)
	}
	var sawUser, sawOwned bool
	for _, grp := range g {
		m := grp.(map[string]any)
		if m["matcher"] == "Task" {
			sawUser = true
		}
		if m["id"] == "guardrail-claude-pre" {
			sawOwned = true
		}
	}
	if !sawUser || !sawOwned {
		t.Fatalf("user=%v owned=%v", sawUser, sawOwned)
	}
	// a second merge must not add a third group
	MergeInto(p, hookFrag("/x/guardrail"))
	if g := preGroups(t, p); len(g) != 2 {
		t.Fatalf("second merge changed group count to %d", len(g))
	}
}

func TestPermissionsStillUnionAppend(t *testing.T) {
	p := filepath.Join(t.TempDir(), "settings.json")
	os.WriteFile(p, []byte(`{"permissions":{"deny":["Bash(foo)"]}}`), 0o644)
	MergeInto(p, Fragment{"permissions": map[string]any{"deny": []string{"Bash(rm -rf *)"}}})
	deny := readJSON(t, p)["permissions"].(map[string]any)["deny"].([]any)
	if len(deny) != 2 {
		t.Fatalf("deny = %v, want the user entry kept + the new one", deny)
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `/usr/local/go/bin/go test ./internal/genconfig/ -run 'MergeHooks|PermissionsStill' -v`
Expected: FAIL — `TestMergeHooksRebindsBinary` gets 2 groups (union-append forked it); `TestMergeHooksReplacesOwnedOnRerun` may pass by luck (identical JSON dedups) but the rebind test fails.

- [ ] **Step 3: Write minimal implementation**

In `internal/genconfig/merge.go`:

Add `"strings"` to the import block. In `deepMerge`, before the generic `if dok && sok { deepMerge(dm, sm); continue }`, insert:

```go
		if k == "hooks" && dok && sok {
			mergeHooks(dm, sm)
			continue
		}
```

Add:

```go
func mergeHooks(dst, src map[string]any) {
	for event, sv := range src {
		sGroups, _ := toAnySlice(sv)
		dGroups, _ := toAnySlice(dst[event])

		out := make([]any, 0, len(dGroups)+len(sGroups))
		seen := map[string]bool{}
		for _, g := range dGroups {
			if ownedByGuardrail(g) {
				continue // drop; src replaces it
			}
			out = append(out, g)
			seen[jsonKey(g)] = true
		}
		for _, g := range sGroups {
			if ownedByGuardrail(g) {
				out = append(out, g)
				continue
			}
			if k := jsonKey(g); !seen[k] {
				seen[k] = true
				out = append(out, g)
			}
		}
		dst[event] = out
	}
}

func ownedByGuardrail(group any) bool {
	m, ok := group.(map[string]any)
	if !ok {
		return false
	}
	id, _ := m["id"].(string)
	return strings.HasPrefix(id, "guardrail-")
}

func jsonKey(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}
```

Replace the inline closure in `unionAppend` with the shared helper:

```go
func unionAppend(dst, src []any) []any {
	seen := map[string]bool{}
	for _, v := range dst {
		seen[jsonKey(v)] = true
	}
	out := append([]any{}, dst...)
	for _, v := range src {
		if k := jsonKey(v); !seen[k] {
			seen[k] = true
			out = append(out, v)
		}
	}
	return out
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `/usr/local/go/bin/go test ./internal/genconfig/ -v`
Expected: PASS (all genconfig tests, incl. Task 2's and the Plan 2 merge tests).

- [ ] **Step 5: Commit**

```bash
gofmt -w internal/genconfig/
git add internal/genconfig/
git commit -m "feat(genconfig): hooks merge replaces guardrail-owned groups, union-appends user groups"
```

---

### Task 4: Honor `--print=false`

**Files:**
- Modify: `cmd/guardrail/genconfig.go`
- Modify: `cmd/guardrail/genconfig_test.go`

**Interfaces:**
- `cmdGenConfig`: when `--merge` is unset — if `--print` is true, marshal + write stdout (return 0); if `--print` is false, write `guardrail: gen-config: nothing to do (pass --merge <path> or drop --print=false)` to stderr and return `2`.

- [ ] **Step 1: Write the failing test**

Add to `cmd/guardrail/genconfig_test.go`:

```go
func TestGenConfigPrintFalseIsNoOp(t *testing.T) {
	var out, errb bytes.Buffer
	code := run([]string{"gen-config", "claude", "--print=false"}, strings.NewReader(""), &out, &errb)
	if code != 2 {
		t.Fatalf("exit = %d, want 2", code)
	}
	if out.Len() != 0 {
		t.Fatalf("stdout should be empty, got %q", out.String())
	}
	if !strings.Contains(errb.String(), "nothing to do") {
		t.Fatalf("stderr = %q", errb.String())
	}
}

func TestGenConfigDefaultStillPrints(t *testing.T) {
	var out, errb bytes.Buffer
	code := run([]string{"gen-config", "claude"}, strings.NewReader(""), &out, &errb)
	if code != 0 || out.Len() == 0 {
		t.Fatalf("exit=%d stdout=%q", code, out.String())
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `/usr/local/go/bin/go test ./cmd/guardrail/ -run 'TestGenConfigPrintFalse|TestGenConfigDefaultStill' -v`
Expected: FAIL — `--print=false` still prints, exit 0.

- [ ] **Step 3: Write minimal implementation**

In `cmd/guardrail/genconfig.go`, replace the tail (`if *mergePath != ""` block onward) with:

```go
	if *mergePath != "" {
		if err := genconfig.MergeInto(*mergePath, frag); err != nil {
			fmt.Fprintf(stderr, "guardrail: merge failed: %v\n", err)
			return 2
		}
		fmt.Fprintf(stderr, "guardrail: merged Claude config into %s\n", *mergePath)
		return 0
	}

	if !*doPrint {
		fmt.Fprintln(stderr, "guardrail: gen-config: nothing to do (pass --merge <path> or drop --print=false)")
		return 2
	}

	b, err := json.MarshalIndent(frag, "", "  ")
	if err != nil {
		fmt.Fprintf(stderr, "guardrail: cannot marshal config: %v\n", err)
		return 2
	}
	stdout.Write(append(b, '\n'))
	return 0
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `/usr/local/go/bin/go test ./cmd/guardrail/ -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
gofmt -w cmd/guardrail/
git add cmd/guardrail/
git commit -m "fix(cli): gen-config --print=false is now a real no-op (exit 2), not ignored"
```

---

### Task 5: `doctor` — JSON-aware hook detection, distinguish missing vs unreadable

**Files:**
- Modify: `cmd/guardrail/doctor.go`
- Modify: `cmd/guardrail/doctor_test.go`

**Interfaces:**
- `claudeSettingsState() string` — read `~/.claude/settings.json`:
  - read error that `errors.Is(err, fs.ErrNotExist)` ⇒ `"no settings.json"`.
  - other read error ⇒ `"unreadable: <err>"`.
  - parse the JSON; if any `hooks.<event>[]` group has a string `id` with prefix `guardrail-` ⇒ `"guardrail hook registered"`.
  - parse failure ⇒ fall back to `strings.Contains(raw, "guardrail hook claude")` ⇒ `"guardrail hook registered (unparsed match)"` or `"present, hook NOT registered"`.
  - parsed but no owned id ⇒ `"present, hook NOT registered"`.

- [ ] **Step 1: Write the failing test**

Replace `TestDoctorSeesRegisteredHook` and add cases in `cmd/guardrail/doctor_test.go`:

```go
func writeClaudeSettings(t *testing.T, home, body string) {
	t.Helper()
	dir := filepath.Join(home, ".claude")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "settings.json"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestDoctorHookRegisteredByID(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("GUARDRAIL_CONFIG", "")
	writeClaudeSettings(t, home, `{"hooks":{"PreToolUse":[{"id":"guardrail-claude-pre","matcher":"Bash","hooks":[{"type":"command","command":"/opt/guardrail hook claude"}]}]}}`)
	var out, errb bytes.Buffer
	run([]string{"doctor"}, strings.NewReader(""), &out, &errb)
	if !strings.Contains(out.String(), "hook registered") {
		t.Errorf("want registered:\n%s", out.String())
	}
}

func TestDoctorHookNotRegistered(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("GUARDRAIL_CONFIG", "")
	writeClaudeSettings(t, home, `{"theme":"dark"}`)
	var out, errb bytes.Buffer
	run([]string{"doctor"}, strings.NewReader(""), &out, &errb)
	if !strings.Contains(out.String(), "NOT registered") {
		t.Errorf("want NOT registered:\n%s", out.String())
	}
}

func TestDoctorNoSettingsFile(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("GUARDRAIL_CONFIG", "")
	var out, errb bytes.Buffer
	run([]string{"doctor"}, strings.NewReader(""), &out, &errb)
	if !strings.Contains(out.String(), "no settings.json") {
		t.Errorf("want 'no settings.json':\n%s", out.String())
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `/usr/local/go/bin/go test ./cmd/guardrail/ -run TestDoctor -v`
Expected: FAIL — `TestDoctorHookNotRegistered` currently passes only by substring luck; add a case that breaks it: a `settings.json` whose unrelated content contains the literal `guardrail hook claude` in a comment-like string would be a false positive. The three tests above compile-fail first (helper), then `TestDoctorHookRegisteredByID` fails if the code can't see the id when `--binary` isn't literally `guardrail`. (`/opt/guardrail hook claude` does contain the substring, so this one is subtle — keep it; it locks the id-based path in.)

- [ ] **Step 3: Write minimal implementation**

In `cmd/guardrail/doctor.go`: add `"encoding/json"`, `"errors"`, `"io/fs"` to imports. Replace `claudeSettingsState`:

```go
func claudeSettingsState() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return "unknown (no home dir)"
	}
	p := filepath.Join(home, ".claude", "settings.json")
	raw, err := os.ReadFile(p)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return "no settings.json"
		}
		return fmt.Sprintf("unreadable: %v", err)
	}
	var doc map[string]any
	if json.Unmarshal(raw, &doc) == nil {
		if hooksHaveOwnedGroup(doc) {
			return "guardrail hook registered"
		}
		return "present, hook NOT registered"
	}
	if strings.Contains(string(raw), "guardrail hook claude") {
		return "guardrail hook registered (unparsed match)"
	}
	return "present, hook NOT registered"
}

func hooksHaveOwnedGroup(doc map[string]any) bool {
	hooks, ok := doc["hooks"].(map[string]any)
	if !ok {
		return false
	}
	for _, ev := range hooks {
		groups, ok := ev.([]any)
		if !ok {
			continue
		}
		for _, g := range groups {
			m, ok := g.(map[string]any)
			if !ok {
				continue
			}
			if id, _ := m["id"].(string); strings.HasPrefix(id, "guardrail-") {
				return true
			}
		}
	}
	return false
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `/usr/local/go/bin/go test ./cmd/guardrail/ -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
gofmt -w cmd/guardrail/
git add cmd/guardrail/
git commit -m "fix(cli): doctor detects the guardrail hook by owned id; missing vs unreadable settings distinguished"
```

---

### Task 6: Shared `policy.SortedWaivers` helper

**Files:**
- Modify: `internal/policy/policy.go`
- Create: `internal/policy/policy_waivers_test.go`
- Modify: `cmd/guardrail/doctor.go`
- Modify: `cmd/guardrail/hook.go`

**Interfaces:**
- `func policy.SortedWaivers(p *Policy) []string` — keys of `p.Waived` whose value is `true`, `slices.Sort`ed. `nil`-safe (`p == nil` or `p.Waived == nil` ⇒ `nil`).
- `cmd/guardrail/doctor.go` — replace the inline collect+sort with `policy.SortedWaivers(merged)`.
- `cmd/guardrail/hook.go` — replace `waivedList` body (or the function) with `policy.SortedWaivers(merged)`.

- [ ] **Step 1: Write the failing test**

`internal/policy/policy_waivers_test.go`:

```go
package policy

import (
	"slices"
	"testing"
)

func TestSortedWaivers(t *testing.T) {
	p := &Policy{Waived: map[string]bool{"P6": true, "P1.rm-rf": true, "P2": false}}
	got := SortedWaivers(p)
	want := []string{"P1.rm-rf", "P6"}
	if !slices.Equal(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	if SortedWaivers(nil) != nil {
		t.Error("nil policy should give nil")
	}
	if SortedWaivers(&Policy{}) != nil {
		t.Error("nil Waived map should give nil")
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `/usr/local/go/bin/go test ./internal/policy/ -run TestSortedWaivers -v`
Expected: FAIL — undefined.

- [ ] **Step 3: Write minimal implementation**

Add to `internal/policy/policy.go` (add `"slices"` to imports if absent):

```go
// SortedWaivers returns the ids of active waivers in p, sorted. nil-safe.
func SortedWaivers(p *Policy) []string {
	if p == nil || p.Waived == nil {
		return nil
	}
	var out []string
	for k, v := range p.Waived {
		if v {
			out = append(out, k)
		}
	}
	slices.Sort(out)
	return out
}
```

In `cmd/guardrail/doctor.go`, replace lines that collect `waived` + `slices.Sort(waived)` with:

```go
	waived := policy.SortedWaivers(merged)
```

(Keep the `len(waived) == 0` / else print block. Drop the now-unused `slices` import from `doctor.go` if nothing else uses it — the compiler will tell you.)

In `cmd/guardrail/hook.go`, replace the `waivedList` call site with `policy.SortedWaivers(merged)` and delete the local `waivedList` function.

- [ ] **Step 4: Run the test to verify it passes**

Run: `/usr/local/go/bin/go test ./... && /usr/local/go/bin/go vet ./...`
Expected: PASS, vet clean. Fix any now-unused imports (`slices` in `doctor.go`).

- [ ] **Step 5: Commit**

```bash
gofmt -w internal/policy/ cmd/guardrail/
git add internal/policy/ cmd/guardrail/
git commit -m "refactor(policy): shared SortedWaivers helper; drop duplicated collect+sort in doctor and hook"
```

---

### Task 7: Untrack the built binary; add `vet` + `check` Makefile targets

**Files:**
- Modify: `Makefile`
- Remove from index: `guardrail`

- [ ] **Step 1: Untrack the binary**

Run:
```bash
git rm --cached guardrail
git status   # guardrail now untracked; .gitignore already covers /guardrail
```
Expected: `guardrail` staged for deletion-from-index only (file stays on disk).

- [ ] **Step 2: Extend the Makefile**

Replace the `.PHONY` lines and append targets so the file reads:

```make
GO ?= /usr/local/go/bin/go
VERSION ?= dev
CGO_ENABLED ?= 0

.PHONY: build test fmt contract golden vet check dist

build:
	$(GO) build -ldflags "-X main.version=$(VERSION)" -o guardrail ./cmd/guardrail

test:
	$(GO) test ./...

vet:
	$(GO) vet ./...

fmt:
	$(GO) fmt ./...

check: test vet
	@test -z "$$($(GO) run cmd/gofmt -l . 2>/dev/null || gofmt -l .)" || { echo "gofmt needed:"; gofmt -l .; exit 1; }

contract:
	$(GO) test ./test/ -v

golden:
	$(GO) test ./test/ -run Golden -update

dist:
	./scripts/build-dist.sh
```

(`scripts/build-dist.sh` is created in Task 10; `make dist` will fail until then — that is expected and noted.)

- [ ] **Step 3: Verify**

Run: `make check`
Expected: `test` + `vet` pass; the gofmt gate prints nothing and exits 0.

- [ ] **Step 4: Commit**

```bash
git add Makefile
git commit -m "chore: untrack built binary; add make vet/check targets"
```

---

## Arc B — CI and the first real release

### Task 8: Make the `test/` build helper CI-portable

**Files:**
- Modify: `test/contract_test.go`

**Interfaces:**
- `func goCmd() string` (package `test`) — `os.Getenv("GUARDRAIL_GO")` if non-empty; else `"go"` if `exec.LookPath("go")` succeeds; else `"/usr/local/go/bin/go"`.
- `buildBinary` uses `goCmd()` instead of the hardcoded path.

- [ ] **Step 1: Write the failing test**

Add to `test/contract_test.go`:

```go
func TestGoCmdResolves(t *testing.T) {
	got := goCmd()
	if got == "" {
		t.Fatal("goCmd returned empty")
	}
	// it must be runnable
	if err := exec.Command(got, "version").Run(); err != nil {
		t.Fatalf("goCmd() = %q is not runnable: %v", got, err)
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `/usr/local/go/bin/go test ./test/ -run TestGoCmdResolves -v`
Expected: FAIL — `goCmd` undefined.

- [ ] **Step 3: Write minimal implementation**

In `test/contract_test.go`, add and rewire:

```go
func goCmd() string {
	if v := os.Getenv("GUARDRAIL_GO"); v != "" {
		return v
	}
	if _, err := exec.LookPath("go"); err == nil {
		return "go"
	}
	return "/usr/local/go/bin/go"
}

func buildBinary(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "guardrail")
	out, err := exec.Command(goCmd(), "build", "-o", bin, "../cmd/guardrail").CombinedOutput()
	if err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	return bin
}
```

(Ensure `"os"` is imported in `contract_test.go` — it already is for `os.Environ()`.)

- [ ] **Step 4: Run the test to verify it passes**

Run: `/usr/local/go/bin/go test ./test/ -v`
Expected: PASS (locally `go` is not on PATH → falls back to `/usr/local/go/bin/go`).

- [ ] **Step 5: Commit**

```bash
gofmt -w test/
git add test/
git commit -m "test: goCmd() helper so the build tests run in CI (go on PATH) and locally (fallback path)"
```

---

### Task 9: `ci.yml` — build/test/vet/gofmt gate

**Files:**
- Create: `.github/workflows/ci.yml`

**Interfaces:** GitHub Actions. Triggers on push to any branch and on PR. Two-OS matrix.

- [ ] **Step 1: Write the workflow**

`.github/workflows/ci.yml`:

```yaml
name: CI

on:
  push:
    branches: ["**"]
    tags-ignore: ["**"]
  pull_request:

permissions:
  contents: read

jobs:
  test:
    strategy:
      fail-fast: false
      matrix:
        os: [ubuntu-latest, windows-latest]
    runs-on: ${{ matrix.os }}
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version: "1.23"
          check-latest: true
      - run: go build ./...
      - run: go vet ./...
      - run: go test ./...
      - name: gofmt
        if: matrix.os == 'ubuntu-latest'
        run: |
          unformatted="$(gofmt -l .)"
          if [ -n "$unformatted" ]; then
            echo "These files need gofmt:"; echo "$unformatted"; exit 1
          fi
```

- [ ] **Step 2: Validate the YAML**

Run:
```bash
command -v actionlint >/dev/null && actionlint .github/workflows/ci.yml || echo "actionlint not installed — first push will validate"
/usr/local/go/bin/go run gopkg.in/yaml.v3 2>/dev/null || python3 -c "import yaml,sys; yaml.safe_load(open('.github/workflows/ci.yml'))" && echo "YAML parses"
```
Expected: `actionlint` clean (if present); YAML parses.

- [ ] **Step 3: Commit**

```bash
git add .github/workflows/ci.yml
git commit -m "ci: build/test/vet/gofmt on push and PR (ubuntu + windows)"
```

---

### Task 10: `release.yml` + `scripts/build-dist.sh`

**Files:**
- Create: `.github/workflows/release.yml`
- Create: `scripts/build-dist.sh`

**Interfaces:**
- `scripts/build-dist.sh` — cross-compiles the 6 targets into `dist/`, writes `dist/SHA256SUMS`. Reads the version from `git describe --tags --always` unless `$VERSION` is set. Executable.
- `release.yml` — on tag push `v*`: run `scripts/build-dist.sh` with `VERSION=<tag>`, then `gh release create <tag> --generate-notes --verify-tag dist/guardrail_* dist/SHA256SUMS`.

- [ ] **Step 1: Write `scripts/build-dist.sh`**

```bash
#!/usr/bin/env bash
# Cross-compile the guardrail binary for every supported platform into dist/
# and emit dist/SHA256SUMS. Used by `make dist` and by .github/workflows/release.yml.
set -euo pipefail

GO="${GO:-go}"
command -v "$GO" >/dev/null || GO=/usr/local/go/bin/go

VERSION="${VERSION:-$(git describe --tags --always 2>/dev/null || echo dev)}"
OUT="dist"
rm -rf "$OUT"
mkdir -p "$OUT"

targets="linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64"
for t in $targets; do
  goos="${t%/*}"; goarch="${t#*/}"
  ext=""; [ "$goos" = "windows" ] && ext=".exe"
  name="guardrail_${goos}_${goarch}${ext}"
  echo "building $name ($VERSION)"
  CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch" "$GO" build \
    -trimpath -ldflags "-s -w -X main.version=${VERSION}" \
    -o "$OUT/$name" ./cmd/guardrail
done

( cd "$OUT" && sha256sum guardrail_* > SHA256SUMS )
echo "---"
cat "$OUT/SHA256SUMS"
```

- [ ] **Step 2: Make it executable and smoke it locally**

Run:
```bash
chmod +x scripts/build-dist.sh
VERSION=v0.0.0-test ./scripts/build-dist.sh
ls -1 dist/
file dist/guardrail_linux_arm64 dist/guardrail_windows_amd64.exe
( cd dist && sha256sum -c SHA256SUMS )
dist/guardrail_linux_amd64 version   # if on linux/amd64: prints "guardrail v0.0.0-test"
```
Expected: 6 binaries + `SHA256SUMS`; `file` reports `ARM aarch64` and `PE32+ ... x86-64`; `sha256sum -c` says `OK` for all 6.

- [ ] **Step 3: Write `release.yml`**

`.github/workflows/release.yml`:

```yaml
name: Release

on:
  push:
    tags: ["v*"]

permissions:
  contents: write

jobs:
  release:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - uses: actions/setup-go@v5
        with:
          go-version: "1.23"
          check-latest: true
      - name: Build release artifacts
        env:
          VERSION: ${{ github.ref_name }}
        run: ./scripts/build-dist.sh
      - name: Publish GitHub Release
        env:
          GH_TOKEN: ${{ github.token }}
        run: |
          gh release create "${{ github.ref_name }}" \
            --title "${{ github.ref_name }}" \
            --generate-notes \
            --verify-tag \
            dist/guardrail_* dist/SHA256SUMS
```

- [ ] **Step 4: Validate**

Run: `command -v actionlint >/dev/null && actionlint .github/workflows/release.yml || echo "will validate on first tag"`
Expected: clean or deferred.

- [ ] **Step 5: Commit**

```bash
git add .github/workflows/release.yml scripts/build-dist.sh
git commit -m "ci: tag-triggered cross-compile + SHA256SUMS + gh release; scripts/build-dist.sh"
```

---

### Task 11: Push, tag `v0.3.0`, verify the release

**Files:** none (release action).

- [ ] **Step 1: Full local green**

Run: `make check && /usr/local/go/bin/go test ./... && rm -rf dist`
Expected: all pass; `dist/` removed so it doesn't get committed.

- [ ] **Step 2: Push the branch and confirm CI**

```bash
git push origin main
```
Then watch: `gh run list --branch main --limit 3` → the `CI` workflow run for the latest commit is `completed / success` (ubuntu + windows). If it fails, fix forward and re-push before tagging.

- [ ] **Step 3: Tag and push the release**

```bash
git tag v0.3.0
git push origin v0.3.0
```

- [ ] **Step 4: Verify the release**

```bash
gh run list --workflow Release --limit 1     # completed / success
gh release view v0.3.0
```
Expected: the release exists with **7 assets** — `guardrail_{linux,darwin,windows}_{amd64,arm64}` (windows with `.exe`) plus `SHA256SUMS`. Download one and spot-check:
```bash
gh release download v0.3.0 -p 'guardrail_linux_amd64' -p 'SHA256SUMS' -D /tmp/grv
( cd /tmp/grv && sha256sum -c --ignore-missing SHA256SUMS )
/tmp/grv/guardrail_linux_amd64 version    # -> guardrail v0.3.0
```
Expected: `guardrail_linux_amd64: OK`; version prints `v0.3.0`.

- [ ] **Step 5: If the Release workflow failed**

Delete the tag remotely and locally, fix `release.yml` / `build-dist.sh`, re-commit, re-tag:
```bash
git push --delete origin v0.3.0 && git tag -d v0.3.0
# ...fix, commit...
git tag v0.3.0 && git push origin v0.3.0
```
Do **not** move a tag that already has a published release with downloads — if `v0.3.0` published partially, bump to `v0.3.1`.

---

### Task 12: Docs + self-review

**Files:**
- Modify: `README.md`
- Modify: `docs/HANDOFF-2026-09-03.md`

- [ ] **Step 1: Update `README.md` Status**

Replace the Status body:

```markdown
## Status

Plans 1–3 implemented. `guardrail hook claude` enforces P1/P4 with audit logging and
per-repo `guardrail.toml` overlays; `guardrail gen-config claude` emits/merges the
Claude declarative floor with marker-based owned-entry replacement (safe to re-run
and to rebind `--binary`); `guardrail doctor` reports resolved state. CI builds and
tests on push (ubuntu + windows); `v*` tags publish checksummed cross-platform
binaries to GitHub Releases (`v0.3.0` is the first). Pending: chezmoi installer +
real-Claude smoke test (Plan 3b), policy modules P2/P5/P6/P7/P10 (Plan 4), opencode
adapter (Plan 5), Antigravity adapter (Plan 6), recipes + `guardrail sync` (Plan 7).
```

- [ ] **Step 2: Update the HANDOFF plan table**

In `docs/HANDOFF-2026-09-03.md`, split the Plan 3 row:

```
| **3** | agent-guardrails: ADR-0004 + owned-entry hook merge, `--print=false` fix, doctor cleanups, `ci.yml` + `release.yml`, first real release `v0.3.0`. | **DONE** — `docs/superpowers/plans/2026-09-04-owned-entry-merge-and-ci-release.md`. |
| **3b** | chezmoi: `install_agent_guardrails()` in `run_onchange_install_packages.{sh,ps1}.tmpl` (download pinned release binary → checksum-verify → `~/.local/bin/guardrail` → `guardrail gen-config claude --merge ~/.claude/settings.json --binary ...`), `.chezmoi.toml.tmpl` toggle, `update_ai_tools.*` section, `docs/tool-parity.md` row; + `make smoke` driving real `claude`. Cross-repo. | Not written |
```

Keep Plan 4 (policy modules) and below unchanged.

- [ ] **Step 3: Commit**

```bash
git add README.md docs/HANDOFF-2026-09-03.md
git commit -m "docs: Plan 3 done (owned-entry merge + CI + v0.3.0); HANDOFF adds Plan 3b"
git push origin main
```

---

## Self-Review

**1. Spec coverage.**

| Item | Task |
|---|---|
| Ruling 8 — marker-based owned hook entries; ADR | 1, 2, 3 |
| `--merge` idempotent on re-run and on `--binary` change | 3 |
| `permissions` stays union-append (fail-safe) | 3 (`TestPermissionsStillUnionAppend`) |
| `--print=false` no longer silently prints | 4 |
| doctor: JSON-aware hook detection, missing vs unreadable | 5 |
| doctor/hook waiver dedup (parked papercut) | 6 |
| untrack the committed `./guardrail` binary | 7 |
| CI build/test/vet/gofmt on push + PR | 9 (after 8 makes it possible) |
| tag → checksummed cross-platform release | 10, 11 |
| first real release `v0.3.0` | 11 |

Deferred, by design: the chezmoi installer function, `.chezmoi.toml.tmpl` toggle, `update_ai_tools.*` section, `docs/tool-parity.md` row, `Unblock-File`, and the real-`claude` smoke test are **Plan 3b** — they need the `v0.3.0` release (Task 11) to exist first. Parked papercuts not addressed here (golden swallows stderr, `-run Golden` breadth, untested doctor branches) are noted for Plan 3b polish.

**2. Placeholder scan.** No `TBD`/"handle errors"/"similar to". `make dist` is documented as failing until Task 10 creates `scripts/build-dist.sh` — a real intermediate state, not a placeholder. Every YAML and shell block is literal.

**3. Type consistency.**
- `genconfig.claudeHooks(string) map[string]any` — id fields added Task 2, consumed by `mergeHooks`/`ownedByGuardrail` Task 3.
- `genconfig.mergeHooks(dst, src map[string]any)` / `ownedByGuardrail(any) bool` / `jsonKey(any) string` — Task 3; `jsonKey` also replaces the inline closure in `unionAppend` (same package, same signature).
- `deepMerge` gains one `if k == "hooks"` branch — Task 3; does not change its signature.
- `genconfig.MergeInto` / `Fragment` — unchanged from Plan 2.
- `cmdGenConfig(args []string, stdout, stderr io.Writer) int` — behavior change only (Task 4), signature stable.
- `claudeSettingsState() string` + new `hooksHaveOwnedGroup(map[string]any) bool` — Task 5, `package main`.
- `policy.SortedWaivers(*Policy) []string` — Task 6; replaces inline code in `cmd/guardrail/doctor.go` and the `waivedList` func in `cmd/guardrail/hook.go` (that func is deleted; `hook.go`'s `audit.Record.Waivers` field is now filled by `policy.SortedWaivers(merged)`).
- `test.goCmd() string` + `buildBinary(*testing.T) string` — Task 8; `buildBinary` signature unchanged, `genconfig_test.go`'s reuse still compiles.
- `Makefile` `dist` target → `scripts/build-dist.sh` (Task 7 declares, Task 10 creates).
- Workflows reference `scripts/build-dist.sh` with `VERSION` env = `github.ref_name` (Task 10) — the script reads `${VERSION:-$(git describe ...)}`.

No drift. `actions/checkout@v4` + `actions/setup-go@v5` are the pinned majors; `gh` is preinstalled on `ubuntu-latest`.

---

## Execution Handoff

**Plan complete and saved to `docs/superpowers/plans/2026-09-04-owned-entry-merge-and-ci-release.md`. Two execution options:**

**1. Subagent-Driven (recommended)** — fresh subagent per task via `superpowers:subagent-driven-development`, review between tasks.

**2. Inline Execution** — `superpowers:executing-plans`, batch with checkpoints.

**Which approach?**
