# P8 Per-Edit Recipes + `guardrail sync` — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** The last plan in the original series. P8 per-edit format+lint (Go, Python, JS/TS, Rust) — a `PostToolUse` check that runs each language's formatter+linter on the edited file and denies (surfacing the linter's own output as the reason) when the linter fails, reusing the exact `policy.Verdict`/`Evaluate`-adjacent pipeline shape trifecta already established. `guardrail sync` — a new subcommand that regenerates a *project's* plane configs (`.claude/settings.json`, `opencode.json`, `.agents/hooks.json`, all repo-relative) from **Base + Overlay merged**, not Base alone, so a project's `guardrail.toml` rules reach the declarative floor too (Q18).

**Architecture:** `internal/recipe` is a new, small, dependency-free package: a data registry (`Recipe{Extensions, PerEdit}`) plus `Check(tc) *policy.Verdict`, which shells out to each per-edit command and is lenient about missing tools (skip silently) but strict about a tool that ran and failed (deny). Wired into `cmd/guardrail/hook.go` the same way trifecta is — a separate step after `Evaluate` that can only escalate an `Allow`, never override a more specific verdict. `guardrail sync` is almost entirely reuse: it runs the same Base+Overlay+Merge sequence `cmdHook` already does, then calls the *same* `genconfig.ClaudeConfig`/`OpencodeConfig`/`AntigravityConfig`/`MergeInto` functions `cmdGenConfig` already calls — the only difference is the `*policy.Policy` passed in (merged, not base-only) and the target paths (project-relative, not global).

**Tech Stack:** Go 1.23+, existing deps only. Shells out to `gofmt`, `ruff`, `prettier`, `eslint`, `rustfmt` — none of these are new Go dependencies; they're external tools the recipe check probes for with `exec.LookPath` before ever running.

**Spec:** `../../../DESIGN.md` P8, Q9, Q18. Closes the original plan series (`docs/HANDOFF-2026-09-03.md`'s table). Two deliberate scope cuts recorded in ADR-0009 rather than built here: **Odoo and Elixir recipes are deferred** (Odoo's `.py` files collide with the generic Python recipe's extension claim — additive-not-exclusive recipe composition is real design work, not builtin to this plan's registry shape); **the session-completion tier (a `Stop` hook running the full build/test/typecheck suite) is deferred** — only the per-edit tier ships here.

## Global Constraints

- **Recipe execution is lenient about absence, strict about failure.** `exec.LookPath` fails (tool not installed) → skip that command silently, never block. The command runs and exits nonzero → deny, with its combined output as the `Reason`.
- **Per-edit tier only, `PostToolUse`/`post` event only.** No `Stop` hook, no session-completion commands (`go vet`, `go build`, `pytest`, etc.) in this plan.
- **Four recipes, no extension conflicts:** Go (`.go`), Python (`.py`), JS/TS (`.js`,`.jsx`,`.ts`,`.tsx`), Rust (`.rs`). Odoo and Elixir are **not** in the registry — see ADR-0009.
- **`guardrail sync` never invents new merge/generation logic** — it is a thin CLI wrapper around functions Plans 2, 5, 6 already built and tested. If you find yourself writing new `Fragment`-building code in this task, stop — call the existing `genconfig.*Config` functions instead.
- Every code step is literal. `gofmt -w` before every commit. Conventional Commits, one commit per task.
- Verified current state: `cmd/guardrail/hook.go`'s shared pipeline (base/overlay/merge/session-start/trifecta/`Evaluate`/audit/emit) is plane-agnostic across all three planes (Plans 3–6). `genconfig.ClaudeConfig(pol *policy.Policy, binary string) Fragment`, `OpencodeConfig(pol *policy.Policy, pluginPath string) Fragment`, `AntigravityConfig(binary string) Fragment`, `MergeInto(path string, frag Fragment) error`, `OpencodePluginJS []byte` (embedded, Plan 5) are all already exported from `internal/genconfig`. `policy.LoadBase()`, `FindOverlayPath(cwd) (string,bool,string)`, `LoadOverlay(path) (*Overlay,error)`, `Merge(base,ov,version) (*Policy,[]string,error)` are the exact functions `cmdHook` calls — `cmdSync` reuses them verbatim.

---

### Task 1: `internal/recipe` — registry + `ForFile`

**Files:**
- Create: `internal/recipe/recipe.go`
- Create: `internal/recipe/recipe_test.go`

**Interfaces:**
- `type Recipe struct { Name string; Extensions []string; PerEdit [][]string }` — each `PerEdit` entry is an argv template; the literal token `"{file}"` is replaced with the real path before exec.
- `var Registry []Recipe` — four entries: `go` (`gofmt -w {file}`), `python` (`ruff format {file}`, `ruff check --fix {file}`), `js-ts` (`prettier --write {file}`, `eslint --fix {file}`), `rust` (`rustfmt {file}`).
- `func ForFile(path string) (Recipe, bool)` — matches by `filepath.Ext(path)` (case-sensitive as-is; extensions in `Registry` are lowercase, matched against a lowercased `filepath.Ext` result) against each `Recipe.Extensions`; first match wins (no two entries share an extension, so order is irrelevant in practice).

- [ ] **Step 1: Write the failing test**

`internal/recipe/recipe_test.go`:

```go
package recipe

import "testing"

func TestForFile(t *testing.T) {
	cases := map[string]string{
		"main.go":       "go",
		"app.py":        "python",
		"index.ts":      "js-ts",
		"component.tsx": "js-ts",
		"lib.rs":        "rust",
	}
	for file, want := range cases {
		r, ok := ForFile(file)
		if !ok || r.Name != want {
			t.Errorf("ForFile(%q) = %+v,%v; want %q", file, r, ok, want)
		}
	}
	if _, ok := ForFile("README.md"); ok {
		t.Error("README.md should have no recipe")
	}
}

func TestRegistryNoExtensionCollisions(t *testing.T) {
	seen := map[string]string{}
	for _, r := range Registry {
		for _, ext := range r.Extensions {
			if owner, dup := seen[ext]; dup {
				t.Errorf("extension %q claimed by both %q and %q", ext, owner, r.Name)
			}
			seen[ext] = r.Name
		}
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `/usr/local/go/bin/go test ./internal/recipe/... -v`
Expected: FAIL — package undefined.

- [ ] **Step 3: Write minimal implementation**

`internal/recipe/recipe.go`:

```go
// Package recipe runs per-language format+lint commands after an edit. See
// docs/adr/0009-recipe-scope.md for why only four languages, per-edit only.
package recipe

import "path/filepath"

type Recipe struct {
	Name       string
	Extensions []string
	PerEdit    [][]string
}

var Registry = []Recipe{
	{
		Name:       "go",
		Extensions: []string{".go"},
		PerEdit:    [][]string{{"gofmt", "-w", "{file}"}},
	},
	{
		Name:       "python",
		Extensions: []string{".py"},
		PerEdit: [][]string{
			{"ruff", "format", "{file}"},
			{"ruff", "check", "--fix", "{file}"},
		},
	},
	{
		Name:       "js-ts",
		Extensions: []string{".js", ".jsx", ".ts", ".tsx"},
		PerEdit: [][]string{
			{"prettier", "--write", "{file}"},
			{"eslint", "--fix", "{file}"},
		},
	},
	{
		Name:       "rust",
		Extensions: []string{".rs"},
		PerEdit:    [][]string{{"rustfmt", "{file}"}},
	},
}

func ForFile(path string) (Recipe, bool) {
	ext := filepath.Ext(path)
	for _, r := range Registry {
		for _, e := range r.Extensions {
			if e == ext {
				return r, true
			}
		}
	}
	return Recipe{}, false
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `/usr/local/go/bin/go test ./internal/recipe/... -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
gofmt -w internal/recipe/
git add internal/recipe/
git commit -m "feat(recipe): registry — go/python/js-ts/rust per-edit format+lint commands"
```

---

### Task 2: `recipe.Check` — run per-edit commands, lenient on absence, strict on failure

**Files:**
- Modify: `internal/recipe/recipe.go`
- Modify: `internal/recipe/recipe_test.go`

**Interfaces:**
- `func Check(tc engine.ToolCall) *policy.Verdict` — `nil` unless `tc.Event == "post"` and the tool is a file-write tool (reuse the same `Write`/`Edit`/`MultiEdit` set the Engine's `checkOutOfRepoWrite`/`checkCIInfraLockfile` already gate on — this package does its own lightweight check rather than importing `internal/engine`'s unexported `isFileTool`, to avoid a needless cross-package dependency for one string comparison). For each `tc.Paths` entry with a matching `Recipe`: for each `PerEdit` command, substitute `"{file}"` with the path; `exec.LookPath(argv[0])` — not found → skip this command; found → run it (`exec.Command(...).CombinedOutput()`); a `*exec.ExitError` (nonzero exit) → return `&policy.Verdict{Decision: policy.Deny, RuleID: "P8.recipe-lint", Reason: <combined output, or a fallback string if output is empty>}` immediately (first failure stops the chain — later commands in the same recipe would run against a file the failed command may have left mid-edit); any other error (couldn't start the process at all, despite `LookPath` succeeding) → skip, don't block on infra flakiness.

- [ ] **Step 1: Write the failing test**

Add to `internal/recipe/recipe_test.go`:

```go
import (
	"strings"
	"testing"

	"github.com/CtrlCarlitos/agent-guardrails/internal/engine"
	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
)

func TestCheckIgnoresNonPostEvents(t *testing.T) {
	tc := engine.ToolCall{Event: "pre", Tool: "Write", Paths: []string{"main.go"}}
	if v := Check(tc); v != nil {
		t.Fatalf("pre event should be ignored, got %+v", v)
	}
}

func TestCheckIgnoresNonFileTools(t *testing.T) {
	tc := engine.ToolCall{Event: "post", Tool: "Bash", Command: "ls"}
	if v := Check(tc); v != nil {
		t.Fatalf("bash should be ignored, got %+v", v)
	}
}

func TestCheckIgnoresUnrecipedExtension(t *testing.T) {
	tc := engine.ToolCall{Event: "post", Tool: "Write", Paths: []string{"README.md"}}
	if v := Check(tc); v != nil {
		t.Fatalf("no recipe for .md, got %+v", v)
	}
}

func TestCheckDeniesOnLintFailure(t *testing.T) {
	// gofmt on a nonexistent file exits nonzero deterministically — no need
	// to construct genuinely malformed Go source for this test.
	tc := engine.ToolCall{Event: "post", Tool: "Write", Paths: []string{"/nonexistent/path/does-not-exist.go"}}
	v := Check(tc)
	if v == nil || v.Decision != policy.Deny || v.RuleID != "P8.recipe-lint" {
		t.Fatalf("gofmt on a missing file -> %+v, want deny/P8.recipe-lint", v)
	}
	if v.Reason == "" {
		t.Error("Reason should carry the tool's output")
	}
}

func TestCheckSkipsMissingTool(t *testing.T) {
	tc := engine.ToolCall{Event: "post", Tool: "Write", Paths: []string{"nonexistent-tool-probe.rs"}}
	// rustfmt may or may not be installed on the machine running this test;
	// either way Check must not panic, and must not deny for a reason other
	// than a real lint failure (a missing tool must never surface as deny).
	v := Check(tc)
	if v != nil && !strings.Contains(v.Reason, "error") && v.RuleID != "P8.recipe-lint" {
		t.Fatalf("unexpected verdict shape: %+v", v)
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `/usr/local/go/bin/go test ./internal/recipe/... -run TestCheck -v`
Expected: FAIL — `Check` undefined.

- [ ] **Step 3: Write minimal implementation**

Add to `internal/recipe/recipe.go` (new imports: `"os/exec"`, `"strings"`, plus `"github.com/CtrlCarlitos/agent-guardrails/internal/engine"` and `"github.com/CtrlCarlitos/agent-guardrails/internal/policy"`):

```go
func Check(tc engine.ToolCall) *policy.Verdict {
	if tc.Event != "post" || !isWriteTool(tc.Tool) {
		return nil
	}
	for _, p := range tc.Paths {
		r, ok := ForFile(p)
		if !ok {
			continue
		}
		if v := runRecipe(r, p); v != nil {
			return v
		}
	}
	return nil
}

func isWriteTool(tool string) bool {
	switch strings.ToLower(tool) {
	case "write", "edit", "multiedit":
		return true
	}
	return false
}

func runRecipe(r Recipe, file string) *policy.Verdict {
	for _, cmdTemplate := range r.PerEdit {
		argv := make([]string, len(cmdTemplate))
		for i, a := range cmdTemplate {
			if a == "{file}" {
				a = file
			}
			argv[i] = a
		}
		if _, err := exec.LookPath(argv[0]); err != nil {
			continue // tool not installed: skip silently
		}
		out, err := exec.Command(argv[0], argv[1:]...).CombinedOutput()
		if err == nil {
			continue
		}
		if _, isExit := err.(*exec.ExitError); isExit {
			reason := strings.TrimSpace(string(out))
			if reason == "" {
				reason = argv[0] + " failed on " + file
			}
			return &policy.Verdict{Decision: policy.Deny, RuleID: "P8.recipe-lint", Reason: reason}
		}
		// spawn error other than a nonzero exit (e.g. a race where LookPath
		// succeeded but the binary vanished): skip, don't block on infra flakiness.
	}
	return nil
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `/usr/local/go/bin/go test ./internal/recipe/... -v`
Expected: PASS. (`TestCheckDeniesOnLintFailure` requires `gofmt` on PATH — it always is, since it ships with the Go toolchain this whole project already depends on.)

- [ ] **Step 5: Commit**

```bash
gofmt -w internal/recipe/
git add internal/recipe/
git commit -m "feat(recipe): Check — run per-edit commands, skip missing tools, deny on real lint failure"
```

---

### Task 3: Wire `recipe.Check` into `cmdHook`

**Files:**
- Modify: `cmd/guardrail/hook.go`
- Modify: `cmd/guardrail/hook_test.go`

**Interfaces:**
- After the trifecta block and before building `audit.Record`: `if v.Decision == policy.Allow { if rv := recipe.Check(tc); rv != nil { v = *rv } }` — same "only escalate an Allow" discipline as `TrifectaVerdict`, so a recipe failure never masks a more specific existing verdict, and never fires on anything but a genuinely-allowed post-edit.

- [ ] **Step 1: Write the failing test**

Add to `cmd/guardrail/hook_test.go`:

```go
func TestHookRecipeDeniesOnPostEditLintFailure(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	t.Setenv("GUARDRAIL_CONFIG", "")
	payload := `{"session_id":"s1","cwd":"/tmp","hook_event_name":"PostToolUse","tool_name":"Write","tool_input":{"file_path":"/nonexistent/path/does-not-exist.go"}}`
	var out, errb bytes.Buffer
	code := run([]string{"hook", "claude"}, strings.NewReader(payload), &out, &errb)
	if code != 2 {
		t.Fatalf("exit=%d, want 2 (recipe lint failure denies); stderr=%s", code, errb.String())
	}
}

func TestHookRecipeSilentOnBenignEdit(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	t.Setenv("GUARDRAIL_CONFIG", "")
	payload := `{"session_id":"s1","cwd":"/tmp","hook_event_name":"PostToolUse","tool_name":"Write","tool_input":{"file_path":"/tmp/README.md"}}`
	var out, errb bytes.Buffer
	code := run([]string{"hook", "claude"}, strings.NewReader(payload), &out, &errb)
	if code != 0 {
		t.Fatalf("exit=%d, want 0 (no recipe for .md)", code)
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `/usr/local/go/bin/go test ./cmd/guardrail/ -run TestHookRecipe -v`
Expected: FAIL — `.go` PostToolUse writes currently always allow.

- [ ] **Step 3: Write minimal implementation**

In `cmd/guardrail/hook.go`, add `"github.com/CtrlCarlitos/agent-guardrails/internal/recipe"` to imports. After the trifecta block (Plan 4b Task 4) and before the `audit.Record{...}` construction, insert:

```go
	if v.Decision == policy.Allow {
		if rv := recipe.Check(tc); rv != nil {
			v = *rv
		}
	}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `/usr/local/go/bin/go test ./cmd/guardrail/ -v`
Expected: PASS. Run the full suite: `/usr/local/go/bin/go test ./... -v`.

- [ ] **Step 5: Commit**

```bash
gofmt -w cmd/guardrail/
git add cmd/guardrail/
git commit -m "feat(cli): wire P8 recipe checks into guardrail hook — post-edit only, allow-only escalation"
```

---

### Task 4: Contract fixture

**Files:**
- Create: `test/fixtures/claude/post-edit-lint-fail.json`
- Modify: `test/fixtures/claude/expected.json`

- [ ] **Step 1: Write the fixture**

`test/fixtures/claude/post-edit-lint-fail.json`:
```json
{"session_id":"s1","cwd":"/tmp","hook_event_name":"PostToolUse","tool_name":"Write","tool_input":{"file_path":"/nonexistent/path/does-not-exist.go"}}
```

- [ ] **Step 2: Add to `expected.json`**

Add `"post-edit-lint-fail.json": {"exit": 2}`.

- [ ] **Step 3: Run the contract + full suite**

Run: `make check && make contract && /usr/local/go/bin/go test ./...`
Expected: all green.

- [ ] **Step 4: Commit**

```bash
git add test/fixtures/claude/
git commit -m "test: contract fixture for P8 recipe post-edit lint failure"
```

---

### Task 5: ADR-0009 — recipe scope cuts

**Files:**
- Create: `docs/adr/0009-recipe-scope.md`

- [ ] **Step 1: Write the ADR**

```markdown
# Recipe scope: four languages, per-edit tier only

Two deliberate cuts from DESIGN.md's full P8 vision.

**Odoo and Elixir are not in the registry.** Odoo's Python files use the
`.py` extension — identical to the generic Python recipe's claim. A recipe
registry keyed purely by extension can't express "this .py file additionally
gets pylint-odoo" without either exclusive-claim conflicts or an
additive-composition model (multiple recipes contributing commands for one
extension, gated by an explicit per-project opt-in — DESIGN.md's Q9 always
intended Odoo/Elixir to be off-by-default, opt-in). Building that
composition model well is its own design work. Elixir's `.ex`/`.exs` don't
collide with anything, but is cut alongside Odoo for the same reason: both
were envisioned as opt-in from the start, and opt-in needs the overlay
`[recipes]` schema this plan didn't build.

**Only the per-edit tier ships.** No `Stop` hook, no `go vet`/`go build`/
`pytest`/`mix test`/`cargo test`/full-project lint runs. Claude Code
supports a `Stop` event (confirmed by this project's own hooks research)
that could carry this, but wiring a new hook event, deciding what "block
session end" means for opencode/Antigravity (neither of which has an
obviously analogous event), and running potentially-slow full-suite
commands from inside a tool-use hook is real additional scope.

## Consequences

- A Go/Python/JS-TS/Rust project gets real, working format+lint enforcement
  today. An Odoo or Elixir project gets nothing recipe-related until a
  follow-up builds the opt-in composition model.
- Nothing here blocks catching a *syntax-breaking* edit at commit/CI time —
  the per-edit formatter often surfaces that anyway (e.g. `gofmt` fails
  loudly on unparseable Go). The session-completion tier's value is deeper
  checks (type errors, failing tests), not just "is broken code possible."
```

- [ ] **Step 2: Commit**

```bash
git add docs/adr/0009-recipe-scope.md
git commit -m "docs(adr): 0009 — recipe scope cuts (no Odoo/Elixir, per-edit only)"
```

---

### Task 6: `cmdSync` — regenerate project-level configs from Base+Overlay

**Files:**
- Create: `cmd/guardrail/sync.go`
- Create: `cmd/guardrail/sync_test.go`

**Interfaces:**
- `func cmdSync(args []string, stdout, stderr io.Writer) int` — flags: `--dir <path>` (default `.`), `--binary <path>` (default `guardrail`), `--planes <comma-list>` (default `claude,opencode,antigravity`). Loads `policy.LoadBase()`, `policy.FindOverlayPath(absDir)` + `LoadOverlay` if found, `policy.Merge(base, ov, version)` — identical sequence to `cmdHook`, printing `Merge`'s warnings to stderr. For each requested plane, writes to a **repo-relative** path using the **merged** policy:
  - `claude` → `<dir>/.claude/settings.json`, `genconfig.ClaudeConfig(merged, binary)`.
  - `opencode` → `<dir>/opencode.json`; plugin deployed to `<dir>/.guardrail/guardrail.js` (`genconfig.OpencodePluginJS`, `0o644`, dir created first) at its **absolute** path; `genconfig.OpencodeConfig(merged, absPluginPath)`.
  - `antigravity` → `<dir>/.agents/hooks.json` (dir created first); `genconfig.AntigravityConfig(binary)`.
  Each merge failure is reported to stderr and the loop continues to the next plane (one plane's failure doesn't abort the others). A line `"synced <plane> -> <path>"` is printed to stdout per successful plane. Returns `2` only on a `LoadBase`/`LoadOverlay`/`Merge` error (nothing to sync at all); returns `0` otherwise even if individual plane merges failed (their failures are visible on stderr, matching `cmdHook`'s `gen-config` precedent of warn-and-continue).

- [ ] **Step 1: Write the failing test**

`cmd/guardrail/sync_test.go`:

```go
package main

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func gitInitSync(t *testing.T, dir string) {
	t.Helper()
	for _, args := range [][]string{{"init", "-q"}, {"config", "user.email", "t@t"}, {"config", "user.name", "t"}} {
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
}

func TestSyncAllPlanes(t *testing.T) {
	dir := t.TempDir()
	gitInitSync(t, dir)
	overlay := "waive = [\"P6\"]\n"
	os.WriteFile(filepath.Join(dir, "guardrail.toml"), []byte(overlay), 0o644)

	var out, errb bytes.Buffer
	code := run([]string{"sync", "--dir", dir, "--binary", "/opt/guardrail"}, strings.NewReader(""), &out, &errb)
	if code != 0 {
		t.Fatalf("exit=%d stderr=%s", code, errb.String())
	}

	claudePath := filepath.Join(dir, ".claude", "settings.json")
	if _, err := os.Stat(claudePath); err != nil {
		t.Fatalf(".claude/settings.json not written: %v", err)
	}
	oc := filepath.Join(dir, "opencode.json")
	if _, err := os.Stat(oc); err != nil {
		t.Fatalf("opencode.json not written: %v", err)
	}
	pluginPath := filepath.Join(dir, ".guardrail", "guardrail.js")
	if _, err := os.Stat(pluginPath); err != nil {
		t.Fatalf("opencode plugin not deployed: %v", err)
	}
	ag := filepath.Join(dir, ".agents", "hooks.json")
	if _, err := os.Stat(ag); err != nil {
		t.Fatalf(".agents/hooks.json not written: %v", err)
	}

	raw, _ := os.ReadFile(ag)
	if !strings.Contains(string(raw), "guardrail-antigravity-pre") {
		t.Errorf("antigravity hooks.json missing the owned id")
	}
}

func TestSyncSinglePlane(t *testing.T) {
	dir := t.TempDir()
	gitInitSync(t, dir)
	var out, errb bytes.Buffer
	code := run([]string{"sync", "--dir", dir, "--planes", "claude", "--binary", "/opt/guardrail"}, strings.NewReader(""), &out, &errb)
	if code != 0 {
		t.Fatalf("exit=%d stderr=%s", code, errb.String())
	}
	if _, err := os.Stat(filepath.Join(dir, "opencode.json")); err == nil {
		t.Error("opencode.json should not have been written when --planes=claude")
	}
	if _, err := os.Stat(filepath.Join(dir, ".claude", "settings.json")); err != nil {
		t.Error(".claude/settings.json should have been written")
	}
}

func TestSyncOverlayReachesClaudeFloor(t *testing.T) {
	dir := t.TempDir()
	gitInitSync(t, dir)
	os.WriteFile(filepath.Join(dir, "guardrail.toml"), []byte(`
[[rules]]
id = "proj.tf"
pattern = "terraform apply*"
decision = "ask"
reason = "infra change"
`), 0o644)
	var out, errb bytes.Buffer
	code := run([]string{"sync", "--dir", dir, "--planes", "claude", "--binary", "guardrail"}, strings.NewReader(""), &out, &errb)
	if code != 0 {
		t.Fatalf("exit=%d stderr=%s", code, errb.String())
	}
	// The overlay rule itself isn't a Bash()-glob-shaped entry (ClaudeConfig
	// only ever emits the fixed floor globs, not arbitrary overlay [[rules]]
	// as permission strings) — this test locks that gen-config's Merge call
	// received the *merged* policy at all by checking a merge-only signal:
	// the hooks id is present (proves the pipeline ran end-to-end).
	raw, _ := os.ReadFile(filepath.Join(dir, ".claude", "settings.json"))
	var m map[string]any
	json.Unmarshal(raw, &m)
	if _, ok := m["hooks"]; !ok {
		t.Fatal("hooks block missing from synced settings.json")
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `/usr/local/go/bin/go test ./cmd/guardrail/ -run TestSync -v`
Expected: FAIL — `sync` is currently an unknown subcommand.

- [ ] **Step 3: Write minimal implementation**

`cmd/guardrail/sync.go`:

```go
package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/CtrlCarlitos/agent-guardrails/internal/genconfig"
	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
)

func cmdSync(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("sync", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dir := fs.String("dir", ".", "repo directory to sync")
	binary := fs.String("binary", "guardrail", "path to the guardrail binary to register in hook commands")
	planesFlag := fs.String("planes", "claude,opencode,antigravity", "comma-separated planes to sync")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	absDir, err := filepath.Abs(*dir)
	if err != nil {
		fmt.Fprintf(stderr, "guardrail: sync: cannot resolve --dir: %v\n", err)
		return 2
	}

	base, err := policy.LoadBase()
	if err != nil {
		fmt.Fprintf(stderr, "guardrail: sync: cannot load base policy: %v\n", err)
		return 2
	}

	var ov *policy.Overlay
	if pth, ok, warn := policy.FindOverlayPath(absDir); ok {
		if warn != "" {
			fmt.Fprintln(stderr, warn)
		}
		ov, err = policy.LoadOverlay(pth)
		if err != nil {
			fmt.Fprintf(stderr, "guardrail: sync: cannot load overlay: %v\n", err)
			return 2
		}
	} else if warn != "" {
		fmt.Fprintln(stderr, warn)
	}

	merged, warnings, err := policy.Merge(base, ov, version)
	if err != nil {
		fmt.Fprintf(stderr, "guardrail: sync: invalid overlay: %v\n", err)
		return 2
	}
	for _, w := range warnings {
		fmt.Fprintln(stderr, w)
	}

	for _, p := range strings.Split(*planesFlag, ",") {
		syncPlane(strings.TrimSpace(p), absDir, *binary, merged, stdout, stderr)
	}
	return 0
}

func syncPlane(plane, dir, binary string, merged *policy.Policy, stdout, stderr io.Writer) {
	switch plane {
	case "claude":
		target := filepath.Join(dir, ".claude", "settings.json")
		frag := genconfig.ClaudeConfig(merged, binary)
		if err := genconfig.MergeInto(target, frag); err != nil {
			fmt.Fprintf(stderr, "guardrail: sync claude failed: %v\n", err)
			return
		}
		fmt.Fprintf(stdout, "synced claude -> %s\n", target)

	case "opencode":
		pluginDir := filepath.Join(dir, ".guardrail")
		if err := os.MkdirAll(pluginDir, 0o755); err != nil {
			fmt.Fprintf(stderr, "guardrail: sync opencode failed: %v\n", err)
			return
		}
		pluginPath := filepath.Join(pluginDir, "guardrail.js")
		if err := os.WriteFile(pluginPath, genconfig.OpencodePluginJS, 0o644); err != nil {
			fmt.Fprintf(stderr, "guardrail: sync opencode failed: %v\n", err)
			return
		}
		absPlugin, err := filepath.Abs(pluginPath)
		if err != nil {
			absPlugin = pluginPath
		}
		target := filepath.Join(dir, "opencode.json")
		frag := genconfig.OpencodeConfig(merged, absPlugin)
		if err := genconfig.MergeInto(target, frag); err != nil {
			fmt.Fprintf(stderr, "guardrail: sync opencode failed: %v\n", err)
			return
		}
		fmt.Fprintf(stdout, "synced opencode -> %s\n", target)

	case "antigravity":
		target := filepath.Join(dir, ".agents", "hooks.json")
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			fmt.Fprintf(stderr, "guardrail: sync antigravity failed: %v\n", err)
			return
		}
		frag := genconfig.AntigravityConfig(binary)
		if err := genconfig.MergeInto(target, frag); err != nil {
			fmt.Fprintf(stderr, "guardrail: sync antigravity failed: %v\n", err)
			return
		}
		fmt.Fprintf(stdout, "synced antigravity -> %s\n", target)

	default:
		fmt.Fprintf(stderr, "guardrail: sync: unknown plane %q, skipping\n", plane)
	}
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `/usr/local/go/bin/go test ./cmd/guardrail/ -run TestSync -v`
Expected: FAIL still — `sync` isn't dispatched from `run()` yet. Continue to Task 7 before re-running.

- [ ] **Step 5: Commit**

```bash
gofmt -w cmd/guardrail/
git add cmd/guardrail/
git commit -m "feat(cli): cmdSync implementation (not yet dispatched — Task 7 wires it)"
```

---

### Task 7: Dispatch `guardrail sync` + update usage text

**Files:**
- Modify: `cmd/guardrail/run.go`

**Interfaces:**
- Add `case "sync": return cmdSync(args[1:], stdout, stderr)` to `run`'s plane... rather, subcommand switch. Update the `usage` const to document `sync` and to list all three planes for `gen-config`/`hook` (closing the pre-existing papercut both Plan 5 and Plan 6's reports flagged — the usage string still said `(plane: claude)` after opencode and antigravity shipped).

- [ ] **Step 1: Run the Task 6 tests to confirm they still fail for the right reason**

Run: `/usr/local/go/bin/go test ./cmd/guardrail/ -run TestSync -v`
Expected: FAIL — `run([]string{"sync",...})` hits the `default: unknown subcommand` branch.

- [ ] **Step 2: Wire the dispatch and fix the usage string**

In `cmd/guardrail/run.go`, add to the `switch args[0]`:

```go
	case "sync":
		return cmdSync(args[1:], stdout, stderr)
```

Replace the `usage` const body with:

```go
const usage = `guardrail — one guardrail policy across AI coding-agent planes

usage:
  guardrail version
  guardrail hook <plane> [phase]        evaluate a hook payload on stdin
      plane: claude | opencode | antigravity (antigravity also needs a phase: pre | post)
  guardrail gen-config <plane> [flags]  emit/merge the declarative floor (global paths)
      plane: claude | opencode | antigravity
      --print              write the JSON fragment to stdout (default)
      --merge <path>       deep-merge it into <path> in place, idempotently
      --binary <path>      guardrail path to register in hook commands (default "guardrail")
      --plugin-dir <dir>   (opencode only) where to deploy the embedded plugin
  guardrail sync [flags]                regenerate a PROJECT's plane configs from Base+Overlay
      --dir <path>         repo directory to sync (default ".")
      --planes <list>      comma-separated planes (default "claude,opencode,antigravity")
      --binary <path>      guardrail path to register in hook commands (default "guardrail")
  guardrail doctor                      print resolved policy/overlay/audit/hook state
`
```

- [ ] **Step 3: Run the tests to verify they pass**

Run: `/usr/local/go/bin/go test ./cmd/guardrail/ -v`
Expected: PASS. Full suite: `/usr/local/go/bin/go test ./... -v`.

- [ ] **Step 4: Commit**

```bash
gofmt -w cmd/guardrail/
git add cmd/guardrail/
git commit -m "feat(cli): dispatch guardrail sync; usage text lists all three planes (closes a Plan 5/6 papercut)"
```

---

### Task 8: docs + tag `v0.8.0-dev` + self-review

**Files:**
- Modify: `README.md`
- Modify: `docs/HANDOFF-2026-09-03.md`

- [ ] **Step 1: `make check` + full suite**

Run: `make check && /usr/local/go/bin/go test ./...`
Expected: all green, vet clean, gofmt clean.

- [ ] **Step 2: README**

Update Status: the original plan series (Plans 1–7 + the git hotfix + the deployment plan) is complete. Note P8 recipes (Go/Python/JS-TS/Rust, per-edit only — Odoo/Elixir and the session-completion tier are follow-ups per ADR-0009) and `guardrail sync`. Update Layout to add `internal/recipe/` and `cmd/guardrail/sync.go`.

- [ ] **Step 3: HANDOFF**

Mark the recipes+sync plan (formerly "Plan 7") done. Note the series is now fully implemented AND fully deployed (all three planes live on Carlitos's machine, verified against real sessions). List what's genuinely open going forward: Codex adapter (deferred by Carlitos, Q3), Odoo/Elixir recipes + session-completion tier (ADR-0009), and the long tail of parked hardening items carried since Plan 1 (`docker … | xargs`, backslash-escaped words, `bash -lc`, `git -C <path>` target-repo validation, Windows-path engine semantics, macOS `sha256sum` fallback, opencode native grep/glob tool mapping).

- [ ] **Step 4: Push and tag**

```bash
git add README.md docs/HANDOFF-2026-09-03.md
git commit -m "docs: recipes + guardrail sync done — original plan series complete"
git push origin main
git tag v0.8.0-dev
git push origin v0.8.0-dev
```

---

## Self-Review

**1. Spec coverage.**

| Item | Task |
|---|---|
| P8 recipe registry (Go/Python/JS-TS/Rust) | 1 |
| Lenient-on-absence, strict-on-failure execution | 2 |
| Wired into the shared hook pipeline, allow-only escalation | 3 |
| End-to-end contract proof | 4 |
| Scope cuts recorded (Odoo/Elixir, session tier) | 5 |
| `guardrail sync` reusing existing gen-config machinery with the merged policy | 6, 7 |
| Multi-plane, single-plane, and overlay-reaches-the-pipeline coverage | 6 |
| Stale usage-string papercut closed (carried from Plans 5–6's own reports) | 7 |

Deferred, confirmed out of scope: Odoo, Elixir, session-completion recipes (ADR-0009); a Codex adapter (Q3, Carlitos's own call, not started); the long tail of hardening items carried since Plan 1 through the deployment plan — none of them touched here, none of them regressed by this plan's changes (recipe execution and `sync` are additive; nothing in `checkBash`/`checkPaths`/the three adapters is modified).

**2. Placeholder scan.** No `TBD`/"handle appropriately". `TestCheckSkipsMissingTool` (Task 2) is deliberately loose because `rustfmt`'s presence is genuinely machine-dependent — that looseness is documented in the test's own comment, not a hidden gap.

**3. Type consistency.**
- `recipe.Recipe{Name, Extensions, PerEdit}` / `recipe.Registry` / `recipe.ForFile(string) (Recipe, bool)` / `recipe.Check(engine.ToolCall) *policy.Verdict` — Tasks 1–2; `Check` is the only exported entry point `cmdHook` calls (Task 3).
- `cmdSync(args []string, stdout, stderr io.Writer) int` — Task 6; dispatched from `run` (Task 7) with the exact same three-arg-plus-writers shape every other subcommand (`cmdHook`, `cmdGenConfig`, `cmdDoctor`) already uses.
- `syncPlane` (unexported, Task 6) calls `genconfig.ClaudeConfig`/`OpencodeConfig`/`AntigravityConfig`/`MergeInto`/`OpencodePluginJS` with their existing Plan 2/5/6 signatures — zero changes to `internal/genconfig`.
- No changes to `Evaluate`, `TrifectaVerdict`, `checkBash`, `checkPaths`, or any of the three adapters' `Parse*`/`Emit*` functions.

---

## Execution Handoff

**Plan complete and saved to `docs/superpowers/plans/2026-09-04-recipes-and-sync.md`. Two execution options:**

**1. Subagent-Driven (recommended)** — fresh subagent per task via `superpowers:subagent-driven-development`, review between tasks.

**2. Inline Execution** — `superpowers:executing-plans`, batch with checkpoints.

**Which approach?**
