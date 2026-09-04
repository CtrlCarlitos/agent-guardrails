# `guardrail gen-config claude` + `guardrail doctor` + Config-Discovery Hardening — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give the `guardrail` binary the ability to emit and idempotently merge its own Claude Code install config (a `hooks` registration + a coarse `permissions` deny/ask floor derived from the Base policy), a `guardrail doctor` self-diagnostic, and stop the binary hard-failing (`exit 2` on every call) when `GUARDRAIL_CONFIG` points at a missing file.

**Architecture:** A new `internal/genconfig` package translates the Base policy's static P1/P4 checks into Claude Code `Bash(...)` / `Read(...)` / `Edit(...)` permission globs and a `hooks` block, and deep-merges that fragment into an existing `~/.claude/settings.json` without clobbering unrelated keys. Two new subcommands (`gen-config`, `doctor`) wire it to the CLI. `policy.FindOverlayPath` gains a third return value (a warning string) so a stale `GUARDRAIL_CONFIG` degrades to base-only-plus-warning instead of failing closed forever.

**Tech Stack:** Go 1.23+ (`/usr/local/go/bin/go`, currently 1.25.0 — not on PATH; invoke by full path or `export PATH=$PATH:/usr/local/go/bin`). Existing deps only: `github.com/BurntSushi/toml v1.6.0`, `github.com/bmatcuk/doublestar/v4 v4.10.0`, `mvdan.cc/sh/v3 v3.10.0`. No new dependencies.

**Spec:** `../../../DESIGN.md` (repo root). This plan is the agent-guardrails half of the original handoff's "Plan 2"; the CI release workflow + dotfiles installer + Claude smoke test are now **Plan 3**. Terminology: `../../../CONTEXT.md`. Decisions: `../../adr/`.

## Global Constraints

- Module path: `github.com/CtrlCarlitos/agent-guardrails`. Go floor `go 1.23`.
- **No new dependencies.** JSON merge is hand-rolled with `encoding/json` + `map[string]any`.
- **Fail closed stays fail closed for real errors.** A *malformed* overlay still → `exit 2`. Only a *set-but-missing* `GUARDRAIL_CONFIG` degrades to base-only + a stderr warning (this matches DESIGN.md Q14 "degrade, don't brick").
- `gen-config` builds the **global floor from Base policy only** — no overlay merge. (`guardrail sync`, which folds overlays into per-repo plane config, stays Plan 7.)
- The declarative floor is **deliberately coarser than the engine.** Claude's argument-glob matching is documented as fragile; the floor only has to hold the worst destructive cases when the Engine binary is unavailable. The Engine is the real check.
- Merge output is **idempotent**: running `gen-config claude --merge <path>` twice produces a byte-identical file the second time (modulo the first run's additions).
- Every code step shows literal code. Minimal TDD implementations. `gofmt -w` before every commit. Conventional Commits messages. Commit after every task.
- Subprocess calls (`git`) use explicit arg lists, never a shell string.
- Known types you are extending (from Plan 1, verified against the built tree at `v0.1.0-dev`):
  - `policy.Policy{ Slots policy.Slots; Rules []policy.Rule; Waived map[string]bool }`
  - `policy.Slots{ SafeRoots, SecretGlobs, SecretAllow, EgressAllowlist []string; AuditLog string }`
  - `policy.LoadBase() (*policy.Policy, error)` — Base has **no `[[rules]]`**; P1/P4 are Go code.
  - `policy.FindOverlayPath(cwd string) (string, bool)` — **this plan changes its signature.**
  - `policy.LoadOverlay(pth string) (*policy.Overlay, error)`
  - `policy.Merge(base *policy.Policy, ov *policy.Overlay, binaryVersion string) (*policy.Policy, []string, error)`
  - `audit.DefaultPath(override string) string`
  - `cmd/guardrail`: `var version = "dev"` (ldflags `-X main.version=`); `run(args []string, stdin io.Reader, stdout, stderr io.Writer) int` dispatches on `args[0]`.

---

### Task 1: `gen-config` subcommand scaffold + flag parsing

**Files:**
- Create: `cmd/guardrail/genconfig.go`
- Create: `cmd/guardrail/genconfig_test.go`
- Modify: `cmd/guardrail/run.go` (add `case "gen-config"`)

**Interfaces:**
- Consumes: `run` dispatch (Plan 1, `cmd/guardrail/run.go`).
- Produces:
  - `func cmdGenConfig(args []string, stdout, stderr io.Writer) int` — `args[0]` is the plane. Only `"claude"` is implemented; anything else (or missing) → stderr message + exit `2`. Remaining args parsed with a `flag.FlagSet`: `--print` (bool, default true), `--merge <path>` (string), `--binary <path>` (string, default `"guardrail"`). `--merge` set ⇒ ignore `--print`. Flag parse error → exit `2`.
  - This task only wires arg/flag handling and the "unsupported plane" path; actual output comes in Task 5.

- [ ] **Step 1: Write the failing test**

`cmd/guardrail/genconfig_test.go`:

```go
package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestGenConfigNoPlane(t *testing.T) {
	var out, errb bytes.Buffer
	code := run([]string{"gen-config"}, strings.NewReader(""), &out, &errb)
	if code != 2 {
		t.Fatalf("exit = %d, want 2", code)
	}
	if !strings.Contains(errb.String(), "plane") {
		t.Fatalf("stderr = %q, want it to mention a plane", errb.String())
	}
}

func TestGenConfigUnsupportedPlane(t *testing.T) {
	var out, errb bytes.Buffer
	code := run([]string{"gen-config", "emacs"}, strings.NewReader(""), &out, &errb)
	if code != 2 || !strings.Contains(errb.String(), "emacs") {
		t.Fatalf("exit=%d stderr=%q", code, errb.String())
	}
}

func TestGenConfigBadFlag(t *testing.T) {
	var out, errb bytes.Buffer
	code := run([]string{"gen-config", "claude", "--nope"}, strings.NewReader(""), &out, &errb)
	if code != 2 {
		t.Fatalf("exit = %d, want 2", code)
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `/usr/local/go/bin/go test ./cmd/guardrail/ -run TestGenConfig -v`
Expected: FAIL — `gen-config` is an unknown subcommand (exit 2 but wrong stderr) / `cmdGenConfig` undefined.

- [ ] **Step 3: Add the dispatch case**

In `cmd/guardrail/run.go`, add to the `switch args[0]`:

```go
	case "gen-config":
		return cmdGenConfig(args[1:], stdout, stderr)
```

- [ ] **Step 4: Write minimal implementation**

`cmd/guardrail/genconfig.go`:

```go
package main

import (
	"flag"
	"fmt"
	"io"
)

func cmdGenConfig(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "guardrail: gen-config needs a plane (claude)")
		return 2
	}
	plane := args[0]
	if plane != "claude" {
		fmt.Fprintf(stderr, "guardrail: gen-config: unsupported plane %q\n", plane)
		return 2
	}

	fs := flag.NewFlagSet("gen-config", flag.ContinueOnError)
	fs.SetOutput(stderr)
	doPrint := fs.Bool("print", true, "write the config fragment to stdout")
	mergePath := fs.String("merge", "", "merge the fragment into this settings.json in place")
	binary := fs.String("binary", "guardrail", "path to the guardrail binary to register in the hook command")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	_ = doPrint
	_ = mergePath
	_ = binary

	// Output implemented in Task 5.
	return 0
}
```

- [ ] **Step 5: Run the test to verify it passes**

Run: `/usr/local/go/bin/go test ./cmd/guardrail/ -run TestGenConfig -v`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
gofmt -w cmd/guardrail/
git add cmd/guardrail/
git commit -m "feat(cli): gen-config subcommand scaffold with flag parsing"
```

---

### Task 2: Translate P1 static checks → Claude `Bash(...)` deny / ask globs

**Files:**
- Create: `internal/genconfig/claude.go`
- Create: `internal/genconfig/claude_test.go`

**Interfaces:**
- Consumes: `github.com/CtrlCarlitos/agent-guardrails/internal/policy`.
- Produces:
  - `type Fragment = map[string]any` (package `genconfig`).
  - `func bashDenyGlobs() []string` — a curated, literal list of `Bash(...)` patterns for the P1 deny-tier commands (`rm -rf`, `dd`, `mkfs*`, `wipefs`, `shred`, `srm`, `sudo`, `su`, `doas`, `git push --force`, `git clean -f*`, `docker compose down`, `docker system|volume|network prune`).
  - `func bashAskGlobs() []string` — `Bash(...)` patterns for the P1 ask-tier commands (`chmod -R`, `chmod 777`, `chown -R`, `truncate`, `kill -9`, `killall`, `pkill`, `find * -delete`).
  - Both are pure functions (no policy input — these commands are not parameterized).

- [ ] **Step 1: Write the failing test**

`internal/genconfig/claude_test.go`:

```go
package genconfig

import (
	"slices"
	"strings"
	"testing"
)

func TestBashDenyGlobs(t *testing.T) {
	got := bashDenyGlobs()
	mustHave := []string{
		"Bash(rm -rf *)", "Bash(dd *)", "Bash(mkfs*)", "Bash(shred *)",
		"Bash(sudo *)", "Bash(git push --force*)", "Bash(git clean -f*)",
		"Bash(docker compose down*)", "Bash(docker system prune*)",
	}
	for _, m := range mustHave {
		if !slices.Contains(got, m) {
			t.Errorf("bashDenyGlobs missing %q; got %v", m, got)
		}
	}
	for _, g := range got {
		if !strings.HasPrefix(g, "Bash(") || !strings.HasSuffix(g, ")") {
			t.Errorf("malformed glob %q", g)
		}
	}
}

func TestBashAskGlobs(t *testing.T) {
	got := bashAskGlobs()
	for _, m := range []string{"Bash(chmod -R *)", "Bash(chown -R *)", "Bash(truncate *)", "Bash(pkill *)"} {
		if !slices.Contains(got, m) {
			t.Errorf("bashAskGlobs missing %q", m)
		}
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `/usr/local/go/bin/go test ./internal/genconfig/ -v`
Expected: FAIL — package/functions undefined.

- [ ] **Step 3: Write minimal implementation**

`internal/genconfig/claude.go`:

```go
// Package genconfig translates a merged policy into each plane's native
// declarative config (the "declarative floor") and merges it into that plane's
// settings file.
package genconfig

// Fragment is a JSON-shaped config fragment ready to be merged into a plane's
// settings file.
type Fragment = map[string]any

// bashDenyGlobs is the curated coarse floor for P1 deny-tier shell commands.
// Intentionally not exhaustive — Claude's argument-glob matching is fragile and
// the Engine is the real check; this only has to catch the worst cases when the
// Engine binary is missing.
func bashDenyGlobs() []string {
	return []string{
		"Bash(rm -rf *)", "Bash(rm -fr *)", "Bash(rm -r -f *)", "Bash(rm -f -r *)",
		"Bash(dd *)",
		"Bash(mkfs*)", "Bash(wipefs *)",
		"Bash(shred *)", "Bash(srm *)",
		"Bash(sudo *)", "Bash(su *)", "Bash(su)", "Bash(doas *)",
		"Bash(git push --force*)", "Bash(git push -f*)",
		"Bash(git clean -f*)", "Bash(git clean -xf*)", "Bash(git clean -fx*)",
		"Bash(git clean -df*)", "Bash(git clean -fd*)",
		"Bash(docker compose down*)",
		"Bash(docker system prune*)", "Bash(docker volume prune*)", "Bash(docker network prune*)",
	}
}

// bashAskGlobs is the curated coarse floor for P1 ask-tier shell commands.
func bashAskGlobs() []string {
	return []string{
		"Bash(chmod -R *)", "Bash(chmod 777 *)", "Bash(chmod -R 777 *)",
		"Bash(chown -R *)",
		"Bash(truncate *)",
		"Bash(kill -9 *)", "Bash(killall *)", "Bash(pkill *)",
		"Bash(find * -delete)",
	}
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `/usr/local/go/bin/go test ./internal/genconfig/ -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
gofmt -w internal/genconfig/
git add internal/genconfig/
git commit -m "feat(genconfig): curated P1 deny/ask Bash() globs for the Claude floor"
```

---

### Task 3: Translate P4 secret globs → Claude `Read(...)` / `Edit(...)` denies, honoring `secret_allow`

**Files:**
- Modify: `internal/genconfig/claude.go`
- Modify: `internal/genconfig/claude_test.go`

**Interfaces:**
- Consumes: `policy.Policy`, `github.com/bmatcuk/doublestar/v4`.
- Produces:
  - `func secretDenyGlobs(pol *policy.Policy) []string` — for each `pol.Slots.SecretGlobs` entry `g`, emit `"Read(" + g + ")"` and `"Edit(" + g + ")"`, **unless** `g` also matches any `pol.Slots.SecretAllow` entry (`doublestar.Match(g, allowEntry)`), in which case `g` is skipped entirely (Claude has no allow-exception under a deny). Order: all `Read(...)` then all `Edit(...)`, in `SecretGlobs` order.

- [ ] **Step 1: Write the failing test**

Add to `internal/genconfig/claude_test.go`:

```go
import "github.com/CtrlCarlitos/agent-guardrails/internal/policy" // add to imports

func secretPol() *policy.Policy {
	return &policy.Policy{Slots: policy.Slots{
		SecretGlobs: []string{"**/.env", ".env.*", "**/.ssh/**", "id_rsa*", "*.pem"},
		SecretAllow: []string{"**/.env.example", ".env.example"},
	}}
}

func TestSecretDenyGlobs(t *testing.T) {
	got := secretDenyGlobs(secretPol())
	want := []string{
		"Read(**/.env)", "Read(**/.ssh/**)", "Read(id_rsa*)", "Read(*.pem)",
		"Edit(**/.env)", "Edit(**/.ssh/**)", "Edit(id_rsa*)", "Edit(*.pem)",
	}
	for _, w := range want {
		if !slices.Contains(got, w) {
			t.Errorf("missing %q in %v", w, got)
		}
	}
	// .env.* collides with .env.example -> must be dropped entirely.
	for _, bad := range []string{"Read(.env.*)", "Edit(.env.*)"} {
		if slices.Contains(got, bad) {
			t.Errorf("%q should have been dropped (collides with secret_allow)", bad)
		}
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `/usr/local/go/bin/go test ./internal/genconfig/ -run TestSecretDenyGlobs -v`
Expected: FAIL — `secretDenyGlobs` undefined.

- [ ] **Step 3: Write minimal implementation**

Add to `internal/genconfig/claude.go`:

```go
import (
	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
	"github.com/bmatcuk/doublestar/v4"
)

func secretDenyGlobs(pol *policy.Policy) []string {
	var reads, edits []string
	for _, g := range pol.Slots.SecretGlobs {
		if collidesWithAllow(g, pol.Slots.SecretAllow) {
			continue
		}
		reads = append(reads, "Read("+g+")")
		edits = append(edits, "Edit("+g+")")
	}
	return append(reads, edits...)
}

func collidesWithAllow(glob string, allow []string) bool {
	for _, a := range allow {
		if ok, _ := doublestar.Match(glob, a); ok {
			return true
		}
	}
	return false
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `/usr/local/go/bin/go test ./internal/genconfig/ -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
gofmt -w internal/genconfig/
git add internal/genconfig/
git commit -m "feat(genconfig): translate P4 secret globs to Read()/Edit() denies, honoring secret_allow"
```

---

### Task 4: The `hooks` registration block

**Files:**
- Modify: `internal/genconfig/claude.go`
- Modify: `internal/genconfig/claude_test.go`

**Interfaces:**
- Produces:
  - `func claudeHooks(binary string) map[string]any` — returns
    ```
    {
      "PreToolUse":  [ {"matcher": "Bash|Read|Edit|Write|MultiEdit", "hooks": [ {"type":"command","command": binary + " hook claude","timeout":10} ]} ],
      "PostToolUse": [ {"matcher": "Write|Edit|MultiEdit",           "hooks": [ {"type":"command","command": binary + " hook claude"} ]} ]
    }
    ```

- [ ] **Step 1: Write the failing test**

Add to `internal/genconfig/claude_test.go`:

```go
func TestClaudeHooks(t *testing.T) {
	h := claudeHooks("/usr/local/bin/guardrail")
	pre, ok := h["PreToolUse"].([]any)
	if !ok || len(pre) != 1 {
		t.Fatalf("PreToolUse shape wrong: %#v", h["PreToolUse"])
	}
	entry := pre[0].(map[string]any)
	if entry["matcher"].(string) != "Bash|Read|Edit|Write|MultiEdit" {
		t.Errorf("matcher = %v", entry["matcher"])
	}
	hk := entry["hooks"].([]any)[0].(map[string]any)
	if hk["command"].(string) != "/usr/local/bin/guardrail hook claude" {
		t.Errorf("command = %v", hk["command"])
	}
	if _, ok := h["PostToolUse"]; !ok {
		t.Error("PostToolUse missing")
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `/usr/local/go/bin/go test ./internal/genconfig/ -run TestClaudeHooks -v`
Expected: FAIL — `claudeHooks` undefined.

- [ ] **Step 3: Write minimal implementation**

Add to `internal/genconfig/claude.go`:

```go
func claudeHooks(binary string) map[string]any {
	cmd := binary + " hook claude"
	return map[string]any{
		"PreToolUse": []any{
			map[string]any{
				"matcher": "Bash|Read|Edit|Write|MultiEdit",
				"hooks": []any{
					map[string]any{"type": "command", "command": cmd, "timeout": 10},
				},
			},
		},
		"PostToolUse": []any{
			map[string]any{
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

- [ ] **Step 5: Commit**

```bash
gofmt -w internal/genconfig/
git add internal/genconfig/
git commit -m "feat(genconfig): Claude hooks registration block"
```

---

### Task 5: Assemble the Fragment + wire `gen-config claude --print`

**Files:**
- Modify: `internal/genconfig/claude.go`
- Modify: `internal/genconfig/claude_test.go`
- Modify: `cmd/guardrail/genconfig.go`
- Modify: `cmd/guardrail/genconfig_test.go`

**Interfaces:**
- Produces:
  - `func ClaudeConfig(pol *policy.Policy, binary string) Fragment` — returns
    `{ "hooks": claudeHooks(binary), "permissions": {"deny": bashDenyGlobs() ++ secretDenyGlobs(pol), "ask": bashAskGlobs()} }`.
  - `cmdGenConfig` for `claude` with no `--merge`: `policy.LoadBase()` → `ClaudeConfig(base, *binary)` → `json.MarshalIndent(frag, "", "  ")` → write to `stdout` with a trailing newline; return `0`. Base load error → stderr + exit `2`.

- [ ] **Step 1: Write the failing test**

Add to `internal/genconfig/claude_test.go`:

```go
func TestClaudeConfigShape(t *testing.T) {
	frag := ClaudeConfig(secretPol(), "guardrail")
	perms := frag["permissions"].(map[string]any)
	deny := perms["deny"].([]string)
	if !slices.Contains(deny, "Bash(rm -rf *)") || !slices.Contains(deny, "Read(**/.ssh/**)") {
		t.Errorf("deny incomplete: %v", deny)
	}
	if _, ok := frag["hooks"]; !ok {
		t.Error("hooks missing")
	}
	ask := perms["ask"].([]string)
	if !slices.Contains(ask, "Bash(chmod -R *)") {
		t.Errorf("ask incomplete: %v", ask)
	}
}
```

Add to `cmd/guardrail/genconfig_test.go`:

```go
import "encoding/json" // add to imports

func TestGenConfigClaudePrint(t *testing.T) {
	var out, errb bytes.Buffer
	code := run([]string{"gen-config", "claude", "--print"}, strings.NewReader(""), &out, &errb)
	if code != 0 {
		t.Fatalf("exit=%d stderr=%q", code, errb.String())
	}
	var frag map[string]any
	if err := json.Unmarshal(out.Bytes(), &frag); err != nil {
		t.Fatalf("stdout is not JSON: %v\n%s", err, out.String())
	}
	if _, ok := frag["hooks"]; !ok {
		t.Error("no hooks key")
	}
	if _, ok := frag["permissions"]; !ok {
		t.Error("no permissions key")
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `/usr/local/go/bin/go test ./internal/genconfig/ ./cmd/guardrail/ -run 'ClaudeConfig|GenConfigClaudePrint' -v`
Expected: FAIL — `ClaudeConfig` undefined; `gen-config claude --print` writes nothing.

- [ ] **Step 3: Write minimal implementation**

Add to `internal/genconfig/claude.go`:

```go
func ClaudeConfig(pol *policy.Policy, binary string) Fragment {
	deny := append(bashDenyGlobs(), secretDenyGlobs(pol)...)
	return Fragment{
		"hooks": claudeHooks(binary),
		"permissions": map[string]any{
			"deny": deny,
			"ask":  bashAskGlobs(),
		},
	}
}
```

Replace the tail of `cmdGenConfig` in `cmd/guardrail/genconfig.go` (the `_ = doPrint` block) with:

```go
	base, err := policy.LoadBase()
	if err != nil {
		fmt.Fprintf(stderr, "guardrail: cannot load base policy: %v\n", err)
		return 2
	}
	frag := genconfig.ClaudeConfig(base, *binary)

	if *mergePath != "" {
		// implemented in Task 7
		fmt.Fprintln(stderr, "guardrail: --merge not yet implemented")
		return 2
	}

	b, err := json.MarshalIndent(frag, "", "  ")
	if err != nil {
		fmt.Fprintf(stderr, "guardrail: cannot marshal config: %v\n", err)
		return 2
	}
	stdout.Write(append(b, '\n'))
	_ = doPrint
	return 0
```

Add imports to `genconfig.go`: `"encoding/json"`, `"github.com/CtrlCarlitos/agent-guardrails/internal/genconfig"`, `"github.com/CtrlCarlitos/agent-guardrails/internal/policy"`.

- [ ] **Step 4: Run the test to verify it passes**

Run: `/usr/local/go/bin/go test ./internal/genconfig/ ./cmd/guardrail/ -v`
Expected: PASS.

- [ ] **Step 5: Manual check**

Run: `/usr/local/go/bin/go run ./cmd/guardrail gen-config claude --print`
Expected: pretty JSON with `hooks` + `permissions.deny` (Bash + Read/Edit) + `permissions.ask`.

- [ ] **Step 6: Commit**

```bash
gofmt -w internal/genconfig/ cmd/guardrail/
git add internal/genconfig/ cmd/guardrail/
git commit -m "feat(genconfig): ClaudeConfig fragment + gen-config claude --print"
```

---

### Task 6: Idempotent deep-merge into an existing settings.json

**Files:**
- Create: `internal/genconfig/merge.go`
- Create: `internal/genconfig/merge_test.go`

**Interfaces:**
- Consumes: `encoding/json`, `os`.
- Produces:
  - `func MergeInto(path string, frag Fragment) error` — read `path` as JSON into `map[string]any` (missing/empty file ⇒ `{}`); `deepMerge(existing, frag)`; write back pretty (`  ` indent) + trailing newline, `0644`, atomically (`os.CreateTemp` in the same dir + `os.Rename`). A file that exists but is not a JSON object ⇒ error (do not clobber).
  - `func deepMerge(dst, src map[string]any)` — for each key in `src`: if both `dst[k]` and `src[k]` are `map[string]any` ⇒ recurse; if both are JSON arrays (`[]any` / `[]string`) ⇒ union-append preserving `dst` order, comparing elements by their compact-JSON encoding for dedup; otherwise ⇒ `dst[k] = src[k]`.

- [ ] **Step 1: Write the failing test**

`internal/genconfig/merge_test.go`:

```go
package genconfig

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func readJSON(t *testing.T, p string) map[string]any {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("not json: %v\n%s", err, b)
	}
	return m
}

func TestMergeIntoEmpty(t *testing.T) {
	p := filepath.Join(t.TempDir(), "settings.json")
	frag := Fragment{"permissions": map[string]any{"deny": []string{"Bash(rm -rf *)"}}}
	if err := MergeInto(p, frag); err != nil {
		t.Fatal(err)
	}
	m := readJSON(t, p)
	deny := m["permissions"].(map[string]any)["deny"].([]any)
	if len(deny) != 1 || deny[0] != "Bash(rm -rf *)" {
		t.Fatalf("deny = %v", deny)
	}
}

func TestMergeIntoPreservesUnrelated(t *testing.T) {
	p := filepath.Join(t.TempDir(), "settings.json")
	os.WriteFile(p, []byte(`{"theme":"dark","permissions":{"deny":["Bash(foo)"],"allow":["Bash(ls)"]}}`), 0o644)
	frag := Fragment{"permissions": map[string]any{"deny": []string{"Bash(rm -rf *)"}}}
	if err := MergeInto(p, frag); err != nil {
		t.Fatal(err)
	}
	m := readJSON(t, p)
	if m["theme"] != "dark" {
		t.Error("theme lost")
	}
	perms := m["permissions"].(map[string]any)
	if _, ok := perms["allow"]; !ok {
		t.Error("permissions.allow lost")
	}
	deny := perms["deny"].([]any)
	if len(deny) != 2 {
		t.Fatalf("deny = %v, want the original + the new one", deny)
	}
}

func TestMergeIntoIdempotent(t *testing.T) {
	p := filepath.Join(t.TempDir(), "settings.json")
	frag := Fragment{"permissions": map[string]any{"deny": []string{"Bash(rm -rf *)", "Bash(dd *)"}}}
	if err := MergeInto(p, frag); err != nil {
		t.Fatal(err)
	}
	first, _ := os.ReadFile(p)
	if err := MergeInto(p, frag); err != nil {
		t.Fatal(err)
	}
	second, _ := os.ReadFile(p)
	if string(first) != string(second) {
		t.Fatalf("not idempotent:\n--- first ---\n%s\n--- second ---\n%s", first, second)
	}
}

func TestMergeIntoRejectsNonObject(t *testing.T) {
	p := filepath.Join(t.TempDir(), "settings.json")
	os.WriteFile(p, []byte(`["not","an","object"]`), 0o644)
	if err := MergeInto(p, Fragment{"x": 1}); err == nil {
		t.Fatal("want error, got nil (would have clobbered)")
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `/usr/local/go/bin/go test ./internal/genconfig/ -run TestMergeInto -v`
Expected: FAIL — `MergeInto` undefined.

- [ ] **Step 3: Write minimal implementation**

`internal/genconfig/merge.go`:

```go
package genconfig

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

func MergeInto(path string, frag Fragment) error {
	existing := map[string]any{}
	if raw, err := os.ReadFile(path); err == nil && len(bytes.TrimSpace(raw)) > 0 {
		if err := json.Unmarshal(raw, &existing); err != nil {
			return fmt.Errorf("%s is not a JSON object; refusing to overwrite: %w", path, err)
		}
	} else if err != nil && !os.IsNotExist(err) {
		return err
	}

	deepMerge(existing, frag)

	out, err := json.MarshalIndent(existing, "", "  ")
	if err != nil {
		return err
	}
	out = append(out, '\n')

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".guardrail-settings-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(out); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return err
	}
	return os.Rename(tmpName, path)
}

func deepMerge(dst, src map[string]any) {
	for k, sv := range src {
		dv, present := dst[k]
		if !present {
			dst[k] = sv
			continue
		}
		dm, dok := dv.(map[string]any)
		sm, sok := sv.(map[string]any)
		if dok && sok {
			deepMerge(dm, sm)
			continue
		}
		da, daok := toAnySlice(dv)
		sa, saok := toAnySlice(sv)
		if daok && saok {
			dst[k] = unionAppend(da, sa)
			continue
		}
		dst[k] = sv
	}
}

func toAnySlice(v any) ([]any, bool) {
	switch s := v.(type) {
	case []any:
		return s, true
	case []string:
		out := make([]any, len(s))
		for i, x := range s {
			out[i] = x
		}
		return out, true
	default:
		return nil, false
	}
}

func unionAppend(dst, src []any) []any {
	seen := map[string]bool{}
	key := func(v any) string { b, _ := json.Marshal(v); return string(b) }
	for _, v := range dst {
		seen[key(v)] = true
	}
	out := append([]any{}, dst...)
	for _, v := range src {
		if k := key(v); !seen[k] {
			seen[k] = true
			out = append(out, v)
		}
	}
	return out
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `/usr/local/go/bin/go test ./internal/genconfig/ -run TestMergeInto -v`
Expected: PASS. If `TestMergeIntoIdempotent` fails because Go map key order changed the output, note that `json.MarshalIndent` sorts object keys deterministically — so a diff there means a real non-idempotency (array dedup bug); fix `unionAppend`.

- [ ] **Step 5: Commit**

```bash
gofmt -w internal/genconfig/
git add internal/genconfig/
git commit -m "feat(genconfig): idempotent deep-merge into settings.json (atomic, preserves unrelated keys)"
```

---

### Task 7: Wire `gen-config claude --merge <path>`

**Files:**
- Modify: `cmd/guardrail/genconfig.go`
- Modify: `cmd/guardrail/genconfig_test.go`

**Interfaces:**
- Consumes: `genconfig.MergeInto`.
- Produces: `cmdGenConfig` with `--merge <path>` set: `MergeInto(*mergePath, frag)`; on error stderr + exit `2`; on success print `guardrail: merged Claude config into <path>` to stderr and return `0`. `--print` is ignored when `--merge` is set.

- [ ] **Step 1: Write the failing test**

Add to `cmd/guardrail/genconfig_test.go`:

```go
import "os"           // add to imports
import "path/filepath" // add to imports

func TestGenConfigClaudeMerge(t *testing.T) {
	p := filepath.Join(t.TempDir(), "settings.json")
	var out, errb bytes.Buffer
	code := run([]string{"gen-config", "claude", "--merge", p, "--binary", "/opt/guardrail"}, strings.NewReader(""), &out, &errb)
	if code != 0 {
		t.Fatalf("exit=%d stderr=%q", code, errb.String())
	}
	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	pre := m["hooks"].(map[string]any)["PreToolUse"].([]any)[0].(map[string]any)
	gotCmd := pre["hooks"].([]any)[0].(map[string]any)["command"].(string)
	if gotCmd != "/opt/guardrail hook claude" {
		t.Errorf("command = %q", gotCmd)
	}
	// second run must be a no-op
	before := string(raw)
	run([]string{"gen-config", "claude", "--merge", p, "--binary", "/opt/guardrail"}, strings.NewReader(""), &out, &errb)
	after, _ := os.ReadFile(p)
	if before != string(after) {
		t.Errorf("second merge changed the file")
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `/usr/local/go/bin/go test ./cmd/guardrail/ -run TestGenConfigClaudeMerge -v`
Expected: FAIL — `--merge` still prints "not yet implemented".

- [ ] **Step 3: Write minimal implementation**

In `cmd/guardrail/genconfig.go`, replace the `if *mergePath != "" { ... "not yet implemented" ... }` block with:

```go
	if *mergePath != "" {
		if err := genconfig.MergeInto(*mergePath, frag); err != nil {
			fmt.Fprintf(stderr, "guardrail: merge failed: %v\n", err)
			return 2
		}
		fmt.Fprintf(stderr, "guardrail: merged Claude config into %s\n", *mergePath)
		return 0
	}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `/usr/local/go/bin/go test ./cmd/guardrail/ -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
gofmt -w cmd/guardrail/
git add cmd/guardrail/
git commit -m "feat(cli): gen-config claude --merge writes the floor into settings.json in place"
```

---

### Task 8: `FindOverlayPath` — warn (don't fail) on a stale `GUARDRAIL_CONFIG`

**Files:**
- Modify: `internal/policy/config.go`
- Modify: `internal/policy/config_test.go`

**Interfaces:**
- **Signature change:** `func FindOverlayPath(cwd string) (path string, ok bool, warn string)`.
  - `GUARDRAIL_CONFIG` set and the file **exists** ⇒ `(value, true, "")`.
  - `GUARDRAIL_CONFIG` set and the file **is missing** ⇒ `("", false, "guardrail: GUARDRAIL_CONFIG is set to <value> but that file does not exist; using base policy only")`.
  - `GUARDRAIL_CONFIG` unset ⇒ git-root discovery as before ⇒ `(path, true, "")` or `("", false, "")`.
- All callers updated (only `cmd/guardrail/hook.go`, updated in Task 9; and tests).

- [ ] **Step 1: Update the failing test**

In `internal/policy/config_test.go`, replace the three `FindOverlayPath` tests' call sites and add one:

```go
func TestFindOverlayPathGitRoot(t *testing.T) {
	root := t.TempDir()
	gitInit(t, root)
	sub := filepath.Join(root, "a", "b")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	cfg := filepath.Join(root, "guardrail.toml")
	os.WriteFile(cfg, []byte("engine_min_version = \"0.1\"\n"), 0o644)
	t.Setenv("GUARDRAIL_CONFIG", "")
	got, ok, warn := FindOverlayPath(sub)
	if !ok || got != cfg || warn != "" {
		t.Fatalf("got %q,%v,%q", got, ok, warn)
	}
}

func TestFindOverlayPathEnvPresent(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "custom.toml")
	os.WriteFile(p, []byte("engine_min_version=\"9\"\n"), 0o644)
	t.Setenv("GUARDRAIL_CONFIG", p)
	got, ok, warn := FindOverlayPath("/anywhere")
	if !ok || got != p || warn != "" {
		t.Fatalf("got %q,%v,%q", got, ok, warn)
	}
}

func TestFindOverlayPathEnvStale(t *testing.T) {
	t.Setenv("GUARDRAIL_CONFIG", "/definitely/not/here.toml")
	got, ok, warn := FindOverlayPath("/anywhere")
	if ok || got != "" {
		t.Fatalf("stale env should yield no overlay; got %q,%v", got, ok)
	}
	if warn == "" || !strings.Contains(warn, "/definitely/not/here.toml") {
		t.Fatalf("want a warning naming the path; got %q", warn)
	}
}

func TestFindOverlayPathNone(t *testing.T) {
	t.Setenv("GUARDRAIL_CONFIG", "")
	dir := t.TempDir()
	if _, ok, warn := FindOverlayPath(dir); ok || warn != "" {
		t.Fatalf("want (_, false, \"\"); ok=%v warn=%q", ok, warn)
	}
}
```

Add `"strings"` to the test imports if not present.

- [ ] **Step 2: Run the test to verify it fails**

Run: `/usr/local/go/bin/go test ./internal/policy/ -run FindOverlayPath -v`
Expected: FAIL — signature mismatch (compile error).

- [ ] **Step 3: Write minimal implementation**

In `internal/policy/config.go`, replace `FindOverlayPath`:

```go
func FindOverlayPath(cwd string) (path string, ok bool, warn string) {
	if v := os.Getenv("GUARDRAIL_CONFIG"); v != "" {
		if _, err := os.Stat(v); err != nil {
			return "", false, fmt.Sprintf("guardrail: GUARDRAIL_CONFIG is set to %s but that file does not exist; using base policy only", v)
		}
		return v, true, ""
	}
	out, err := exec.Command("git", "-C", cwd, "rev-parse", "--show-toplevel").Output()
	if err != nil {
		return "", false, ""
	}
	root := strings.TrimSpace(string(out))
	cfg := filepath.Join(root, "guardrail.toml")
	if _, err := os.Stat(cfg); err != nil {
		return "", false, ""
	}
	return cfg, true, ""
}
```

(`fmt` is already imported in `config.go`.)

- [ ] **Step 4: Run the test to verify it fails to compile elsewhere**

Run: `/usr/local/go/bin/go build ./...`
Expected: FAIL in `cmd/guardrail/hook.go` (`assignment mismatch: 2 variables but FindOverlayPath returns 3 values`). Fixed in Task 9.

- [ ] **Step 5: Commit (with the known build break noted)**

```bash
gofmt -w internal/policy/
git add internal/policy/
git commit -m "feat(policy): FindOverlayPath returns a warning instead of forcing a fail-closed on a stale GUARDRAIL_CONFIG

cmd/guardrail/hook.go caller updated in the next commit."
```

---

### Task 9: `cmdHook` consumes the warning, degrades to base-only

**Files:**
- Modify: `cmd/guardrail/hook.go`
- Modify: `cmd/guardrail/hook_test.go`

**Interfaces:**
- Consumes: the new 3-value `policy.FindOverlayPath`.
- Behavior: `pth, ok, warn := policy.FindOverlayPath(tc.CWD)`. If `warn != ""` ⇒ `fmt.Fprintln(stderr, warn)`. If `ok` ⇒ load + merge overlay as before (a *parse* error still ⇒ exit 2). If `!ok` ⇒ `ov` stays `nil`, `Merge(base, nil, version)` ⇒ base-only. The command's own verdict then drives the exit code.

- [ ] **Step 1: Write the failing test**

Add to `cmd/guardrail/hook_test.go`:

```go
func TestHookStaleGuardrailConfigDegrades(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	t.Setenv("GUARDRAIL_CONFIG", "/no/such/guardrail.toml")

	// a destructive command still gets blocked by the base policy
	rm := `{"cwd":"/tmp","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"rm -rf /"}}`
	var out, errb bytes.Buffer
	code := run([]string{"hook", "claude"}, bytes.NewReader([]byte(rm)), &out, &errb)
	if code != 2 {
		t.Fatalf("rm -rf with stale GUARDRAIL_CONFIG: exit %d, want 2 (base policy still applies)", code)
	}
	if !strings.Contains(errb.String(), "/no/such/guardrail.toml") {
		t.Errorf("expected a stale-config warning on stderr; got %q", errb.String())
	}

	// a benign command is allowed
	errb.Reset()
	out.Reset()
	ls := `{"cwd":"/tmp","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"ls"}}`
	code = run([]string{"hook", "claude"}, bytes.NewReader([]byte(ls)), &out, &errb)
	if code != 0 {
		t.Fatalf("ls with stale GUARDRAIL_CONFIG: exit %d, want 0", code)
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `/usr/local/go/bin/go test ./cmd/guardrail/ -run TestHookStale -v`
Expected: FAIL to compile (still the 2-value call), then FAIL the assertion once compiling.

- [ ] **Step 3: Write minimal implementation**

In `cmd/guardrail/hook.go`, replace the overlay-discovery block:

```go
	var ov *policy.Overlay
	if pth, ok, warn := policy.FindOverlayPath(tc.CWD); ok {
		if warn != "" {
			fmt.Fprintln(stderr, warn)
		}
		ov, err = policy.LoadOverlay(pth)
		if err != nil {
			fmt.Fprintf(stderr, "guardrail: cannot load overlay (%v); failing closed\n", err)
			return 2
		}
	} else if warn != "" {
		fmt.Fprintln(stderr, warn)
	}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `/usr/local/go/bin/go test ./cmd/guardrail/ -v`
Expected: PASS (including the Plan 1 hook tests, which set `GUARDRAIL_CONFIG=""`).

- [ ] **Step 5: Run the whole suite**

Run: `/usr/local/go/bin/go test ./... && /usr/local/go/bin/go vet ./...`
Expected: PASS, no vet complaints. `test/contract_test.go`'s `TestClaudeNeverPanics` (which does not clear `GUARDRAIL_CONFIG`) still passes because a stale value now degrades instead of exiting 2 — but note it will still be within its accepted `{0,2}` either way.

- [ ] **Step 6: Commit**

```bash
gofmt -w cmd/guardrail/
git add cmd/guardrail/
git commit -m "fix(cli): stale GUARDRAIL_CONFIG degrades to base-only + stderr warning, not exit 2 forever"
```

---

### Task 10: `guardrail doctor`

**Files:**
- Create: `cmd/guardrail/doctor.go`
- Create: `cmd/guardrail/doctor_test.go`
- Modify: `cmd/guardrail/run.go` (add `case "doctor"`)

**Interfaces:**
- Produces:
  - `func cmdDoctor(args []string, stdout, stderr io.Writer) int` — always returns `0`. Writes a plain-text report to `stdout`:
    - `guardrail <version>`
    - `cwd: <getwd>`
    - `GUARDRAIL_CONFIG: <value>` or `GUARDRAIL_CONFIG: (unset)`
    - `overlay: <path> (parsed OK)` / `overlay: <path> (PARSE ERROR: <err>)` / `overlay: none` — plus the `FindOverlayPath` warn line if any
    - `waivers: <comma-list>` or `waivers: none` (from `Merge` on the discovered overlay; empty if none)
    - `audit log: <audit.DefaultPath(mergedAuditLog)>`
    - `claude settings: <~/.claude/settings.json state>` — `guardrail hook registered` / `present, hook NOT registered` / `no settings.json`
  - Uses `os.Getwd()`, `policy.FindOverlayPath`, `policy.LoadBase`, `policy.LoadOverlay`, `policy.Merge`, `audit.DefaultPath`, and reads `~/.claude/settings.json` if present (`os.UserHomeDir`).

- [ ] **Step 1: Write the failing test**

`cmd/guardrail/doctor_test.go`:

```go
package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDoctorBasics(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_STATE_HOME", filepath.Join(home, "state"))
	t.Setenv("GUARDRAIL_CONFIG", "")

	var out, errb bytes.Buffer
	code := run([]string{"doctor"}, strings.NewReader(""), &out, &errb)
	if code != 0 {
		t.Fatalf("doctor exit = %d, want 0", code)
	}
	s := out.String()
	for _, want := range []string{"guardrail ", "GUARDRAIL_CONFIG:", "overlay:", "audit log:", "claude settings:"} {
		if !strings.Contains(s, want) {
			t.Errorf("doctor output missing %q\n---\n%s", want, s)
		}
	}
}

func TestDoctorStaleConfig(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("GUARDRAIL_CONFIG", "/no/such/file.toml")
	var out, errb bytes.Buffer
	run([]string{"doctor"}, strings.NewReader(""), &out, &errb)
	if !strings.Contains(out.String(), "/no/such/file.toml") {
		t.Errorf("doctor should surface the stale GUARDRAIL_CONFIG path:\n%s", out.String())
	}
}

func TestDoctorSeesRegisteredHook(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("GUARDRAIL_CONFIG", "")
	cdir := filepath.Join(home, ".claude")
	os.MkdirAll(cdir, 0o755)
	os.WriteFile(filepath.Join(cdir, "settings.json"),
		[]byte(`{"hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"guardrail hook claude"}]}]}}`), 0o644)
	var out, errb bytes.Buffer
	run([]string{"doctor"}, strings.NewReader(""), &out, &errb)
	if !strings.Contains(out.String(), "hook registered") {
		t.Errorf("doctor should detect the registered hook:\n%s", out.String())
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `/usr/local/go/bin/go test ./cmd/guardrail/ -run TestDoctor -v`
Expected: FAIL — `doctor` unknown / `cmdDoctor` undefined.

- [ ] **Step 3: Add the dispatch case**

In `cmd/guardrail/run.go` `switch args[0]`:

```go
	case "doctor":
		return cmdDoctor(args[1:], stdout, stderr)
```

- [ ] **Step 4: Write minimal implementation**

`cmd/guardrail/doctor.go`:

```go
package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/CtrlCarlitos/agent-guardrails/internal/audit"
	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
)

func cmdDoctor(args []string, stdout, stderr io.Writer) int {
	fmt.Fprintf(stdout, "guardrail %s\n", version)

	cwd, _ := os.Getwd()
	fmt.Fprintf(stdout, "cwd: %s\n", cwd)

	if v := os.Getenv("GUARDRAIL_CONFIG"); v != "" {
		fmt.Fprintf(stdout, "GUARDRAIL_CONFIG: %s\n", v)
	} else {
		fmt.Fprintln(stdout, "GUARDRAIL_CONFIG: (unset)")
	}

	base, baseErr := policy.LoadBase()
	if baseErr != nil {
		fmt.Fprintf(stdout, "base policy: ERROR %v\n", baseErr)
		return 0
	}

	pth, ok, warn := policy.FindOverlayPath(cwd)
	if warn != "" {
		fmt.Fprintf(stdout, "overlay: %s\n", warn)
	}
	var ov *policy.Overlay
	switch {
	case ok:
		o, err := policy.LoadOverlay(pth)
		if err != nil {
			fmt.Fprintf(stdout, "overlay: %s (PARSE ERROR: %v)\n", pth, err)
		} else {
			ov = o
			fmt.Fprintf(stdout, "overlay: %s (parsed OK)\n", pth)
		}
	case warn == "":
		fmt.Fprintln(stdout, "overlay: none")
	}

	merged, warnings, err := policy.Merge(base, ov, version)
	if err != nil {
		fmt.Fprintf(stdout, "merge: ERROR %v\n", err)
		return 0
	}
	for _, w := range warnings {
		fmt.Fprintf(stdout, "  %s\n", w)
	}

	var waived []string
	for k, v := range merged.Waived {
		if v {
			waived = append(waived, k)
		}
	}
	if len(waived) == 0 {
		fmt.Fprintln(stdout, "waivers: none")
	} else {
		fmt.Fprintf(stdout, "waivers: %s\n", strings.Join(waived, ", "))
	}

	fmt.Fprintf(stdout, "audit log: %s\n", audit.DefaultPath(merged.Slots.AuditLog))

	fmt.Fprintf(stdout, "claude settings: %s\n", claudeSettingsState())
	return 0
}

func claudeSettingsState() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return "unknown (no home dir)"
	}
	p := filepath.Join(home, ".claude", "settings.json")
	raw, err := os.ReadFile(p)
	if err != nil {
		return "no settings.json"
	}
	if strings.Contains(string(raw), "guardrail hook claude") {
		return "guardrail hook registered"
	}
	return "present, hook NOT registered"
}
```

- [ ] **Step 5: Run the test to verify it passes**

Run: `/usr/local/go/bin/go test ./cmd/guardrail/ -run TestDoctor -v`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
gofmt -w cmd/guardrail/
git add cmd/guardrail/
git commit -m "feat(cli): guardrail doctor — resolved version, overlay, waivers, audit path, hook state"
```

---

### Task 11: `--help` / usage text, README Layout + Status fix

**Files:**
- Modify: `cmd/guardrail/run.go` (usage on no-subcommand / `help` / `-h`)
- Modify: `README.md`

**Interfaces:**
- `run` with `args[0]` in `{"help","-h","--help"}` ⇒ print a usage block to `stdout`, return `0`. The no-subcommand branch prints the same block to `stderr` and returns `2`.
- Usage lists: `version`, `hook <plane>`, `gen-config <plane> [--print|--merge <path>] [--binary <path>]`, `doctor`.

- [ ] **Step 1: Write the failing test**

Add to `cmd/guardrail/run_test.go`:

```go
func TestRunHelp(t *testing.T) {
	var out, errb bytes.Buffer
	code := run([]string{"help"}, strings.NewReader(""), &out, &errb)
	if code != 0 {
		t.Fatalf("help exit = %d, want 0", code)
	}
	for _, want := range []string{"hook", "gen-config", "doctor", "version"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("usage missing %q", want)
		}
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `/usr/local/go/bin/go test ./cmd/guardrail/ -run TestRunHelp -v`
Expected: FAIL — `help` is an unknown subcommand (exit 2).

- [ ] **Step 3: Write minimal implementation**

In `cmd/guardrail/run.go`, add a `usage` string and handle it:

```go
const usage = `guardrail — one guardrail policy across AI coding-agent planes

usage:
  guardrail version
  guardrail hook <plane>              evaluate a hook payload on stdin (plane: claude)
  guardrail gen-config <plane> [flags]  emit/merge the declarative floor (plane: claude)
      --print            write the JSON fragment to stdout (default)
      --merge <path>     deep-merge it into <path> in place, idempotently
      --binary <path>    guardrail path to register in the hook command (default "guardrail")
  guardrail doctor                   print resolved policy/overlay/audit/hook state
`

// in run(), before the switch's default:
	case "help", "-h", "--help":
		fmt.Fprint(stdout, usage)
		return 0
```

And change the `len(args) == 0` branch body to:

```go
		fmt.Fprint(stderr, usage)
		return 2
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `/usr/local/go/bin/go test ./cmd/guardrail/ -v`
Expected: PASS. `TestRunNoArgs` still expects exit 2 — unchanged.

- [ ] **Step 5: Fix `README.md`**

Replace the **Status** section body with:

```markdown
## Status

Plans 1–2 implemented. `guardrail hook claude` enforces P1 (destructive commands)
and P4 (secret paths) with audit logging and per-repo `guardrail.toml` overlays;
`guardrail gen-config claude` emits/merges the Claude declarative floor (`hooks`
registration + a coarse `permissions` deny/ask set); `guardrail doctor` reports
resolved state. Pending: CI release workflow + dotfiles installer + smoke test
(Plan 3), remaining policy modules P2/P5/P6/P7/P10 (Plan 4), opencode adapter
(Plan 5), Antigravity adapter (Plan 6), recipes + `guardrail sync` (Plan 7).
```

In the **Layout** block, change the `cmd/guardrail/` line to:

```
cmd/guardrail/        Engine entrypoint; `guardrail hook <plane>`, `gen-config <plane>`, `doctor` (`sync` is planned, Plan 7)
```

and add a line:

```
internal/genconfig/   Translate the policy into each plane's native declarative floor + idempotent merge
```

- [ ] **Step 6: Commit**

```bash
gofmt -w cmd/guardrail/
git add cmd/guardrail/ README.md
git commit -m "feat(cli): usage/help text; docs: README reflects gen-config + doctor"
```

---

### Task 12: Golden test for `gen-config claude --print`, Makefile target, tag

**Files:**
- Create: `test/fixtures/claude/settings-floor.golden.json`
- Create: `test/genconfig_test.go`
- Modify: `Makefile`

**Interfaces:**
- `test/genconfig_test.go` (`package test`, black-box): builds the binary (reuse the `buildBinary` helper pattern from `test/contract_test.go` — if it is unexported there and in the same package, call it directly; both files are `package test`), runs `guardrail gen-config claude --print --binary /usr/local/bin/guardrail`, and asserts the stdout equals `settings-floor.golden.json` byte-for-byte. A `-update` flag regenerates the golden.

- [ ] **Step 1: Write the failing test**

`test/genconfig_test.go`:

```go
package test

import (
	"bytes"
	"flag"
	"os"
	"os/exec"
	"testing"
)

var updateGolden = flag.Bool("update", false, "rewrite golden files")

func TestGenConfigClaudeGolden(t *testing.T) {
	bin := buildBinary(t) // from contract_test.go, same package
	cmd := exec.Command(bin, "gen-config", "claude", "--print", "--binary", "/usr/local/bin/guardrail")
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		t.Fatalf("run: %v", err)
	}
	golden := "fixtures/claude/settings-floor.golden.json"
	if *updateGolden {
		if err := os.WriteFile(golden, out.Bytes(), 0o644); err != nil {
			t.Fatal(err)
		}
		t.Logf("wrote %s", golden)
		return
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatalf("read golden (run with -update once): %v", err)
	}
	if !bytes.Equal(want, out.Bytes()) {
		t.Fatalf("gen-config output drift.\n--- got ---\n%s\n--- want ---\n%s", out.String(), want)
	}
}
```

- [ ] **Step 2: Run to generate the golden, then verify**

Run:
```bash
/usr/local/go/bin/go test ./test/ -run TestGenConfigClaudeGolden -update
/usr/local/go/bin/go test ./test/ -run TestGenConfigClaudeGolden -v
```
Expected: first writes `test/fixtures/claude/settings-floor.golden.json`; second PASSES. Open the golden and sanity-check it: `hooks.PreToolUse[0].hooks[0].command == "/usr/local/bin/guardrail hook claude"`, `permissions.deny` contains `Bash(rm -rf *)` and `Read(**/.ssh/**)` but not `Read(.env.*)`, `permissions.ask` contains `Bash(chmod -R *)`.

- [ ] **Step 3: Add the Makefile target**

Append to `Makefile`:

```make
.PHONY: golden
golden:
	$(GO) test ./test/ -run Golden -update
```

- [ ] **Step 4: Full green + vet**

Run: `/usr/local/go/bin/go test ./... && /usr/local/go/bin/go vet ./... && $(command -v gofmt || echo /usr/local/go/bin/gofmt) -l .`
Expected: all tests pass; vet clean; `gofmt -l` prints nothing.

- [ ] **Step 5: Commit and tag**

```bash
git add test/ Makefile
git commit -m "test: golden for gen-config claude --print; make golden target"
git tag v0.2.0-dev
```

---

## Self-Review

**1. Spec coverage.** This plan implements the agent-guardrails slice of the handoff's "Plan 2":

| Item | Task |
|---|---|
| `guardrail gen-config claude` — emit declarative floor | 1, 2, 3, 4, 5 |
| Floor = `hooks` registration + `permissions` deny/ask derived from Base | 2 (P1 Bash), 3 (P4 secret), 4 (hooks), 5 (assemble) |
| `secret_allow` honored (no `.env.example` deny) | 3 |
| Idempotent in-place merge into `~/.claude/settings.json`, preserving unrelated keys | 6, 7 |
| Configurable binary path in the hook command (for the installer) | 1, 4, 7 |
| Stale `GUARDRAIL_CONFIG` no longer forces `exit 2` on every call (parked gap) | 8, 9 |
| Malformed overlay still fails closed | 9 (unchanged path) |
| `guardrail doctor` self-diagnostic | 10 |
| Usage/help; README no longer claims unimplemented subcommands | 11 |
| Regression lock (golden) | 12 |

Deferred, by design: the CI release workflow, the chezmoi installer function, `~/scripts/update_ai_tools.sh` section, the `.chezmoi.toml.tmpl` toggle, `docs/tool-parity.md` row, and the real-Claude smoke test are **Plan 3**. `gen-config` for opencode/antigravity is Plan 5/6. `--overlay` support in `gen-config` (for `guardrail sync`) is Plan 7.

**2. Placeholder scan.** No `TBD`/`TODO`/"handle errors appropriately"/"similar to". Every code and test block is literal. Task 5 and Task 7 explicitly stage the `--merge` path ("implemented in Task 7") — that is a real intermediate state with a working `--print`, not a placeholder, and the stub returns `2` + a message rather than silently succeeding.

**3. Type consistency.**
- `genconfig.Fragment = map[string]any` — defined Task 2, used Tasks 3, 5, 6, 7.
- `genconfig.ClaudeConfig(*policy.Policy, string) Fragment` — Task 5, called Tasks 5, 7 (via `cmdGenConfig`).
- `genconfig.MergeInto(string, Fragment) error` — Task 6, called Task 7.
- `genconfig.bashDenyGlobs() []string` / `bashAskGlobs() []string` / `secretDenyGlobs(*policy.Policy) []string` / `claudeHooks(string) map[string]any` — Tasks 2–4, consumed by `ClaudeConfig` Task 5.
- `policy.FindOverlayPath(string) (string, bool, string)` — new signature Task 8; sole non-test caller `cmd/guardrail/hook.go` updated Task 9; `cmd/guardrail/doctor.go` Task 10 uses the 3-value form from the start.
- `cmdGenConfig(args []string, stdout, stderr io.Writer) int` / `cmdDoctor(args []string, stdout, stderr io.Writer) int` — Tasks 1, 10; dispatched from `run` Tasks 1, 10.
- `version` (`package main`) — read by `cmdDoctor` (Task 10) and passed to `policy.Merge` there; ldflags-set, defaults `"dev"` (consistent with Plan 1).
- `audit.DefaultPath(string) string` — unchanged from Plan 1, called Task 10.
- `test` package `buildBinary(t)` helper — introduced in Plan 1's `test/contract_test.go`, reused Task 12 (same package, no redefinition).

No drift found. `flag.FlagSet` with `flag.ContinueOnError` + `SetOutput(stderr)` returns a non-nil error on bad flags (Task 1) — `run` maps that to exit 2, matching `TestGenConfigBadFlag`.

---

## Execution Handoff

**Plan complete and saved to `docs/superpowers/plans/2026-09-03-claude-genconfig-and-doctor.md`. Two execution options:**

**1. Subagent-Driven (recommended)** — fresh subagent per task via `superpowers:subagent-driven-development`, review between tasks.

**2. Inline Execution** — `superpowers:executing-plans`, batch with checkpoints.

**Which approach?**
