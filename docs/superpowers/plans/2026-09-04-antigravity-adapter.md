# Antigravity Adapter — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** `guardrail hook antigravity <pre|post>` — a third plane subcommand sharing the entire existing pipeline — plus `guardrail gen-config antigravity` emitting Antigravity's native `hooks.json` (global: `~/.gemini/config/hooks.json`; project: `<workspace>/.agents/hooks.json`, same format for both).

**Architecture:** Antigravity invokes a command directly, like Claude — no in-process runtime to bridge, unlike opencode. The phase (`pre`/`post`) arrives as **argv**, not in the JSON payload (confirmed by takumi-dream's live, working `.agents/hooks.json`, which registers `"command": "python3 ./hooks/antigravity-guard.py pre"`). `adapter.ParseAntigravity(phase, r)` and `adapter.EmitAntigravity(v, phase, stdout)` join `ParseClaude`/`EmitClaude` and `ParseOpencode`/`EmitOpencode`; `cmdHook`'s plane dispatch grows a third arm. `genconfig.AntigravityConfig` reuses Plan 3's already-generic `mergeHooks`/`deepMerge` by marking its own hook groups `"id":"guardrail-antigravity-pre"/"-post"` — zero merge.go changes, same as the `SessionStart` group added in Plan 4b.

**Tech Stack:** Go 1.23+, existing deps only.

**Spec:** `../../../DESIGN.md` Q7, Q11c, Q17. Confirmed by official-docs research earlier in this project (Antigravity's own `hooks.json` schema, changelog corroboration, Google DevRel corroboration): global hooks at `~/.gemini/config/hooks.json`; events `PreToolUse`, `PostToolUse`, `PreInvocation`, `PostInvocation`, `Stop`; decision values `allow|deny|ask|force_ask|deny_unless_prior_grant`; `PostToolUse` returns `{}`; **exit code is not the protocol** — the decision lives entirely in the stdout JSON; default hook timeout 30s; only the `agy` CLI and the Antigravity IDE run hooks (both confirmed working by Carlitos hands-on, Q7). Reference implementation on this machine, proven working: `/home/carlitos/projects/CtrlCarlitos/takumi-dream/.agents/hooks/antigravity-guard.py` and `/home/carlitos/projects/CtrlCarlitos/takumi-dream/.agents/hooks.json`.

## Global Constraints

- **Antigravity has no separate declarative permission layer** the way Claude (`permissions.deny/ask`) and opencode (`permission.bash/read/edit`) do — the `hooks.json` registration *is* the entire enforcement surface. There is no "coarse floor + dynamic engine" split for this plane; `AntigravityConfig`'s fragment is hook registration only, no `permissions`-equivalent key. This is a real, inherent platform limitation (documented in Task 8's ADR), not something to work around.
- **Response protocol is JSON-only.** `EmitAntigravity` always returns exit `0` — Antigravity does not use the exit code as a signal (confirmed by research; unlike Claude's exit-2-blocks convention).
- **Phase comes from argv, not the payload.** `guardrail hook antigravity pre` / `guardrail hook antigravity post` — `cmdHook` must accept a second positional arg for this plane only.
- **Unknown/ungated tool names must fail safe as `Allow`, not error.** Antigravity's tool set includes `grep_search`, `search_web`, `read_url_content` and others this project has no rules for yet — `normalizeAntigravityTool` passing an unrecognized name through unchanged means `isFileTool`/`tc.IsBash()` are both false, so `Evaluate` naturally returns `Allow`. That is correct today; it is not a security gap because there is no rule content for those tools to bypass yet.
- Every code step is literal. `gofmt -w` before every commit. Conventional Commits, one commit per task.
- Verified current state relevant to this plan: `cmd/guardrail/hook.go`'s plane `switch` currently has `"claude"` and `"opencode"` arms (Plan 5); `internal/genconfig/merge.go`'s `mergeHooks` is generic over any event key found under a `"hooks"` fragment key, keyed by owned-`id` prefix `guardrail-`; `internal/adapter/claude.go` has an unexported `repoRoot(cwd string) string` helper, reusable as-is by the new adapter file.

---

### Task 1: Verify the payload shape and `hooks.json` structure against the live reference

**Files:** none (investigation only — findings feed Tasks 2, 3, 5).

- [ ] **Step 1: Read the live, working files in full**

Run:
```bash
cat -n /home/carlitos/projects/CtrlCarlitos/takumi-dream/.agents/hooks.json
cat -n /home/carlitos/projects/CtrlCarlitos/takumi-dream/.agents/hooks/antigravity-guard.py
cat -n /home/carlitos/projects/CtrlCarlitos/takumi-dream/.agents/hooks/test_guard.py
```

Confirm specifically:
1. **`hooks.json` top-level structure**: is `PreToolUse`/`PostToolUse` at the JSON root, or nested under a named key (takumi's file wraps them under `"takumi-guard": {"enabled": true, ...}`)? Determine whether that wrapper is a **schema requirement** or just takumi's own organizational choice (their spec docs at `/home/carlitos/projects/CtrlCarlitos/takumi-dream/docs/superpowers/specs/2026-09-03-antigravity-guardrails-design.md`, if present, may say). If genuinely ambiguous, prefer the flat root-level structure (`{"PreToolUse":[...],"PostToolUse":[...]}`) as the default — it matches how Claude Code's own `hooks.json`/`settings.json` `hooks` key already works in this codebase and is the simpler hypothesis; but if the docs or the file clearly require a named wrapper, follow that instead.
2. **Exact stdin JSON field names** the Python script reads: `toolCall.name`, `toolCall.args.CommandLine`, `toolCall.args.Cwd` (or how CWD is actually obtained — the script may use its own CWD via `pathlib`/`os.getcwd()` rather than reading it from the payload; note which), `toolCall.args.AbsolutePath`, `toolCall.args.TargetFile`, `conversationId`, `workspacePaths`.
3. **Exact response JSON** the script emits for `pre` (`{"decision":"allow"|"deny"|"ask", "reason":...}`) and for `post` (confirm it emits `{}`).
4. **Timeout and matcher values** actually registered (`PreToolUse` matcher, `PostToolUse` matcher, timeout numbers) — Task 5's fragment should match these unless there's a reason to differ.

- [ ] **Step 2: No commit** (investigation only; carry findings into later tasks' code and commit messages if they deviate from this plan's drafts).

---

### Task 2: `adapter.ParseAntigravity`

**Files:**
- Create: `internal/adapter/antigravity.go`
- Create: `internal/adapter/antigravity_test.go`

**Interfaces:**
- `func ParseAntigravity(phase string, r io.Reader) (engine.ToolCall, error)` — decodes `{"conversationId":"...","toolCall":{"name":"...","args":{...}},"workspacePaths":["..."]}`; `args` parsed permissively into a struct carrying `CommandLine`, `Cwd`, `AbsolutePath`, `TargetFile` (adjust field names per Task 1's findings). `Event`: `"pre"` unless `phase == "post"`. `Tool` via `normalizeAntigravityTool` (`run_command→Bash`, `view_file→Read`, `write_to_file→Write`, `replace_file_content`/`multi_replace_file_content`→`Edit`, else passthrough). `CWD`: the args' `Cwd` if present, else the first `workspacePaths` entry, else `""`. `Paths`: `[AbsolutePath]` if non-empty, else `[TargetFile]` if non-empty, else `nil`. `Plane: "antigravity"`, `SessionID: conversationId`, `RepoRoot` via the existing `repoRoot(cwd)` helper (same package as `claude.go`, reused unmodified).

- [ ] **Step 1: Write the failing test**

`internal/adapter/antigravity_test.go`:

```go
package adapter

import (
	"strings"
	"testing"
)

func TestParseAntigravityBash(t *testing.T) {
	raw := `{"conversationId":"c1","toolCall":{"name":"run_command","args":{"CommandLine":"rm -rf /","Cwd":"/tmp"}},"workspacePaths":["/tmp"]}`
	tc, err := ParseAntigravity("pre", strings.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	if tc.Plane != "antigravity" || tc.Tool != "Bash" || tc.Command != "rm -rf /" || tc.Event != "pre" || tc.SessionID != "c1" {
		t.Fatalf("bad ToolCall: %+v", tc)
	}
}

func TestParseAntigravityFileTool(t *testing.T) {
	raw := `{"conversationId":"c1","toolCall":{"name":"write_to_file","args":{"AbsolutePath":"/tmp/.env"}}}`
	tc, err := ParseAntigravity("pre", strings.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	if tc.Tool != "Write" || len(tc.Paths) != 1 || tc.Paths[0] != "/tmp/.env" {
		t.Fatalf("bad ToolCall: %+v", tc)
	}
}

func TestParseAntigravityPostPhase(t *testing.T) {
	tc, err := ParseAntigravity("post", strings.NewReader(`{"toolCall":{"name":"replace_file_content","args":{"TargetFile":"/tmp/x.go"}}}`))
	if err != nil {
		t.Fatal(err)
	}
	if tc.Event != "post" || tc.Tool != "Edit" || tc.Paths[0] != "/tmp/x.go" {
		t.Fatalf("bad ToolCall: %+v", tc)
	}
}

func TestParseAntigravityCWDFallsBackToWorkspacePaths(t *testing.T) {
	raw := `{"toolCall":{"name":"run_command","args":{"CommandLine":"ls"}},"workspacePaths":["/repo"]}`
	tc, err := ParseAntigravity("pre", strings.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	if tc.CWD != "/repo" {
		t.Fatalf("CWD = %q, want /repo (from workspacePaths)", tc.CWD)
	}
}

func TestParseAntigravityUnknownToolPassesThrough(t *testing.T) {
	tc, err := ParseAntigravity("pre", strings.NewReader(`{"toolCall":{"name":"grep_search","args":{}}}`))
	if err != nil {
		t.Fatal(err)
	}
	if tc.Tool != "grep_search" {
		t.Fatalf("Tool = %q, want passthrough grep_search", tc.Tool)
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `/usr/local/go/bin/go test ./internal/adapter/ -run TestParseAntigravity -v`
Expected: FAIL — undefined.

- [ ] **Step 3: Write minimal implementation**

`internal/adapter/antigravity.go` (adjust field names per Task 1's findings if they differ):

```go
package adapter

import (
	"encoding/json"
	"io"

	"github.com/CtrlCarlitos/agent-guardrails/internal/engine"
	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
)

type antigravityArgs struct {
	CommandLine  string `json:"CommandLine"`
	Cwd          string `json:"Cwd"`
	AbsolutePath string `json:"AbsolutePath"`
	TargetFile   string `json:"TargetFile"`
}

type antigravityToolCall struct {
	Name string          `json:"name"`
	Args antigravityArgs `json:"args"`
}

type antigravityPayload struct {
	ConversationID string              `json:"conversationId"`
	ToolCall       antigravityToolCall `json:"toolCall"`
	WorkspacePaths []string            `json:"workspacePaths"`
}

func ParseAntigravity(phase string, r io.Reader) (engine.ToolCall, error) {
	raw, err := io.ReadAll(r)
	if err != nil {
		return engine.ToolCall{}, err
	}
	var p antigravityPayload
	if err := json.Unmarshal(raw, &p); err != nil {
		return engine.ToolCall{}, err
	}

	event := "pre"
	if phase == "post" {
		event = "post"
	}

	cwd := p.ToolCall.Args.Cwd
	if cwd == "" && len(p.WorkspacePaths) > 0 {
		cwd = p.WorkspacePaths[0]
	}

	var paths []string
	if p.ToolCall.Args.AbsolutePath != "" {
		paths = []string{p.ToolCall.Args.AbsolutePath}
	} else if p.ToolCall.Args.TargetFile != "" {
		paths = []string{p.ToolCall.Args.TargetFile}
	}

	tc := engine.ToolCall{
		Plane:     "antigravity",
		Event:     event,
		Tool:      normalizeAntigravityTool(p.ToolCall.Name),
		Command:   p.ToolCall.Args.CommandLine,
		Paths:     paths,
		SessionID: p.ConversationID,
		CWD:       cwd,
		Raw:       raw,
	}
	tc.RepoRoot = repoRoot(cwd)
	return tc, nil
}

func normalizeAntigravityTool(name string) string {
	switch name {
	case "run_command":
		return "Bash"
	case "view_file":
		return "Read"
	case "write_to_file":
		return "Write"
	case "replace_file_content", "multi_replace_file_content":
		return "Edit"
	default:
		return name
	}
}

// EmitAntigravity is defined in Task 3 — declared here only as a forward
// reference in this doc comment for readers; the real function lives in
// this same file once Task 3 lands.
var _ = policy.Allow // placeholder import anchor removed once EmitAntigravity (Task 3) uses the policy package
```

(The trailing `var _ = policy.Allow` line exists only so this task's file compiles standing alone before Task 3 adds real `policy` usage — Task 3 replaces it with `EmitAntigravity`. Remove it as part of Task 3's diff, don't leave both.)

- [ ] **Step 4: Run the test to verify it passes**

Run: `/usr/local/go/bin/go test ./internal/adapter/ -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
gofmt -w internal/adapter/
git add internal/adapter/
git commit -m "feat(adapter): ParseAntigravity — argv phase + toolCall.args payload"
```

---

### Task 3: `adapter.EmitAntigravity`

**Files:**
- Modify: `internal/adapter/antigravity.go`
- Modify: `internal/adapter/antigravity_test.go`

**Interfaces:**
- `func EmitAntigravity(v policy.Verdict, phase string, stdout io.Writer) int` — `phase == "post"` writes `{}` and returns `0`, ignoring `v` entirely (matches the confirmed contract). Otherwise writes `{"decision":"allow"|"ask"|"deny"[,"reason":"..."]}` (the `reason` key omitted when empty) and **always returns `0`** — exit code carries no protocol meaning for this plane.

- [ ] **Step 1: Write the failing test**

Add to `internal/adapter/antigravity_test.go`:

```go
import (
	"bytes"
	"encoding/json"
	"github.com/CtrlCarlitos/agent-guardrails/internal/policy" // add to imports
)

func TestEmitAntigravityPre(t *testing.T) {
	var out bytes.Buffer
	code := EmitAntigravity(policy.Verdict{Decision: policy.Deny, Reason: "no"}, "pre", &out)
	if code != 0 {
		t.Fatalf("code = %d, want 0 (exit code carries no meaning here)", code)
	}
	var got map[string]string
	json.Unmarshal(out.Bytes(), &got)
	if got["decision"] != "deny" || got["reason"] != "no" {
		t.Fatalf("bad payload: %v", got)
	}
}

func TestEmitAntigravityPost(t *testing.T) {
	var out bytes.Buffer
	code := EmitAntigravity(policy.Verdict{Decision: policy.Deny, Reason: "irrelevant"}, "post", &out)
	if code != 0 || out.String() != "{}\n" {
		t.Fatalf("post phase must always emit {} regardless of v; got code=%d out=%q", code, out.String())
	}
}

func TestEmitAntigravityAllowOmitsReason(t *testing.T) {
	var out bytes.Buffer
	EmitAntigravity(policy.Verdict{Decision: policy.Allow}, "pre", &out)
	var got map[string]any
	json.Unmarshal(out.Bytes(), &got)
	if _, ok := got["reason"]; ok {
		t.Errorf("reason should be omitted when empty: %v", got)
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `/usr/local/go/bin/go test ./internal/adapter/ -run TestEmitAntigravity -v`
Expected: FAIL — undefined.

- [ ] **Step 3: Write minimal implementation**

In `internal/adapter/antigravity.go`, delete the placeholder `var _ = policy.Allow` line from Task 2 and add:

```go
func EmitAntigravity(v policy.Verdict, phase string, stdout io.Writer) int {
	if phase == "post" {
		stdout.Write([]byte("{}\n"))
		return 0
	}
	payload := map[string]any{"decision": string(v.Decision)}
	if v.Reason != "" {
		payload["reason"] = v.Reason
	}
	b, _ := json.Marshal(payload)
	stdout.Write(append(b, '\n'))
	return 0
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `/usr/local/go/bin/go test ./internal/adapter/ -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
gofmt -w internal/adapter/
git add internal/adapter/
git commit -m "feat(adapter): EmitAntigravity — decision JSON, post phase always {}, exit code always 0"
```

---

### Task 4: Wire `guardrail hook antigravity <phase>` into `cmdHook`

**Files:**
- Modify: `cmd/guardrail/hook.go`
- Modify: `cmd/guardrail/hook_test.go`

**Interfaces:**
- `cmdHook`'s plane `switch` gains a `"antigravity"` case: requires `len(args) >= 2` (plane + phase), stores the phase, calls `adapter.ParseAntigravity(phase, stdin)`. The shared pipeline (base/overlay/merge/session-start-branch/trifecta/evaluate/audit) runs unchanged — `tc.Event == "session-start"` never happens for this plane, so that branch stays dormant exactly as it does for opencode. Final emit switch gains `case "antigravity": return adapter.EmitAntigravity(v, antigravityPhase, stdout)`.

- [ ] **Step 1: Write the failing test**

Add to `cmd/guardrail/hook_test.go`:

```go
func TestHookAntigravityDeny(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	t.Setenv("GUARDRAIL_CONFIG", "")
	payload := `{"conversationId":"c1","toolCall":{"name":"run_command","args":{"CommandLine":"rm -rf /","Cwd":"/tmp"}}}`
	var out, errb bytes.Buffer
	code := run([]string{"hook", "antigravity", "pre"}, strings.NewReader(payload), &out, &errb)
	if code != 0 {
		t.Fatalf("exit=%d, want 0 (antigravity never uses exit code); stderr=%s", code, errb.String())
	}
	if !strings.Contains(out.String(), `"decision":"deny"`) {
		t.Fatalf("stdout = %s, want a deny decision", out.String())
	}
}

func TestHookAntigravityAllow(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	t.Setenv("GUARDRAIL_CONFIG", "")
	payload := `{"conversationId":"c1","toolCall":{"name":"run_command","args":{"CommandLine":"ls -la","Cwd":"/tmp"}}}`
	var out, errb bytes.Buffer
	code := run([]string{"hook", "antigravity", "pre"}, strings.NewReader(payload), &out, &errb)
	if code != 0 || !strings.Contains(out.String(), `"decision":"allow"`) {
		t.Fatalf("code=%d stdout=%s", code, out.String())
	}
}

func TestHookAntigravityPostAlwaysEmptyObject(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	t.Setenv("GUARDRAIL_CONFIG", "")
	payload := `{"conversationId":"c1","toolCall":{"name":"replace_file_content","args":{"TargetFile":"/tmp/.env"}}}`
	var out, errb bytes.Buffer
	code := run([]string{"hook", "antigravity", "post"}, strings.NewReader(payload), &out, &errb)
	if code != 0 || out.String() != "{}\n" {
		t.Fatalf("post phase: code=%d out=%q, want 0/{}", code, out.String())
	}
}

func TestHookAntigravityMissingPhase(t *testing.T) {
	var out, errb bytes.Buffer
	code := run([]string{"hook", "antigravity"}, strings.NewReader(""), &out, &errb)
	if code != 2 {
		t.Fatalf("code = %d, want 2 (missing phase)", code)
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `/usr/local/go/bin/go test ./cmd/guardrail/ -run TestHookAntigravity -v`
Expected: FAIL — `antigravity` is currently "unsupported plane".

- [ ] **Step 3: Write minimal implementation**

In `cmd/guardrail/hook.go`, extend the plane-dispatch block at the top of `cmdHook`:

```go
	plane := args[0]

	var tc engine.ToolCall
	var err error
	var antigravityPhase string
	switch plane {
	case "claude":
		tc, err = adapter.ParseClaude(stdin)
	case "opencode":
		tc, err = adapter.ParseOpencode(stdin)
	case "antigravity":
		if len(args) < 2 {
			fmt.Fprintln(stderr, "guardrail: hook antigravity needs a phase (pre, post)")
			return 2
		}
		antigravityPhase = args[1]
		tc, err = adapter.ParseAntigravity(antigravityPhase, stdin)
	default:
		fmt.Fprintf(stderr, "guardrail: unsupported plane %q\n", plane)
		return 2
	}
```

And extend the final emit switch:

```go
	switch plane {
	case "claude":
		return adapter.EmitClaude(v, tc.Event, stdout, stderr)
	case "opencode":
		return adapter.EmitOpencode(v, stdout, stderr)
	case "antigravity":
		return adapter.EmitAntigravity(v, antigravityPhase, stdout)
	default:
		return 2
	}
```

(Everything between these two blocks — `policy.LoadBase`, `FindOverlayPath`/`LoadOverlay`, `Merge`, the `session-start` branch, `engine.Evaluate`, the trifecta block, `audit.Write` — is untouched, exactly as Plan 5's Task 3 left it.)

- [ ] **Step 4: Run the tests to verify they pass**

Run: `/usr/local/go/bin/go test ./cmd/guardrail/ -v`
Expected: PASS. Run the full suite: `/usr/local/go/bin/go test ./... -v`.

- [ ] **Step 5: Commit**

```bash
gofmt -w cmd/guardrail/
git add cmd/guardrail/
git commit -m "feat(cli): guardrail hook antigravity <pre|post> — third plane, shares the full pipeline"
```

---

### Task 5: `genconfig.AntigravityConfig`

**Files:**
- Create: `internal/genconfig/antigravity.go`
- Create: `internal/genconfig/antigravity_test.go`

**Interfaces:**
- `func AntigravityConfig(binary string) Fragment` — returns `{"hooks": {"PreToolUse":[...], "PostToolUse":[...]}}` (root shape per Task 1's finding — adjust if a named wrapper key is required instead). `PreToolUse` group: `id:"guardrail-antigravity-pre"`, `matcher:"run_command|view_file|write_to_file|replace_file_content|multi_replace_file_content"`, `hooks:[{type:"command", command: binary+" hook antigravity pre", timeout: 15}]`. `PostToolUse` group: `id:"guardrail-antigravity-post"`, `matcher:"write_to_file|replace_file_content|multi_replace_file_content"`, `hooks:[{type:"command", command: binary+" hook antigravity post", timeout: 120}]` (timeouts per Task 1's confirmed values — adjust if they differ from takumi's 15/120).
- No `permissions` key — Antigravity has no declarative permission layer (Global Constraints).

- [ ] **Step 1: Write the failing test**

`internal/genconfig/antigravity_test.go`:

```go
package genconfig

import "testing"

func TestAntigravityConfigShape(t *testing.T) {
	frag := AntigravityConfig("/usr/local/bin/guardrail")
	hooks := frag["hooks"].(map[string]any)

	pre := hooks["PreToolUse"].([]any)[0].(map[string]any)
	if pre["id"] != "guardrail-antigravity-pre" {
		t.Errorf("pre id = %v", pre["id"])
	}
	preCmd := pre["hooks"].([]any)[0].(map[string]any)["command"].(string)
	if preCmd != "/usr/local/bin/guardrail hook antigravity pre" {
		t.Errorf("pre command = %q", preCmd)
	}

	post := hooks["PostToolUse"].([]any)[0].(map[string]any)
	if post["id"] != "guardrail-antigravity-post" {
		t.Errorf("post id = %v", post["id"])
	}
	postCmd := post["hooks"].([]any)[0].(map[string]any)["command"].(string)
	if postCmd != "/usr/local/bin/guardrail hook antigravity post" {
		t.Errorf("post command = %q", postCmd)
	}

	if _, ok := frag["permissions"]; ok {
		t.Error("AntigravityConfig should not emit a permissions key — no declarative layer exists for this plane")
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `/usr/local/go/bin/go test ./internal/genconfig/ -run TestAntigravityConfigShape -v`
Expected: FAIL — `AntigravityConfig` undefined.

- [ ] **Step 3: Write minimal implementation**

`internal/genconfig/antigravity.go` (timeouts/matcher per Task 1's confirmed findings):

```go
package genconfig

func AntigravityConfig(binary string) Fragment {
	preCmd := binary + " hook antigravity pre"
	postCmd := binary + " hook antigravity post"
	return Fragment{
		"hooks": map[string]any{
			"PreToolUse": []any{
				map[string]any{
					"id":      "guardrail-antigravity-pre",
					"matcher": "run_command|view_file|write_to_file|replace_file_content|multi_replace_file_content",
					"hooks": []any{
						map[string]any{"type": "command", "command": preCmd, "timeout": 15},
					},
				},
			},
			"PostToolUse": []any{
				map[string]any{
					"id":      "guardrail-antigravity-post",
					"matcher": "write_to_file|replace_file_content|multi_replace_file_content",
					"hooks": []any{
						map[string]any{"type": "command", "command": postCmd, "timeout": 120},
					},
				},
			},
		},
	}
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `/usr/local/go/bin/go test ./internal/genconfig/ -v`
Expected: PASS.

- [ ] **Step 5: Merge regression check — reuse Plan 3's owned-entry machinery with zero merge.go changes**

Add to `internal/genconfig/antigravity_test.go`:

```go
func TestMergeAntigravityRebindsBinaryNoFork(t *testing.T) {
	p := filepath.Join(t.TempDir(), "hooks.json")
	MergeInto(p, AntigravityConfig("/old/guardrail"))
	MergeInto(p, AntigravityConfig("/new/guardrail"))
	m := readJSON(t, p)
	pre := m["hooks"].(map[string]any)["PreToolUse"].([]any)
	if len(pre) != 1 {
		t.Fatalf("want exactly 1 owned PreToolUse group after a rebind, got %d: %v", len(pre), pre)
	}
	cmd := pre[0].(map[string]any)["hooks"].([]any)[0].(map[string]any)["command"].(string)
	if cmd != "/new/guardrail hook antigravity pre" {
		t.Fatalf("command = %q, want the new binary path", cmd)
	}
}
```

(Add `"path/filepath"` to imports if absent; `readJSON` is the existing test helper from `internal/genconfig/merge_test.go`, same package.)

Run: `/usr/local/go/bin/go test ./internal/genconfig/ -run TestMergeAntigravity -v`
Expected: PASS with **no changes to `merge.go`** — this locks in that Plan 3's generic `mergeHooks` correctly handles a third plane's hook groups purely because they follow the same `id`-prefix convention.

- [ ] **Step 6: Commit**

```bash
gofmt -w internal/genconfig/
git add internal/genconfig/
git commit -m "feat(genconfig): AntigravityConfig — hooks.json fragment, no permissions key, reuses Plan 3's owned-entry merge"
```

---

### Task 6: `gen-config antigravity` in the CLI

**Files:**
- Modify: `cmd/guardrail/genconfig.go`
- Modify: `cmd/guardrail/genconfig_test.go`

**Interfaces:**
- `cmdGenConfig` plane check extended to accept `"antigravity"`; `--plugin-dir` stays opencode-only (unused for this plane); `frag = genconfig.AntigravityConfig(*binary)` (no `policy.LoadBase()` needed for this plane's fragment — but still call it, to keep the error-handling path uniform and because a future `--overlay` flag, Plan 7, will want a `*policy.Policy` in hand for all planes).

- [ ] **Step 1: Write the failing test**

Add to `cmd/guardrail/genconfig_test.go`:

```go
func TestGenConfigAntigravityPrint(t *testing.T) {
	var out, errb bytes.Buffer
	code := run([]string{"gen-config", "antigravity", "--print", "--binary", "/opt/guardrail"}, strings.NewReader(""), &out, &errb)
	if code != 0 {
		t.Fatalf("exit=%d stderr=%s", code, errb.String())
	}
	var frag map[string]any
	if err := json.Unmarshal(out.Bytes(), &frag); err != nil {
		t.Fatalf("stdout is not JSON: %v\n%s", err, out.String())
	}
	if _, ok := frag["hooks"]; !ok {
		t.Error("no hooks key")
	}
	if _, ok := frag["permissions"]; ok {
		t.Error("antigravity fragment should not have a permissions key")
	}
}

func TestGenConfigAntigravityMerge(t *testing.T) {
	p := filepath.Join(t.TempDir(), "hooks.json")
	var out, errb bytes.Buffer
	code := run([]string{"gen-config", "antigravity", "--merge", p, "--binary", "/opt/guardrail"}, strings.NewReader(""), &out, &errb)
	if code != 0 {
		t.Fatalf("exit=%d stderr=%s", code, errb.String())
	}
	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "guardrail-antigravity-pre") {
		t.Fatalf("merged file missing the owned pre-hook id:\n%s", raw)
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `/usr/local/go/bin/go test ./cmd/guardrail/ -run TestGenConfigAntigravity -v`
Expected: FAIL — `"antigravity"` is currently an unsupported plane.

- [ ] **Step 3: Write minimal implementation**

In `cmd/guardrail/genconfig.go`, extend the plane-validation line and the `switch plane` block:

```go
	if plane != "claude" && plane != "opencode" && plane != "antigravity" {
		fmt.Fprintf(stderr, "guardrail: gen-config: unsupported plane %q\n", plane)
		return 2
	}
```

```go
	case "antigravity":
		frag = genconfig.AntigravityConfig(*binary)
```

(add this `case` to the existing `switch plane { case "claude": ...; case "opencode": ...; }` block from Plan 5 Task 5, leaving those two arms untouched.)

- [ ] **Step 4: Run the tests to verify they pass**

Run: `/usr/local/go/bin/go test ./cmd/guardrail/ -v`
Expected: PASS. Full suite: `/usr/local/go/bin/go test ./... -v`.

- [ ] **Step 5: Commit**

```bash
gofmt -w cmd/guardrail/
git add cmd/guardrail/
git commit -m "feat(cli): gen-config antigravity --print/--merge"
```

---

### Task 7: contract fixtures + golden test

**Files:**
- Create: `test/fixtures/antigravity/run-command-rm-rf.json`, `test/fixtures/antigravity/run-command-ls.json`, `test/fixtures/antigravity/write-secret.json`
- Create: `test/fixtures/antigravity/expected.json`
- Modify: `test/contract_test.go`
- Modify: `test/genconfig_test.go`
- Create: `test/fixtures/antigravity/hooks-floor.golden.json`

**Interfaces:**
- Same shape as Plan 5's Task 6, but `expected.json` here checks a **stdout substring** (`"decision":"deny"` / `"decision":"allow"`) rather than exit code, since Antigravity's exit code is always 0. `TestAntigravityContractFixtures` therefore diverges slightly from the Claude/opencode loop — it is its own small test rather than reusing the generic `{"exit":N}` runner.

- [ ] **Step 1: Write the fixtures**

`test/fixtures/antigravity/run-command-rm-rf.json`:
```json
{"conversationId":"c1","toolCall":{"name":"run_command","args":{"CommandLine":"rm -rf /","Cwd":"/tmp"}}}
```

`test/fixtures/antigravity/run-command-ls.json`:
```json
{"conversationId":"c1","toolCall":{"name":"run_command","args":{"CommandLine":"ls -la","Cwd":"/tmp"}}}
```

`test/fixtures/antigravity/write-secret.json`:
```json
{"conversationId":"c1","toolCall":{"name":"write_to_file","args":{"AbsolutePath":"/tmp/.env"}}}
```

`test/fixtures/antigravity/expected.json`:
```json
{
  "run-command-rm-rf.json": {"decision": "deny"},
  "run-command-ls.json":    {"decision": "allow"},
  "write-secret.json":      {"decision": "deny"}
}
```

- [ ] **Step 2: Write the failing test**

Add to `test/contract_test.go`:

```go
func TestAntigravityContractFixtures(t *testing.T) {
	bin := buildBinary(t)
	raw, err := os.ReadFile("fixtures/antigravity/expected.json")
	if err != nil {
		t.Fatal(err)
	}
	var expected map[string]struct {
		Decision string `json:"decision"`
	}
	if err := json.Unmarshal(raw, &expected); err != nil {
		t.Fatal(err)
	}
	for name, want := range expected {
		t.Run(name, func(t *testing.T) {
			payload, err := os.ReadFile(filepath.Join("fixtures", "antigravity", name))
			if err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command(bin, "hook", "antigravity", "pre")
			cmd.Stdin = bytes.NewReader(payload)
			cmd.Env = append(os.Environ(), "XDG_STATE_HOME="+t.TempDir(), "GUARDRAIL_CONFIG=")
			out, _ := cmd.Output()
			if !bytes.Contains(out, []byte(`"decision":"`+want.Decision+`"`)) {
				t.Fatalf("%s: stdout %s, want decision %q", name, out, want.Decision)
			}
		})
	}
}
```

Add to `test/genconfig_test.go`:

```go
func TestGenConfigAntigravityGolden(t *testing.T) {
	bin := buildBinary(t)
	cmd := exec.Command(bin, "gen-config", "antigravity", "--print", "--binary", "/usr/local/bin/guardrail")
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		t.Fatalf("run: %v", err)
	}
	golden := "fixtures/antigravity/hooks-floor.golden.json"
	if *updateGolden {
		os.WriteFile(golden, out.Bytes(), 0o644)
		t.Logf("wrote %s", golden)
		return
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatalf("read golden (run with -update once): %v", err)
	}
	if !bytes.Equal(want, out.Bytes()) {
		t.Fatalf("gen-config antigravity output drift.\n--- got ---\n%s\n--- want ---\n%s", out.String(), want)
	}
}
```

- [ ] **Step 3: Generate the golden, then verify**

Run:
```bash
/usr/local/go/bin/go test ./test/ -run TestGenConfigAntigravityGolden -update
/usr/local/go/bin/go test ./test/ -v
```
Expected: golden written; full suite green.

- [ ] **Step 4: Commit**

```bash
git add test/
git commit -m "test: antigravity contract fixtures + gen-config antigravity golden"
```

---

### Task 8: ADR-0008 — Antigravity has no declarative floor; the hook is the entire boundary

**Files:**
- Create: `docs/adr/0008-antigravity-no-declarative-floor.md`

- [ ] **Step 1: Write the ADR**

```markdown
# Antigravity has no declarative permission floor — the hook is the entire boundary

Claude Code carries `permissions.deny/ask` and opencode carries
`permission.bash/read/edit` as a static, glob-based enforcement layer
independent of any hook — the "declarative floor" ADR-0001 relies on so
that a missing or crashed guardrail Engine still leaves *something*
blocking `rm -rf` and secret reads. Antigravity has no equivalent: its
`hooks.json` registration **is** the entire enforcement surface. There is
no separate static permission config to fall back to.

Decision: `AntigravityConfig`'s fragment carries only a `hooks` key, no
`permissions`-shaped key — there is nothing legitimate to put there. This
is accepted as an inherent per-plane limitation, not a design gap in this
project: ADR-0001's "degrade, don't brick" guarantee (Q14) is real for
Claude and opencode and is **not** available for Antigravity. If the
guardrail binary is missing, times out, or crashes when Antigravity calls
it, whatever Antigravity itself does on a failed hook call (documented
platform changelog history mentions timeouts and unrunnable-hook handling
maturing over 2026, but no declarative fallback) is the only remaining
boundary — likely fail-open, unverified.

## Consequences

- If Antigravity ever adds a declarative permission config of its own, add
  a floor-equivalent to `AntigravityConfig` then — there's nothing to build
  today.
- The install/update pipeline (Plan 6b or a future dotfiles-installer plan)
  should treat "guardrail binary present and correct version" as
  *more* load-bearing for Antigravity sessions than for Claude/opencode
  ones, precisely because there is no floor behind it.
```

- [ ] **Step 2: Commit**

```bash
git add docs/adr/0008-antigravity-no-declarative-floor.md
git commit -m "docs(adr): 0008 — Antigravity has no declarative floor, the hook is the whole boundary"
```

---

### Task 9: docs + tag `v0.7.0-dev` + self-review

**Files:**
- Modify: `README.md`
- Modify: `docs/HANDOFF-2026-09-03.md`

- [ ] **Step 1: `make check` + full suite**

Run: `make check && /usr/local/go/bin/go test ./...`
Expected: all green, vet clean, gofmt clean.

- [ ] **Step 2: README**

Update Status to mention the Antigravity adapter (`hook antigravity <pre|post>`, `gen-config antigravity`), and note the no-declarative-floor limitation (link ADR-0008). Update Layout to add `internal/genconfig/antigravity.go` and `internal/adapter/antigravity.go`.

- [ ] **Step 3: HANDOFF**

Mark the Antigravity adapter (formerly "Plan 6") done; record Task 1's actual findings (wrapper key or not, exact field names, timeouts) for future reference; note ADR-0008's limitation.

- [ ] **Step 4: Push and tag**

```bash
git add README.md docs/HANDOFF-2026-09-03.md
git commit -m "docs: Antigravity adapter done — hook antigravity, gen-config antigravity, ADR-0008"
git push origin main
git tag v0.7.0-dev
git push origin v0.7.0-dev
```

---

## Self-Review

**1. Spec coverage.**

| Item | Task |
|---|---|
| Payload/response shape verified against the live reference | 1 |
| `guardrail hook antigravity <phase>` sharing the full pipeline | 2, 3, 4 |
| Exit code carries no meaning; `post` always `{}` | 3 |
| `genconfig.AntigravityConfig` — hooks.json fragment, no permissions key | 5 |
| Owned-entry merge reused with zero merge.go changes (third plane, third proof) | 5 |
| `gen-config antigravity --print/--merge` | 6 |
| Contract + golden regression coverage | 7 |
| No-declarative-floor limitation recorded | 8 |

Deferred, confirmed out of scope: everything Plan 7 (recipes, `guardrail sync`) covers; a Codex adapter (explicitly the plane after this one, per DESIGN Q3, not started); project-level `.agents/hooks.json` generation specifically (this plan's `--merge` works for either path — global or project — since the target path is caller-supplied, but nothing here writes the accompanying `.agents/rules/guardrails.md`-style posture file takumi-dream also carries; that's takumi-dream's own overlay concern per Q1/Q6, not this project's).

**2. Placeholder scan.** No `TBD`/"handle appropriately". Task 1's uncertainty (wrapper key) is bounded and resolved before Task 5 writes real code, same discipline as Plans 4b and 5.

**3. Type consistency.**
- `adapter.ParseAntigravity(string, io.Reader) (engine.ToolCall, error)` / `EmitAntigravity(policy.Verdict, string, io.Writer) int` — Tasks 2–3; reuse `engine.ToolCall`/`policy.Verdict` and the existing unexported `repoRoot` helper unchanged.
- `cmdHook`'s three-plane dispatch (Task 4) — the shared pipeline block (base/overlay/merge/session-start/trifecta/evaluate/audit) is untouched from Plan 5; only the parse-dispatch and emit-dispatch switches grow a case each.
- `genconfig.AntigravityConfig(string) Fragment` (Task 5) — same `Fragment = map[string]any` alias as `ClaudeConfig`/`OpencodeConfig`; consumed by `cmdGenConfig`'s extended `switch plane` (Task 6) exactly like the other two.
- `test/contract_test.go`'s `buildBinary`/`goCmd` (Plan 3) reused unmodified.

---

## Execution Handoff

**Plan complete and saved to `docs/superpowers/plans/2026-09-04-antigravity-adapter.md`. Two execution options:**

**1. Subagent-Driven (recommended)** — fresh subagent per task via `superpowers:subagent-driven-development`, review between tasks.

**2. Inline Execution** — `superpowers:executing-plans`, batch with checkpoints.

**Which approach?**
