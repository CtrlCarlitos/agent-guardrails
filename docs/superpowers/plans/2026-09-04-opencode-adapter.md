# opencode Adapter — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** `guardrail hook opencode` — a second plane subcommand reusing the entire existing policy pipeline (Base+Overlay merge, `Evaluate`, the P7 trifecta heuristic, audit logging) — plus `guardrail gen-config opencode` emitting opencode's native `permission` block and deploying a thin JS plugin that delegates to the binary, matching ADR-0002's "one binary, thin idiomatic shims" design.

**Architecture:** The plugin and the binary speak a wire format **we define**, not opencode's internal `output.args` shape — the plugin normalizes opencode's real payload into `{session_id, event, tool, command, paths, cwd}` before calling `guardrail hook opencode`, exactly mirroring `internal/adapter/claude.go`'s shape. `cmd/guardrail/hook.go`'s `cmdHook` is refactored to dispatch parsing by plane, then shares one pipeline (merge → trifecta → `Evaluate` → audit → plane-specific emit). `genconfig.OpencodeConfig` reuses the *exact same* glob lists already built for the Claude floor (`bashDenyGlobs`, `secretDenyGlobs`, etc.) by stripping their `Bash(...)`/`Read(...)`/`Edit(...)` wrapper — no re-typed policy content, unlike the Claude floor's earlier necessary duplication. The plugin's JS source is embedded in the Go binary (`//go:embed`) and written out by `gen-config opencode --merge`, so there is exactly one copy of it to maintain.

**Tech Stack:** Go 1.23+, existing deps only. The plugin targets `@opencode-ai/plugin` (verified byte-identical between the installed 1.18.18 and the running binary's 1.18.27 — no version-skew risk for the `Hooks` interface this plan uses).

**Spec:** `../../../DESIGN.md` Q4, Q17, ADR-0002. Reference implementation already on this machine: `/home/carlitos/projects/CtrlCarlitos/takumi-dream/.opencode/plugins/takumi-guard.js` and `/home/carlitos/projects/CtrlCarlitos/takumi-dream/opencode.json` (both proven working — Task 1 verifies specifics against them before any code is written).

## Global Constraints

- **The plugin↔binary wire format is our own, not opencode's.** Do not attempt to make `guardrail hook opencode`'s stdin schema match opencode's internal `tool.execute.before` payload — the plugin's job is exactly to translate one into the other.
- **`ask` has no native plugin-level equivalent in opencode's `tool.execute.before`.** Per the confirmed `Hooks` interface, that hook can only `throw` (block) or return normally (allow) — there is no third outcome. Follow the proven takumi-guard.js pattern: an engine `ask` verdict also `throw`s, with a message telling the model to confirm with the user before retrying. opencode's *declarative* `permission.bash`/`edit`/`read` (which **do** support `ask` and DO prompt the user interactively — confirmed against takumi's live file, correcting the earlier "opencode carries no ask values" assumption) are the layer that delivers a real interactive ask; the plugin is defense-in-depth on top of that, same relationship P6 egress etc. already have with the Claude floor.
- **Reuse everything already built.** `engine.Evaluate`, `internal/session`, `engine.TrifectaVerdict`/`IsPrivateDataAccess`/`IsNetworkAttempt`, `audit.Write`, `policy.LoadBase`/`FindOverlayPath`/`LoadOverlay`/`Merge`/`SortedWaivers` — none of these are plane-specific and none change in this plan.
- **No `SessionStart`-equivalent for opencode in this plan.** opencode's `event` hook has no context-injection output (`(input) => Promise<void>`, no mutable `output`) — there is no clean analogue to Claude's `additionalContext`. P10-for-opencode is explicitly out of scope; note it as a parked gap, don't invent a workaround.
- Every code step is literal. `gofmt -w` before every commit. Conventional Commits, one commit per task.
- Verified current state relevant to this plan:
  - `cmd/guardrail/hook.go`'s `cmdHook` currently hardcodes `plane != "claude"` → unsupported, and the `audit.Record{Plane: "claude", ...}` field is a literal string, not `tc.Plane`.
  - `internal/genconfig/claude.go` exports (package-level, same package `genconfig`) `bashDenyGlobs() []string`, `bashAskGlobs() []string`, `secretDenyGlobs(pol) []string`, `selfConfigDenyGlobs() []string`, `ciInfraLockAskGlobs() []string`, `type Fragment = map[string]any`. All Claude-format (`"Bash(x)"`, `"Read(x)"`, `"Edit(x)"`).
  - `internal/genconfig/merge.go`'s `deepMerge`/`unionAppend`/`MergeInto` are plane-agnostic already — no changes needed for opencode's `permission` (nested maps → recurse) or `plugin` (array → union-append) shapes.
  - `internal/session`, `engine.TrifectaVerdict`, `IsPrivateDataAccess`, `IsNetworkAttempt` (Plan 4b) take a `ToolCall`/`*policy.Policy`/`*session.State` — nothing Claude-specific.
  - `adapters/opencode/PLACEHOLDER` is a stub from the original scaffold; this plan supersedes it with an embedded-JS approach and removes the stray file.

---

### Task 1: Verify field names and the plugin-registration mechanism against reality

**Files:** none (investigation only — findings feed Tasks 2–5's code).

- [ ] **Step 1: Read the full reference plugin**

Run: `cat -n /home/carlitos/projects/CtrlCarlitos/takumi-dream/.opencode/plugins/takumi-guard.js`

Confirm the exact field names read off `output.args` inside `"tool.execute.before"` for the bash case (expected: `args.command`) and the file-tool case (expected: `args.filePath`, possibly falling back to `args.path`). Note the exact names actually used — Task 3's plugin code must match them, not guess.

- [ ] **Step 2: Determine opencode's global-plugin resolution**

Run:
```bash
mkdir -p /tmp/guardrail-plugin-probe
cat > /tmp/guardrail-plugin-probe/probe.js <<'EOF'
export default async () => {
  console.error("GUARDRAIL_PLUGIN_PROBE_LOADED");
  return {};
};
EOF
mkdir -p /tmp/guardrail-oc-test && cd /tmp/guardrail-oc-test
cat > opencode.json <<EOF
{"\$schema":"https://opencode.ai/config.json","plugin":["/tmp/guardrail-plugin-probe/probe.js"]}
EOF
opencode run "echo hi" 2>&1 | grep -q GUARDRAIL_PLUGIN_PROBE_LOADED && echo "ABSOLUTE PATH IN plugin ARRAY: WORKS" || echo "ABSOLUTE PATH IN plugin ARRAY: DID NOT LOAD — investigate further (file:// prefix? project-relative? a dedicated global plugin dir?)"
```
Expected: `ABSOLUTE PATH IN plugin ARRAY: WORKS`. If it doesn't, try `"file:///tmp/guardrail-plugin-probe/probe.js"` as the array entry and re-test; if that also fails, check `opencode --help` / `opencode config --help` for a documented global plugin directory before falling back to any other mechanism. Record whichever form actually works — Task 5 depends on it.

- [ ] **Step 3: Clean up the probe**

Run: `rm -rf /tmp/guardrail-plugin-probe /tmp/guardrail-oc-test`

- [ ] **Step 4: No commit** (investigation only; findings carry into later tasks' commit messages if they deviate from this plan's assumptions).

---

### Task 2: `adapter.ParseOpencode` / `adapter.EmitOpencode`

**Files:**
- Create: `internal/adapter/opencode.go`
- Create: `internal/adapter/opencode_test.go`

**Interfaces:**
- Wire envelope (ours, sent by the plugin): `{"session_id":"...","event":"pre"|"post","tool":"bash"|"read"|"edit"|"write"|"list","command":"...","paths":["..."],"cwd":"..."}`.
- `func ParseOpencode(r io.Reader) (engine.ToolCall, error)` — decodes the envelope; `Event` defaults to `"pre"` for anything other than `"pre"`/`"post"`; `Tool` normalized via `normalizeOpencodeTool` to match the Claude-style capitalized names the Engine's rule modules already key off (`isFileTool`, `tc.IsBash()`, `pathReaders`) — `"bash"→"Bash"`, `"read"→"Read"`, `"edit"→"Edit"`, `"write"→"Write"`, `"list"→"List"`; `Plane: "opencode"`; `RepoRoot` via the existing unexported `repoRoot(cwd string) string` helper already in `internal/adapter/claude.go` (same package, reused as-is — no changes there).
- `func EmitOpencode(v policy.Verdict, stdout, stderr io.Writer) int` — writes `{"decision":"allow"|"ask"|"deny","reason":"..."}` + newline to `stdout` always; returns `2` when `v.Decision == policy.Deny`, else `0`.

- [ ] **Step 1: Write the failing test**

`internal/adapter/opencode_test.go`:

```go
package adapter

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
)

func TestParseOpencodeBash(t *testing.T) {
	raw := `{"session_id":"s1","event":"pre","tool":"bash","command":"rm -rf /","cwd":"/tmp"}`
	tc, err := ParseOpencode(strings.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	if tc.Plane != "opencode" || tc.Tool != "Bash" || tc.Command != "rm -rf /" || tc.Event != "pre" {
		t.Fatalf("bad ToolCall: %+v", tc)
	}
}

func TestParseOpencodeFileTool(t *testing.T) {
	raw := `{"session_id":"s1","event":"pre","tool":"read","paths":["/tmp/.env"],"cwd":"/tmp"}`
	tc, err := ParseOpencode(strings.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	if tc.Tool != "Read" || len(tc.Paths) != 1 || tc.Paths[0] != "/tmp/.env" {
		t.Fatalf("bad ToolCall: %+v", tc)
	}
}

func TestParseOpencodeUnknownEventDefaultsPre(t *testing.T) {
	tc, err := ParseOpencode(strings.NewReader(`{"session_id":"s1","tool":"bash","command":"ls"}`))
	if err != nil {
		t.Fatal(err)
	}
	if tc.Event != "pre" {
		t.Fatalf("Event = %q, want pre", tc.Event)
	}
}

func TestEmitOpencodeDeny(t *testing.T) {
	var out, errb bytes.Buffer
	code := EmitOpencode(policy.Verdict{Decision: policy.Deny, Reason: "no"}, &out, &errb)
	if code != 2 {
		t.Fatalf("code = %d, want 2", code)
	}
	var got map[string]string
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got["decision"] != "deny" || got["reason"] != "no" {
		t.Fatalf("bad payload: %v", got)
	}
}

func TestEmitOpencodeAllow(t *testing.T) {
	var out, errb bytes.Buffer
	code := EmitOpencode(policy.Verdict{Decision: policy.Allow}, &out, &errb)
	if code != 0 {
		t.Fatalf("code = %d, want 0", code)
	}
	var got map[string]string
	json.Unmarshal(out.Bytes(), &got)
	if got["decision"] != "allow" {
		t.Fatalf("decision = %q, want allow", got["decision"])
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `/usr/local/go/bin/go test ./internal/adapter/ -run 'TestParseOpencode|TestEmitOpencode' -v`
Expected: FAIL — undefined.

- [ ] **Step 3: Write minimal implementation**

`internal/adapter/opencode.go`:

```go
package adapter

import (
	"encoding/json"
	"io"
	"strings"

	"github.com/CtrlCarlitos/agent-guardrails/internal/engine"
	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
)

type opencodePayload struct {
	SessionID string   `json:"session_id"`
	Event     string   `json:"event"`
	Tool      string   `json:"tool"`
	Command   string   `json:"command"`
	Paths     []string `json:"paths"`
	CWD       string   `json:"cwd"`
}

func ParseOpencode(r io.Reader) (engine.ToolCall, error) {
	raw, err := io.ReadAll(r)
	if err != nil {
		return engine.ToolCall{}, err
	}
	var p opencodePayload
	if err := json.Unmarshal(raw, &p); err != nil {
		return engine.ToolCall{}, err
	}
	event := p.Event
	if event != "pre" && event != "post" {
		event = "pre"
	}
	tc := engine.ToolCall{
		Plane:     "opencode",
		Event:     event,
		Tool:      normalizeOpencodeTool(p.Tool),
		Command:   p.Command,
		Paths:     p.Paths,
		SessionID: p.SessionID,
		CWD:       p.CWD,
		Raw:       raw,
	}
	tc.RepoRoot = repoRoot(p.CWD)
	return tc, nil
}

func normalizeOpencodeTool(t string) string {
	switch strings.ToLower(t) {
	case "bash":
		return "Bash"
	case "read":
		return "Read"
	case "edit":
		return "Edit"
	case "write":
		return "Write"
	case "list":
		return "List"
	default:
		return t
	}
}

func EmitOpencode(v policy.Verdict, stdout, stderr io.Writer) int {
	payload := map[string]any{"decision": string(v.Decision), "reason": v.Reason}
	b, _ := json.Marshal(payload)
	stdout.Write(append(b, '\n'))
	if v.Decision == policy.Deny {
		return 2
	}
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
git commit -m "feat(adapter): ParseOpencode/EmitOpencode — our own wire envelope for the opencode plugin"
```

---

### Task 3: Wire `guardrail hook opencode` into `cmdHook`

**Files:**
- Modify: `cmd/guardrail/hook.go`
- Modify: `cmd/guardrail/hook_test.go`

**Interfaces:**
- `cmdHook` restructured: `args[0]` selects the plane; parsing branches to `adapter.ParseClaude`/`adapter.ParseOpencode`; everything from `policy.LoadBase()` through the trifecta block through `engine.Evaluate` through `audit.Write` is **unchanged, shared code**; the final emit branches to `adapter.EmitClaude`/`adapter.EmitOpencode`. `audit.Record.Plane` changes from the literal `"claude"` to `tc.Plane` (now correct for both planes). The `session-start`-only branch (Task 8 of Plan 4b) stays exactly where it is — `tc.Event` is never `"session-start"` for an opencode-parsed call, so it simply never triggers there.

- [ ] **Step 1: Write the failing test**

Add to `cmd/guardrail/hook_test.go`:

```go
func TestHookOpencodeDeny(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	t.Setenv("GUARDRAIL_CONFIG", "")
	payload := `{"session_id":"s1","event":"pre","tool":"bash","command":"rm -rf /","cwd":"/tmp"}`
	var out, errb bytes.Buffer
	code := run([]string{"hook", "opencode"}, strings.NewReader(payload), &out, &errb)
	if code != 2 {
		t.Fatalf("exit=%d, want 2; stdout=%s stderr=%s", code, out.String(), errb.String())
	}
	if !strings.Contains(out.String(), `"decision":"deny"`) {
		t.Fatalf("stdout = %s, want a deny decision", out.String())
	}
}

func TestHookOpencodeAllow(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	t.Setenv("GUARDRAIL_CONFIG", "")
	payload := `{"session_id":"s1","event":"pre","tool":"bash","command":"ls -la","cwd":"/tmp"}`
	var out, errb bytes.Buffer
	code := run([]string{"hook", "opencode"}, strings.NewReader(payload), &out, &errb)
	if code != 0 {
		t.Fatalf("exit=%d, want 0", code)
	}
}

func TestHookOpencodeAuditRecordsCorrectPlane(t *testing.T) {
	state := t.TempDir()
	t.Setenv("XDG_STATE_HOME", state)
	t.Setenv("GUARDRAIL_CONFIG", "")
	payload := `{"session_id":"s1","event":"pre","tool":"bash","command":"rm -rf /","cwd":"/tmp"}`
	var out, errb bytes.Buffer
	run([]string{"hook", "opencode"}, strings.NewReader(payload), &out, &errb)
	raw, err := os.ReadFile(filepath.Join(state, "guardrail", "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"plane":"opencode"`) {
		t.Fatalf("audit record should say plane opencode, got: %s", raw)
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `/usr/local/go/bin/go test ./cmd/guardrail/ -run TestHookOpencode -v`
Expected: FAIL — `opencode` is currently "unsupported plane".

- [ ] **Step 3: Write minimal implementation**

Replace `cmdHook` in `cmd/guardrail/hook.go`:

```go
func cmdHook(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "guardrail: hook needs a plane (claude, opencode)")
		return 2
	}
	plane := args[0]

	var tc engine.ToolCall
	var err error
	switch plane {
	case "claude":
		tc, err = adapter.ParseClaude(stdin)
	case "opencode":
		tc, err = adapter.ParseOpencode(stdin)
	default:
		fmt.Fprintf(stderr, "guardrail: unsupported plane %q\n", plane)
		return 2
	}
	if err != nil {
		fmt.Fprintf(stderr, "guardrail: unparseable hook payload (%v); failing closed\n", err)
		return 2
	}

	base, err := policy.LoadBase()
	if err != nil {
		fmt.Fprintf(stderr, "guardrail: cannot load base policy (%v); failing closed\n", err)
		return 2
	}

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

	merged, warnings, err := policy.Merge(base, ov, version)
	if err != nil {
		fmt.Fprintf(stderr, "guardrail: invalid overlay (%v); failing closed\n", err)
		return 2
	}
	for _, w := range warnings {
		fmt.Fprintln(stderr, w)
	}

	if tc.Event == "session-start" {
		text := adapter.PostureText(policy.SortedWaivers(merged), warnings)
		return adapter.EmitClaudeSessionStart(text, stdout)
	}

	v := engine.Evaluate(tc, merged)

	if tc.Event == "pre" && tc.SessionID != "" && !merged.Waived["P7.trifecta"] {
		st, loadErr := session.Load(tc.SessionID)
		if loadErr != nil {
			fmt.Fprintf(stderr, "guardrail: session state read failed (%v)\n", loadErr)
		}
		isPrivate := engine.IsPrivateDataAccess(tc, merged)
		isNet := engine.IsNetworkAttempt(tc)
		if esc := engine.TrifectaVerdict(v, isPrivate, isNet, st); esc != nil {
			v = *esc
		}
		st.SawPrivateRead = st.SawPrivateRead || isPrivate
		st.SawNetworkCall = st.SawNetworkCall || isNet
		if err := session.Save(tc.SessionID, st); err != nil {
			fmt.Fprintf(stderr, "guardrail: session state write failed (%v)\n", err)
		}
	}

	rec := audit.Record{
		SessionID: tc.SessionID,
		Plane:     tc.Plane,
		Tool:      tc.Tool,
		Event:     tc.Event,
		Command:   tc.Command,
		Paths:     tc.Paths,
		Decision:  string(v.Decision),
		RuleID:    v.RuleID,
		Reason:    v.Reason,
		Waivers:   policy.SortedWaivers(merged),
	}
	if err := audit.Write(rec, audit.DefaultPath(merged.Slots.AuditLog)); err != nil {
		fmt.Fprintf(stderr, "guardrail: audit write failed (%v)\n", err)
	}

	switch plane {
	case "claude":
		return adapter.EmitClaude(v, tc.Event, stdout, stderr)
	case "opencode":
		return adapter.EmitOpencode(v, stdout, stderr)
	default:
		return 2
	}
}
```

(This assumes the `waivedList` helper was already removed in favor of `policy.SortedWaivers` per Plan 3 Task 6 — if the on-disk file still has a local `waivedList` function, delete it as part of this task's diff; its call site is replaced above.)

- [ ] **Step 4: Run the tests to verify they pass**

Run: `/usr/local/go/bin/go test ./cmd/guardrail/ -v`
Expected: PASS. Run the full suite: `/usr/local/go/bin/go test ./... -v` — confirm the Claude and trifecta/session-start tests from Plans 1–4b are all still green (they exercise the exact same shared code path this task restructured).

- [ ] **Step 5: Commit**

```bash
gofmt -w cmd/guardrail/
git add cmd/guardrail/
git commit -m "feat(cli): guardrail hook opencode — shares the full policy pipeline with claude"
```

---

### Task 4: `genconfig.OpencodeConfig` — reuse the Claude floor's glob lists via wrapper-stripping

**Files:**
- Create: `internal/genconfig/opencode.go`
- Create: `internal/genconfig/opencode_test.go`

**Interfaces:**
- `func stripWrapper(prefix, s string) (string, bool)` — `s` must start with `prefix` and end with `)`; returns the inner pattern.
- `func OpencodeConfig(pol *policy.Policy, pluginPath string) Fragment` — builds `permission.bash` (starts `{"*":"allow"}`, then every `bashDenyGlobs()`/`bashAskGlobs()` entry stripped of its `Bash(...)` wrapper mapped to `"deny"`/`"ask"`), `permission.read`/`permission.edit` (from `secretDenyGlobs(pol)` stripped of `Read(...)`/`Edit(...)`, plus `pol.Slots.SecretAllow` entries mapped to `"allow"` in both, plus `selfConfigDenyGlobs()` stripped of `Edit(...)` mapped to `"deny"`, plus `ciInfraLockAskGlobs()` stripped of `Edit(...)` mapped to `"ask"`), and `"plugin": []string{pluginPath}`.

- [ ] **Step 1: Write the failing test**

`internal/genconfig/opencode_test.go`:

```go
package genconfig

import "testing"

func TestOpencodeConfigBashPermissions(t *testing.T) {
	frag := OpencodeConfig(secretPol(), "/x/guardrail.js")
	bash := frag["permission"].(map[string]any)["bash"].(map[string]string)
	if bash["*"] != "allow" {
		t.Errorf(`bash["*"] = %q, want "allow"`, bash["*"])
	}
	if bash["rm -rf *"] != "deny" {
		t.Errorf(`bash["rm -rf *"] = %q, want "deny"`, bash["rm -rf *"])
	}
	if bash["chmod -R *"] != "ask" {
		t.Errorf(`bash["chmod -R *"] = %q, want "ask"`, bash["chmod -R *"])
	}
}

func TestOpencodeConfigReadEditPermissions(t *testing.T) {
	frag := OpencodeConfig(secretPol(), "/x/guardrail.js")
	read := frag["permission"].(map[string]any)["read"].(map[string]string)
	edit := frag["permission"].(map[string]any)["edit"].(map[string]string)
	if read["**/.ssh/**"] != "deny" {
		t.Errorf(`read["**/.ssh/**"] = %q`, read["**/.ssh/**"])
	}
	if read["**/.env.example"] != "allow" {
		t.Errorf(`read["**/.env.example"] = %q, want allow`, read["**/.env.example"])
	}
	if edit[".claude/**"] != "deny" {
		t.Errorf(`edit[".claude/**"] = %q, want deny`, edit[".claude/**"])
	}
	if edit[".github/workflows/**"] != "ask" {
		t.Errorf(`edit[".github/workflows/**"] = %q, want ask`, edit[".github/workflows/**"])
	}
}

func TestOpencodeConfigPluginRegistered(t *testing.T) {
	frag := OpencodeConfig(secretPol(), "/x/guardrail.js")
	plugins := frag["plugin"].([]string)
	if len(plugins) != 1 || plugins[0] != "/x/guardrail.js" {
		t.Errorf("plugin = %v", plugins)
	}
}
```

(`secretPol()` is the existing helper from `internal/genconfig/claude_test.go`, same package — reused as-is.)

- [ ] **Step 2: Run the test to verify it fails**

Run: `/usr/local/go/bin/go test ./internal/genconfig/ -run TestOpencodeConfig -v`
Expected: FAIL — `OpencodeConfig` undefined.

- [ ] **Step 3: Write minimal implementation**

`internal/genconfig/opencode.go`:

```go
package genconfig

import (
	"strings"

	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
)

func stripWrapper(prefix, s string) (string, bool) {
	if !strings.HasPrefix(s, prefix) || !strings.HasSuffix(s, ")") {
		return "", false
	}
	return s[len(prefix) : len(s)-1], true
}

func OpencodeConfig(pol *policy.Policy, pluginPath string) Fragment {
	bash := map[string]string{"*": "allow"}
	for _, g := range bashDenyGlobs() {
		if p, ok := stripWrapper("Bash(", g); ok {
			bash[p] = "deny"
		}
	}
	for _, g := range bashAskGlobs() {
		if p, ok := stripWrapper("Bash(", g); ok {
			bash[p] = "ask"
		}
	}

	read := map[string]string{}
	edit := map[string]string{}
	for _, g := range secretDenyGlobs(pol) {
		if p, ok := stripWrapper("Read(", g); ok {
			read[p] = "deny"
		}
		if p, ok := stripWrapper("Edit(", g); ok {
			edit[p] = "deny"
		}
	}
	for _, a := range pol.Slots.SecretAllow {
		read[a] = "allow"
		edit[a] = "allow"
	}
	for _, g := range selfConfigDenyGlobs() {
		if p, ok := stripWrapper("Edit(", g); ok {
			edit[p] = "deny"
		}
	}
	for _, g := range ciInfraLockAskGlobs() {
		if p, ok := stripWrapper("Edit(", g); ok {
			edit[p] = "ask"
		}
	}

	return Fragment{
		"permission": map[string]any{
			"bash": bash,
			"read": read,
			"edit": edit,
		},
		"plugin": []string{pluginPath},
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
git commit -m "feat(genconfig): OpencodeConfig — derives permission.{bash,read,edit} from the same glob lists as the Claude floor"
```

---

### Task 5: Embed the plugin JS; `gen-config opencode --merge` deploys it

**Files:**
- Create: `internal/genconfig/opencode_plugin.js`
- Create: `internal/genconfig/opencode_embed.go`
- Modify: `cmd/guardrail/genconfig.go`
- Modify: `cmd/guardrail/genconfig_test.go`
- Remove: `adapters/opencode/PLACEHOLDER` (superseded — the canonical source now lives in `internal/genconfig/opencode_plugin.js`, embedded and deployed by the binary itself)

**Interfaces:**
- `internal/genconfig/opencode_plugin.js` — the plugin, using **the field names Task 1 Step 1 confirmed** (fall back to the plan's `args.filePath || args.path` guess only if Task 1 found no better answer, and note that explicitly in the commit message).
- `//go:embed opencode_plugin.js` → `var OpencodePluginJS []byte` (exported — `cmd/guardrail` needs to write it out).
- `cmdGenConfig` gains an `opencode` plane branch alongside `claude`: flags `--print`/`--merge <opencode.json path>`/`--binary <guardrail path>` (existing) plus a new `--plugin-dir <dir>` (default: the directory containing `--merge`'s path, or `.` if `--print`). On `--merge`: writes `internal/genconfig.OpencodePluginJS` to `<plugin-dir>/guardrail.js` (`0644`, `os.MkdirAll` first), builds `genconfig.OpencodeConfig(base, <absolute path to that file>)`, and `genconfig.MergeInto`s it into the target `opencode.json` — identical shape to the `claude` branch's flow.

- [ ] **Step 1: Write the plugin source**

`internal/genconfig/opencode_plugin.js` — use the field names from Task 1's findings. Starting point (adjust per Task 1):

```js
// The thin opencode plugin that delegates all policy logic to the guardrail
// binary. See ../../DESIGN.md "Planes & adapters" and docs/adr/0007.
// This file is embedded in the guardrail binary (opencode_embed.go) and
// written out by `guardrail gen-config opencode --merge` — it is not meant
// to be hand-edited in place; edit this source and rebuild instead.
import { spawnSync } from "node:child_process";

const GUARDRAIL_BIN = process.env.GUARDRAIL_BIN || "guardrail";

function callGuardrail(envelope) {
	const res = spawnSync(GUARDRAIL_BIN, ["hook", "opencode"], {
		input: JSON.stringify(envelope),
		encoding: "utf8",
		timeout: 15000,
	});
	if (res.error) {
		throw new Error(`guardrail: could not run (${res.error.message}); failing closed`);
	}
	if (res.signal) {
		throw new Error(`guardrail: killed by signal ${res.signal}; failing closed`);
	}
	let decision;
	try {
		decision = JSON.parse(res.stdout || "{}");
	} catch {
		throw new Error(`guardrail: unparseable response; failing closed. stderr: ${res.stderr}`);
	}
	if (decision.decision === "deny") {
		throw new Error(`guardrail: ${decision.reason}`);
	}
	if (decision.decision === "ask") {
		throw new Error(
			`guardrail: needs confirmation - ${decision.reason}. Ask the user directly, then retry if they approve.`
		);
	}
}

export const GuardrailPlugin = async ({ directory }) => {
	return {
		"tool.execute.before": async (input, output) => {
			const tool = input.tool;
			const args = output.args || {};
			const envelope = { session_id: input.sessionID, event: "pre", tool, cwd: directory };
			if (tool === "bash") {
				envelope.command = args.command;
			} else {
				const p = args.filePath || args.path;
				if (p) envelope.paths = [p];
			}
			callGuardrail(envelope);
		},
	};
};

export default GuardrailPlugin;
```

- [ ] **Step 2: Embed it**

`internal/genconfig/opencode_embed.go`:

```go
package genconfig

import _ "embed"

//go:embed opencode_plugin.js
var OpencodePluginJS []byte
```

- [ ] **Step 3: Write the failing test**

Add to `cmd/guardrail/genconfig_test.go`:

```go
func TestGenConfigOpencodeMergeDeploysPlugin(t *testing.T) {
	dir := t.TempDir()
	settingsPath := filepath.Join(dir, "opencode.json")
	os.WriteFile(settingsPath, []byte(`{"plugin":["superpowers@git+https://github.com/obra/superpowers.git"]}`), 0o644)

	var out, errb bytes.Buffer
	code := run([]string{"gen-config", "opencode", "--merge", settingsPath, "--binary", "/opt/guardrail"}, strings.NewReader(""), &out, &errb)
	if code != 0 {
		t.Fatalf("exit=%d stderr=%s", code, errb.String())
	}

	pluginPath := filepath.Join(dir, "guardrail.js")
	if _, err := os.Stat(pluginPath); err != nil {
		t.Fatalf("plugin file not written: %v", err)
	}
	js, _ := os.ReadFile(pluginPath)
	if !strings.Contains(string(js), "tool.execute.before") {
		t.Fatalf("deployed plugin looks wrong:\n%s", js)
	}

	raw, _ := os.ReadFile(settingsPath)
	var m map[string]any
	json.Unmarshal(raw, &m)
	plugins := m["plugin"].([]any)
	foundSuperpowers, foundGuardrail := false, false
	for _, p := range plugins {
		s := p.(string)
		if strings.Contains(s, "superpowers") {
			foundSuperpowers = true
		}
		if s == pluginPath {
			foundGuardrail = true
		}
	}
	if !foundSuperpowers {
		t.Error("existing superpowers plugin entry was lost")
	}
	if !foundGuardrail {
		t.Errorf("guardrail plugin path %q not registered; plugin array = %v", pluginPath, plugins)
	}

	perm := m["permission"].(map[string]any)
	if _, ok := perm["bash"]; !ok {
		t.Error("permission.bash missing")
	}
}
```

- [ ] **Step 4: Run the test to verify it fails**

Run: `/usr/local/go/bin/go test ./cmd/guardrail/ -run TestGenConfigOpencodeMergeDeploysPlugin -v`
Expected: FAIL — `opencode` plane not yet handled by `cmdGenConfig`.

- [ ] **Step 5: Write minimal implementation**

In `cmd/guardrail/genconfig.go`, generalize `cmdGenConfig` to accept both planes. Replace the plane-check and the flag/body section:

```go
func cmdGenConfig(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "guardrail: gen-config needs a plane (claude, opencode)")
		return 2
	}
	plane := args[0]
	if plane != "claude" && plane != "opencode" {
		fmt.Fprintf(stderr, "guardrail: gen-config: unsupported plane %q\n", plane)
		return 2
	}

	fs := flag.NewFlagSet("gen-config", flag.ContinueOnError)
	fs.SetOutput(stderr)
	doPrint := fs.Bool("print", true, "write the config fragment to stdout")
	mergePath := fs.String("merge", "", "merge the fragment into this settings file in place")
	binary := fs.String("binary", "guardrail", "path to the guardrail binary to register in the hook command")
	pluginDir := fs.String("plugin-dir", "", "(opencode only) directory to write guardrail.js into; default: alongside --merge's file")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	base, err := policy.LoadBase()
	if err != nil {
		fmt.Fprintf(stderr, "guardrail: cannot load base policy: %v\n", err)
		return 2
	}

	var frag genconfig.Fragment
	switch plane {
	case "claude":
		frag = genconfig.ClaudeConfig(base, *binary)
	case "opencode":
		dir := *pluginDir
		if dir == "" {
			if *mergePath != "" {
				dir = filepath.Dir(*mergePath)
			} else {
				dir = "."
			}
		}
		pluginPath := filepath.Join(dir, "guardrail.js")
		if *mergePath != "" {
			if err := os.MkdirAll(dir, 0o755); err != nil {
				fmt.Fprintf(stderr, "guardrail: cannot create plugin dir: %v\n", err)
				return 2
			}
			if err := os.WriteFile(pluginPath, genconfig.OpencodePluginJS, 0o644); err != nil {
				fmt.Fprintf(stderr, "guardrail: cannot write plugin file: %v\n", err)
				return 2
			}
			abs, err := filepath.Abs(pluginPath)
			if err == nil {
				pluginPath = abs
			}
		}
		frag = genconfig.OpencodeConfig(base, pluginPath)
	}

	if *mergePath != "" {
		if err := genconfig.MergeInto(*mergePath, frag); err != nil {
			fmt.Fprintf(stderr, "guardrail: merge failed: %v\n", err)
			return 2
		}
		fmt.Fprintf(stderr, "guardrail: merged %s config into %s\n", plane, *mergePath)
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
}
```

Add `"os"` and `"path/filepath"` to the file's imports if not already present.

- [ ] **Step 6: Remove the stale placeholder**

```bash
rm -f adapters/opencode/PLACEHOLDER
rmdir adapters/opencode adapters 2>/dev/null || true
```

- [ ] **Step 7: Run the tests to verify they pass**

Run: `/usr/local/go/bin/go test ./... -v`
Expected: PASS across every package, including Plan 2's existing Claude `--merge` tests (the `claude` branch's behavior is unchanged) and the new opencode test.

- [ ] **Step 8: Commit**

```bash
gofmt -w internal/genconfig/ cmd/guardrail/
git add internal/genconfig/ cmd/guardrail/
git rm -r --cached adapters 2>/dev/null || true
git add -A adapters 2>/dev/null || true
git commit -m "feat(cli): gen-config opencode --merge deploys the embedded plugin + permission block; remove the stale adapters/opencode/ placeholder"
```

---

### Task 6: opencode contract fixtures + golden test

**Files:**
- Create: `test/fixtures/opencode/bash-rm-rf.json`, `test/fixtures/opencode/bash-ls.json`, `test/fixtures/opencode/read-env.json`
- Create: `test/fixtures/opencode/expected.json`
- Modify: `test/contract_test.go` (generalize the fixture loop to run per plane, or add a parallel opencode loop)
- Modify: `test/genconfig_test.go` (add an opencode golden test)
- Create: `test/fixtures/opencode/settings-floor.golden.json`

**Interfaces:**
- `test/fixtures/opencode/expected.json` — same `{"exit": N}` shape as the Claude one, using our own envelope's `event`/`tool`/`command`/`paths` fields.
- `TestOpencodeContractFixtures` — same pattern as `TestClaudeContractFixtures`, driving `guardrail hook opencode` instead.
- `TestGenConfigOpencodeGolden` — same pattern as the Claude golden test, driving `guardrail gen-config opencode --print --binary /usr/local/bin/guardrail --plugin-dir /usr/local/lib/guardrail` (note: `--print` mode does **not** write the plugin file per Task 5's flow, so the golden output covers `permission`+`plugin` only, with a fixed plugin path for reproducibility).

- [ ] **Step 1: Write the fixtures**

`test/fixtures/opencode/bash-rm-rf.json`:
```json
{"session_id":"s1","event":"pre","tool":"bash","command":"rm -rf /","cwd":"/tmp"}
```

`test/fixtures/opencode/bash-ls.json`:
```json
{"session_id":"s1","event":"pre","tool":"bash","command":"ls -la","cwd":"/tmp"}
```

`test/fixtures/opencode/read-env.json`:
```json
{"session_id":"s1","event":"pre","tool":"read","paths":["/home/u/proj/.env"],"cwd":"/tmp"}
```

`test/fixtures/opencode/expected.json`:
```json
{
  "bash-rm-rf.json": {"exit": 2},
  "bash-ls.json":    {"exit": 0},
  "read-env.json":   {"exit": 2}
}
```

- [ ] **Step 2: Write the failing test**

Add to `test/contract_test.go`:

```go
func TestOpencodeContractFixtures(t *testing.T) {
	bin := buildBinary(t)
	raw, err := os.ReadFile("fixtures/opencode/expected.json")
	if err != nil {
		t.Fatal(err)
	}
	var expected map[string]struct {
		Exit int `json:"exit"`
	}
	if err := json.Unmarshal(raw, &expected); err != nil {
		t.Fatal(err)
	}
	for name, want := range expected {
		t.Run(name, func(t *testing.T) {
			payload, err := os.ReadFile(filepath.Join("fixtures", "opencode", name))
			if err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command(bin, "hook", "opencode")
			cmd.Stdin = bytes.NewReader(payload)
			cmd.Env = append(os.Environ(), "XDG_STATE_HOME="+t.TempDir(), "GUARDRAIL_CONFIG=")
			_ = cmd.Run()
			if got := cmd.ProcessState.ExitCode(); got != want.Exit {
				t.Fatalf("%s: exit %d, want %d", name, got, want.Exit)
			}
		})
	}
}
```

Add to `test/genconfig_test.go`:

```go
func TestGenConfigOpencodeGolden(t *testing.T) {
	bin := buildBinary(t)
	cmd := exec.Command(bin, "gen-config", "opencode", "--print", "--binary", "/usr/local/bin/guardrail", "--plugin-dir", "/usr/local/lib/guardrail")
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		t.Fatalf("run: %v", err)
	}
	golden := "fixtures/opencode/settings-floor.golden.json"
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
		t.Fatalf("gen-config opencode output drift.\n--- got ---\n%s\n--- want ---\n%s", out.String(), want)
	}
}
```

- [ ] **Step 3: Generate the golden, then verify**

Run:
```bash
/usr/local/go/bin/go test ./test/ -run TestGenConfigOpencodeGolden -update
/usr/local/go/bin/go test ./test/ -v
```
Expected: golden written (spot-check: `permission.bash["*"] == "allow"`, `permission.bash["rm -rf *"] == "deny"`, `plugin == ["/usr/local/lib/guardrail/guardrail.js"]`); full suite green including the new contract + golden tests.

- [ ] **Step 4: Commit**

```bash
git add test/
git commit -m "test: opencode contract fixtures + gen-config opencode golden"
```

---

### Task 7: merge-preserves-existing-config regression test

**Files:**
- Modify: `internal/genconfig/opencode_test.go`

**Interfaces:**
- A test that seeds a takumi-shaped `opencode.json` (catch-all `"*":"allow"` in `permission.bash`, an existing `superpowers@...` plugin entry, an `external_directory` block) and confirms `MergeInto` with `OpencodeConfig`'s fragment preserves all of it while adding guardrail's entries.

- [ ] **Step 1: Write the failing test**

Add to `internal/genconfig/opencode_test.go`:

```go
func TestMergeOpencodePreservesExistingProjectConfig(t *testing.T) {
	p := filepath.Join(t.TempDir(), "opencode.json")
	os.WriteFile(p, []byte(`{
		"plugin": ["superpowers@git+https://github.com/obra/superpowers.git"],
		"permission": {
			"bash": {"*": "allow", "git commit *": "ask"},
			"external_directory": {"~/projects/**": "allow"}
		}
	}`), 0o644)

	frag := OpencodeConfig(secretPol(), "/x/guardrail.js")
	if err := MergeInto(p, frag); err != nil {
		t.Fatal(err)
	}

	raw, _ := os.ReadFile(p)
	var m map[string]any
	json.Unmarshal(raw, &m)
	perm := m["permission"].(map[string]any)

	bash := perm["bash"].(map[string]any)
	if bash["git commit *"] != "ask" {
		t.Errorf("existing project rule lost: %v", bash["git commit *"])
	}
	if bash["rm -rf *"] != "deny" {
		t.Errorf("guardrail rule not added: %v", bash["rm -rf *"])
	}
	if _, ok := perm["external_directory"]; !ok {
		t.Error("external_directory block lost")
	}

	plugins := m["plugin"].([]any)
	if len(plugins) != 2 {
		t.Fatalf("want superpowers + guardrail = 2 plugin entries, got %v", plugins)
	}
}
```

(Add `"encoding/json"`, `"os"`, `"path/filepath"` to the test file's imports if not already present.)

- [ ] **Step 2: Run the test to verify it fails or passes**

Run: `/usr/local/go/bin/go test ./internal/genconfig/ -run TestMergeOpencodePreservesExistingProjectConfig -v`
Expected: this should PASS immediately given Plan 2/3's already-generic `deepMerge` — this task is a **regression lock**, not new behavior. If it fails, `deepMerge`'s object-recursion has a real gap; fix `deepMerge`, not the test.

- [ ] **Step 3: Commit**

```bash
git add internal/genconfig/
git commit -m "test: lock that merging OpencodeConfig preserves an existing project's permission/plugin config"
```

---

### Task 8: ADR-0007 — opencode's wire format and ask-via-throw

**Files:**
- Create: `docs/adr/0007-opencode-wire-format-and-ask-via-throw.md`

- [ ] **Step 1: Write the ADR**

```markdown
# opencode: our own plugin↔binary wire format; ask delivered as a throw

opencode's `tool.execute.before` hook has exactly two outcomes: return
normally (allow) or throw (block) — there is no third "ask" outcome at the
plugin level (confirmed against the installed `@opencode-ai/plugin` types,
identical across the installed 1.18.18 and the running 1.18.27 binary).
Real interactive asks are delivered by opencode's own declarative
`permission.bash`/`edit`/`read` config, confirmed against a live, working
example (`takumi-dream/opencode.json`) to genuinely support `"ask"` values
that prompt the user — correcting an earlier, wrong assumption in this
project's design research that opencode "carries no ask values" for
headless-hang reasons.

Two decisions:

1. **The plugin↔binary payload is a format we define**, not a transcription
   of opencode's internal `tool.execute.before` `input`/`output` shape. The
   plugin normalizes opencode's real payload into
   `{session_id, event, tool, command, paths, cwd}` — the same shape family
   as the Claude adapter — before calling `guardrail hook opencode`. This
   decouples the Go side from opencode's internal types entirely; only the
   ~30-line plugin needs to track them.
2. **An engine `ask` verdict also throws** from the plugin, with a message
   telling the model to confirm with the user before retrying — the exact
   pattern already proven in `takumi-guard.js`. The plugin is defense-in-depth
   on top of the declarative `permission` floor (generated by
   `OpencodeConfig`), which is where a genuine interactive prompt happens;
   the plugin's job is to catch what the static floor's globs miss.

## Consequences

- A future plane with a genuine plugin-level "ask" primitive should use it
  directly rather than following this throw-based pattern — this is
  opencode's specific constraint, not a general adapter rule.
- No `SessionStart`-equivalent posture delivery exists for opencode in this
  plan — `event` hooks have no context-injection output. Parked, not solved.
```

- [ ] **Step 2: Commit**

```bash
git add docs/adr/0007-opencode-wire-format-and-ask-via-throw.md
git commit -m "docs(adr): 0007 — opencode wire format is ours; ask delivered as a throw"
```

---

### Task 9: docs + tag `v0.6.0-dev` + self-review

**Files:**
- Modify: `README.md`
- Modify: `docs/HANDOFF-2026-09-03.md`

- [ ] **Step 1: `make check` + full suite**

Run: `make check && /usr/local/go/bin/go test ./...`
Expected: all green, vet clean, gofmt clean.

- [ ] **Step 2: README**

Update Status to mention the opencode adapter (`hook opencode`, `gen-config opencode` deploying the embedded plugin), and update the Layout block: remove the `adapters/opencode/` line (superseded), add a line for `internal/genconfig/opencode_plugin.js` (embedded plugin source) and `internal/genconfig/opencode.go`.

- [ ] **Step 3: HANDOFF**

Mark the opencode adapter (formerly "Plan 5") done; note the parked P10-for-opencode gap and Task 1's empirical findings (field names, plugin-registration mechanism) for future reference.

- [ ] **Step 4: Push and tag**

```bash
git add README.md docs/HANDOFF-2026-09-03.md
git commit -m "docs: opencode adapter done — hook opencode, gen-config opencode, embedded plugin"
git push origin main
git tag v0.6.0-dev
git push origin v0.6.0-dev
```

---

## Self-Review

**1. Spec coverage.**

| Item | Task |
|---|---|
| `guardrail hook opencode` reusing the full shared pipeline | 2, 3 |
| Plane-agnostic reuse proven (audit `Plane` field, trifecta, waivers) | 3 |
| `genconfig.OpencodeConfig` — permission.bash/read/edit from existing glob lists, no re-typed policy | 4 |
| Plugin deployed by the binary (embedded, single source) | 5 |
| ask → throw (proven pattern), deny → throw, allow → passthrough | plugin source (Task 5), ADR-0007 (Task 8) |
| Contract + golden regression coverage | 6 |
| Merge preserves an existing project's own config | 7 |
| Design rationale recorded | 8 |

Deferred, confirmed out of scope: P10-equivalent posture/waiver delivery for opencode (no context-injection mechanism exists); `tool.execute.after`-driven P8 format/lint hooks (that's Plan 7's recipes work generally, not opencode-specific); opencode's exact permission-matching precedence rule (last-match-wins vs. most-specific — genuinely unconfirmed from any file on this machine; `OpencodeConfig`'s ordering mirrors takumi's proven-working structure rather than depending on knowing the rule).

**2. Placeholder scan.** No `TBD`/"handle appropriately". Task 1 is an explicit, bounded verification step whose findings gate Task 5's plugin source and Task 5's registration mechanism — this is the same discipline Plan 4b used for the SessionStart shape, not an open-ended placeholder.

**3. Type consistency.**
- `adapter.ParseOpencode(io.Reader) (engine.ToolCall, error)` / `EmitOpencode(policy.Verdict, io.Writer, io.Writer) int` — Task 2; both reuse `engine.ToolCall`/`policy.Verdict` unchanged.
- `cmdHook`'s restructure (Task 3) preserves every existing call signature it uses (`policy.LoadBase`, `FindOverlayPath`, `LoadOverlay`, `Merge`, `engine.Evaluate`, `session.Load/Save`, `engine.TrifectaVerdict/IsPrivateDataAccess/IsNetworkAttempt`, `audit.Write/DefaultPath`, `policy.SortedWaivers`, `adapter.PostureText/EmitClaudeSessionStart`) — only the dispatch and the final emit branch are new.
- `genconfig.OpencodeConfig(*policy.Policy, string) Fragment` — Task 4; consumes `bashDenyGlobs`/`bashAskGlobs`/`secretDenyGlobs`/`selfConfigDenyGlobs`/`ciInfraLockAskGlobs` (all pre-existing, Plan 2–4, zero signature changes) via the new `stripWrapper(string,string) (string,bool)`.
- `genconfig.OpencodePluginJS []byte` (embedded, Task 5) — consumed by `cmd/guardrail/genconfig.go`'s `cmdGenConfig`, which gains the `--plugin-dir` flag; `--merge`/`--binary`/`--print` behavior for the `claude` plane is byte-for-byte unchanged (verified by Task 5 Step 7 re-running the full suite including Plan 2's existing Claude merge tests).
- `test/contract_test.go`'s `buildBinary`/`goCmd` (Plan 3) reused unmodified for the new opencode fixtures (Task 6).

---

## Execution Handoff

**Plan complete and saved to `docs/superpowers/plans/2026-09-04-opencode-adapter.md`. Two execution options:**

**1. Subagent-Driven (recommended)** — fresh subagent per task via `superpowers:subagent-driven-development`, review between tasks.

**2. Inline Execution** — `superpowers:executing-plans`, batch with checkpoints.

**Which approach?**
