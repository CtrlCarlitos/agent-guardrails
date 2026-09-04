# P7 Two-Signal Trifecta Heuristic + P10 SessionStart Posture — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A scoped P7: track two signals per Claude session (touched a private-data path; attempted network egress) in a small session-state file, and escalate an otherwise-`allow` verdict to `ask` when the *second* signal appears in a session that already saw the first. A new P10: a `SessionStart` hook that delivers an autonomy-posture message plus the active-waiver banner (the Q10 requirement deferred since Plan 2) and any policy warnings, via the same `guardrail hook claude` binary.

**Architecture:** `internal/session` is a small, dependency-free package (state keyed by `session_id`, best-effort I/O, opportunistic 24h prune — no dedicated GC command yet). `internal/engine` gains two pure classifiers (`IsPrivateDataAccess`, `IsNetworkAttempt`) and a pure decision function (`TrifectaVerdict`) so the escalation logic is unit-testable without spinning the binary. `cmd/guardrail/hook.go` is the only place that does session I/O — it loads state, asks `engine.TrifectaVerdict`, escalates if `Allow`, then persists. `SessionStart` reuses `adapter.ParseClaude` (extended to recognize the event) and a new `EmitClaudeSessionStart`; `genconfig.claudeHooks` registers a third owned hook group, which Plan 3's generic `mergeHooks` already handles with no changes.

**Tech Stack:** Go 1.23+, existing deps only. No new dependencies.

**Spec:** `../../../DESIGN.md` P7, P10; Q10 (waiver banner), Q14 (engine-down warning surfacing). Confirmed scope (this session, two direct questions): P7 = two-signal heuristic only, `ask` not `deny`, the "untrusted-content ingestion" leg explicitly deferred; P10 = `SessionStart` hook, not a static file.

## Global Constraints

- **P7 v1 does not classify "untrusted content ingestion."** Only the two legs the current `ToolCall` model can observe: a P4-secret-glob-matching path access, and an invocation of a P6 network tool. The third leg of the classic lethal trifecta stays out of scope until there's a concrete design for classifying tool *results* as untrusted (would need `PostToolUse` `tool_response` parsing, not done anywhere in this codebase today).
- **Escalation only, never new denials.** `TrifectaVerdict` only upgrades an `Allow` to `Ask`; it never touches an existing `Ask` or `Deny` (don't stomp a more specific reason) and never produces `Deny` itself (it's a heuristic; false positives are real, so the cost of being wrong must be "one extra confirmation," not "blocked").
- **Trifecta escalation only fires on `PreToolUse` (`tc.Event == "pre"`).** By `PostToolUse` the action already happened; escalating there can't prevent anything and would only be confusing.
- **Respects `waive = ["P7.trifecta"]`.** A project may turn the heuristic off entirely.
- **Session state I/O is best-effort**, matching `audit.Write`'s philosophy: a read/write failure is reported to stderr and never changes the verdict or exit code.
- `SessionStart`'s hook `matcher` value is `"startup|clear|compact"` — **verified against the live, working reference already on this machine**: `~/.claude/plugins/cache/superpowers-marketplace/superpowers/*/hooks/hooks.json` and its paired `hooks/session-start` script emit `{"hookSpecificOutput":{"hookEventName":"SessionStart","additionalContext":"..."}}`. Task 5 has the executor read that file directly before writing the adapter code, since it's a proven-working example on this exact Claude Code install — more reliable than any written spec.
- Every code step is literal. `gofmt -w` before every commit. Conventional Commits, one commit per task.
- Verified current state: `genconfig.claudeHooks(binary) map[string]any` returns `{"PreToolUse":[...], "PostToolUse":[...]}`, each group carrying `"id":"guardrail-claude-pre"/"-post"` (Plan 3). `internal/genconfig/merge.go`'s `mergeHooks(dst, src map[string]any)` iterates `for event, sv := range src` generically — adding a third event key needs **no** merge.go change. `adapter.ParseClaude(io.Reader) (engine.ToolCall, error)` currently maps `hook_event_name`: `"PostToolUse"` → `Event:"post"`, anything else → `Event:"pre"`. `policy.SortedWaivers(*Policy) []string` exists (Plan 3 Task 6). `cmd/guardrail/hook.go`'s `cmdHook` flow: parse → `LoadBase` → `FindOverlayPath`/`LoadOverlay` → `Merge` (→ `merged`, `warnings`, err) → `engine.Evaluate` → audit → `adapter.EmitClaude`.

---

## Arc P7 — two-signal trifecta heuristic

### Task 1: `internal/session` — per-session state, best-effort I/O, 24h prune

**Files:**
- Create: `internal/session/session.go`
- Create: `internal/session/session_test.go`

**Interfaces:**
- `type State struct { SawPrivateRead bool; SawNetworkCall bool; UpdatedAt string }` (JSON tags `saw_private_read`, `saw_network_call`, `updated_at`).
- `func Path(sessionID string) string` — `<XDG_STATE_HOME or ~/.local/state>/guardrail/sessions/<id>.json` (Linux/mac), `<LOCALAPPDATA>/guardrail/sessions/<id>.json` (Windows). Same resolution shape as `audit.DefaultPath`, independent implementation (no import from `internal/audit` — keeps the two packages decoupled; both may drift to a shared `internal/statedir` later, not now).
- `func Load(sessionID string) (*State, error)` — missing file or empty `sessionID` ⇒ `(&State{}, nil)`, not an error.
- `func Save(sessionID string, s *State) error` — no-op success for empty `sessionID`; sets `s.UpdatedAt`; writes `0600`; then opportunistically removes session files older than 24h in the same directory (errors from the prune sweep are swallowed — it is best-effort cleanup, never the caller's concern).

- [ ] **Step 1: Write the failing tests**

`internal/session/session_test.go`:

```go
package session

import (
	"os"
	"testing"
	"time"
)

func TestLoadMissingIsZeroState(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	s, err := Load("nonexistent-session")
	if err != nil {
		t.Fatal(err)
	}
	if s.SawPrivateRead || s.SawNetworkCall {
		t.Fatalf("want zero state, got %+v", s)
	}
}

func TestSaveLoadRoundTrip(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	want := &State{SawPrivateRead: true}
	if err := Save("sess1", want); err != nil {
		t.Fatal(err)
	}
	got, err := Load("sess1")
	if err != nil {
		t.Fatal(err)
	}
	if !got.SawPrivateRead || got.SawNetworkCall {
		t.Fatalf("got %+v", got)
	}
	if got.UpdatedAt == "" {
		t.Error("UpdatedAt not set")
	}
}

func TestEmptySessionIDIsNoOp(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	if err := Save("", &State{SawPrivateRead: true}); err != nil {
		t.Fatal(err)
	}
	s, err := Load("")
	if err != nil || s.SawPrivateRead {
		t.Fatalf("empty session id should no-op, got %+v, err=%v", s, err)
	}
}

func TestPruneRemovesOldSessions(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	Save("old", &State{})
	oldPath := Path("old")
	oldTime := time.Now().Add(-48 * time.Hour)
	os.Chtimes(oldPath, oldTime, oldTime)

	Save("new", &State{}) // triggers a prune sweep as a side effect

	if _, err := os.Stat(oldPath); !os.IsNotExist(err) {
		t.Error("old session file should have been pruned")
	}
	if _, err := os.Stat(Path("new")); err != nil {
		t.Error("new session file should still exist")
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `/usr/local/go/bin/go test ./internal/session/... -v`
Expected: FAIL — package/functions undefined.

- [ ] **Step 3: Write minimal implementation**

`internal/session/session.go`:

```go
// Package session tracks a small set of per-session signals — has this
// Claude session touched a private-data path, has it attempted network
// egress — consumed by the P7 lethal-trifecta heuristic in internal/engine.
// State is best-effort: a read/write failure never blocks a verdict, it just
// means the heuristic silently sees no signal yet.
package session

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"time"
)

type State struct {
	SawPrivateRead bool   `json:"saw_private_read"`
	SawNetworkCall bool   `json:"saw_network_call"`
	UpdatedAt      string `json:"updated_at"`
}

func dir() string {
	if runtime.GOOS == "windows" {
		return filepath.Join(os.Getenv("LOCALAPPDATA"), "guardrail", "sessions")
	}
	base := os.Getenv("XDG_STATE_HOME")
	if base == "" {
		home, _ := os.UserHomeDir()
		base = filepath.Join(home, ".local", "state")
	}
	return filepath.Join(base, "guardrail", "sessions")
}

func Path(sessionID string) string {
	return filepath.Join(dir(), sessionID+".json")
}

func Load(sessionID string) (*State, error) {
	if sessionID == "" {
		return &State{}, nil
	}
	raw, err := os.ReadFile(Path(sessionID))
	if err != nil {
		if os.IsNotExist(err) {
			return &State{}, nil
		}
		return &State{}, err
	}
	var s State
	if err := json.Unmarshal(raw, &s); err != nil {
		return &State{}, err
	}
	return &s, nil
}

func Save(sessionID string, s *State) error {
	if sessionID == "" {
		return nil
	}
	s.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	d := dir()
	if err := os.MkdirAll(d, 0o700); err != nil {
		return err
	}
	raw, err := json.Marshal(s)
	if err != nil {
		return err
	}
	if err := os.WriteFile(Path(sessionID), raw, 0o600); err != nil {
		return err
	}
	prune(d)
	return nil
}

// prune removes session files whose mtime is older than 24h. Best-effort:
// any error here is silently swallowed, never returned to the caller.
func prune(d string) {
	entries, err := os.ReadDir(d)
	if err != nil {
		return
	}
	cutoff := time.Now().Add(-24 * time.Hour)
	for _, e := range entries {
		info, err := e.Info()
		if err != nil || info.ModTime().After(cutoff) {
			continue
		}
		os.Remove(filepath.Join(d, e.Name()))
	}
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `/usr/local/go/bin/go test ./internal/session/... -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
gofmt -w internal/session/
git add internal/session/
git commit -m "feat(session): best-effort per-session state store with 24h opportunistic prune"
```

---

### Task 2: `engine.IsPrivateDataAccess` / `IsNetworkAttempt` — pure signal classifiers

**Files:**
- Create: `internal/engine/trifecta_signals.go`
- Create: `internal/engine/trifecta_signals_test.go`

**Interfaces:**
- `func IsPrivateDataAccess(tc ToolCall, pol *policy.Policy) bool` — same candidate-gathering and glob match P4 (`checkPaths`) already uses (file-tool `tc.Paths` + bash-reader args), against `pol.Slots.SecretGlobs` minus `pol.Slots.SecretAllow`. **Deliberately unconditional on waivers** — it answers "did this tool call touch a secret-classified path," not "was it blocked." (A read that P4 denies never reaches the agent; a read that P4 *would* deny but the project waived `P4.secret-path` succeeds — and this function still correctly flags it, which is the point: the trifecta gate is what remains watching after a waiver removes the primary guard.)
- `func IsNetworkAttempt(tc ToolCall) bool` — true iff `tc.IsBash()` and `Normalize(tc.Command)` contains any `Simple` whose `Argv[0]` is in the `netTools` set from `rules_net.go`. Not conditioned on P6's verdict — a network attempt to an allowlisted or localhost target still counts.

- [ ] **Step 1: Write the failing tests**

`internal/engine/trifecta_signals_test.go`:

```go
package engine

import "testing"

func TestIsPrivateDataAccess(t *testing.T) {
	pol := pathPol()
	if !IsPrivateDataAccess(ToolCall{Tool: "Read", Paths: []string{"/h/.ssh/id_rsa"}}, pol) {
		t.Error("want true for a secret path")
	}
	if IsPrivateDataAccess(ToolCall{Tool: "Read", Paths: []string{"src/main.go"}}, pol) {
		t.Error("want false for a non-secret path")
	}
	if !IsPrivateDataAccess(ToolCall{Tool: "Bash", Command: "cat ~/.aws/credentials"}, pol) {
		t.Error("want true for a bash reader of a secret path")
	}
	if IsPrivateDataAccess(ToolCall{Tool: "Read", Paths: []string{"/repo/.env.example"}}, pol) {
		t.Error("want false for an allowlisted secret-adjacent path")
	}
}

func TestIsNetworkAttempt(t *testing.T) {
	if !IsNetworkAttempt(ToolCall{Tool: "Bash", Command: "curl https://example.com"}) {
		t.Error("want true for curl")
	}
	if IsNetworkAttempt(ToolCall{Tool: "Bash", Command: "ls -la"}) {
		t.Error("want false for ls")
	}
	if IsNetworkAttempt(ToolCall{Tool: "Read", Paths: []string{"x"}}) {
		t.Error("want false for a non-bash tool call")
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `/usr/local/go/bin/go test ./internal/engine/ -run 'TestIsPrivateDataAccess|TestIsNetworkAttempt' -v`
Expected: FAIL — undefined.

- [ ] **Step 3: Write minimal implementation**

`internal/engine/trifecta_signals.go`:

```go
package engine

import (
	"strings"

	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
)

// IsPrivateDataAccess reports whether tc touches a secret-classified path —
// the same glob match P4 (checkPaths) uses, exposed for the P7 heuristic.
// Deliberately unconditional on waivers: see the doc comment in the plan
// that introduced this function.
func IsPrivateDataAccess(tc ToolCall, pol *policy.Policy) bool {
	var candidates []string
	if isFileTool(tc.Tool) {
		candidates = append(candidates, tc.Paths...)
	}
	if tc.IsBash() {
		if simples, err := Normalize(tc.Command); err == nil {
			for _, s := range simples {
				if len(s.Argv) > 0 && pathReaders[s.Argv[0]] {
					candidates = append(candidates, nonFlagArgs(s.Argv)...)
				}
			}
		}
	}
	for _, c := range candidates {
		c = strings.TrimPrefix(strings.TrimPrefix(c, "~/"), "~")
		if matchesAnyGlob(c, pol.Slots.SecretAllow) {
			continue
		}
		if matchesAnyGlob(c, pol.Slots.SecretGlobs) {
			return true
		}
	}
	return false
}

// IsNetworkAttempt reports whether tc invokes a network tool at all,
// regardless of what P6 decides about the destination.
func IsNetworkAttempt(tc ToolCall) bool {
	if !tc.IsBash() {
		return false
	}
	simples, err := Normalize(tc.Command)
	if err != nil {
		return false
	}
	for _, s := range simples {
		if len(s.Argv) > 0 && netTools[s.Argv[0]] {
			return true
		}
	}
	return false
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `/usr/local/go/bin/go test ./internal/engine/ -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
gofmt -w internal/engine/
git add internal/engine/
git commit -m "feat(engine): pure IsPrivateDataAccess/IsNetworkAttempt classifiers for the P7 heuristic"
```

---

### Task 3: `engine.TrifectaVerdict` — the pure escalation decision

**Files:**
- Modify: `internal/engine/trifecta_signals.go`
- Modify: `internal/engine/trifecta_signals_test.go`

**Interfaces:**
- `func TrifectaVerdict(v policy.Verdict, isPrivate, isNet bool, st *session.State) *policy.Verdict` — `nil` unless `v.Decision == policy.Allow`. Escalates to `&policy.Verdict{Decision: policy.Ask, RuleID: "P7.trifecta", Reason: "..."}` when `(isPrivate && st.SawNetworkCall) || (isNet && st.SawPrivateRead)`. `internal/engine` importing `internal/session` introduces no cycle (`internal/session` has no internal imports).

- [ ] **Step 1: Write the failing test**

Add to `internal/engine/trifecta_signals_test.go`:

```go
import "github.com/CtrlCarlitos/agent-guardrails/internal/session" // add to imports
import "github.com/CtrlCarlitos/agent-guardrails/internal/policy"  // add to imports

func TestTrifectaVerdictEscalatesSecondLeg(t *testing.T) {
	v := TrifectaVerdict(policy.Verdict{Decision: policy.Allow}, true, false, &session.State{SawNetworkCall: true})
	if v == nil || v.Decision != policy.Ask || v.RuleID != "P7.trifecta" {
		t.Fatalf("private read after a network call -> %+v, want ask/P7.trifecta", v)
	}
	v = TrifectaVerdict(policy.Verdict{Decision: policy.Allow}, false, true, &session.State{SawPrivateRead: true})
	if v == nil || v.RuleID != "P7.trifecta" {
		t.Fatalf("network call after a private read -> %+v, want ask/P7.trifecta", v)
	}
}

func TestTrifectaVerdictNoEscalationWithoutBothLegs(t *testing.T) {
	if v := TrifectaVerdict(policy.Verdict{Decision: policy.Allow}, true, false, &session.State{}); v != nil {
		t.Fatalf("private read with no prior signal -> %+v, want nil", v)
	}
	if v := TrifectaVerdict(policy.Verdict{Decision: policy.Allow}, false, false, &session.State{SawPrivateRead: true, SawNetworkCall: true}); v != nil {
		t.Fatalf("neither leg this call -> %+v, want nil", v)
	}
}

func TestTrifectaVerdictNeverOverridesNonAllow(t *testing.T) {
	existing := policy.Verdict{Decision: policy.Ask, RuleID: "P1.chmod", Reason: "other reason"}
	if v := TrifectaVerdict(existing, true, true, &session.State{SawPrivateRead: true, SawNetworkCall: true}); v != nil {
		t.Fatalf("should not override an existing non-allow verdict, got %+v", v)
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `/usr/local/go/bin/go test ./internal/engine/ -run TestTrifectaVerdict -v`
Expected: FAIL — `TrifectaVerdict` undefined.

- [ ] **Step 3: Write minimal implementation**

Add to `internal/engine/trifecta_signals.go` (add `"github.com/CtrlCarlitos/agent-guardrails/internal/session"` to imports):

```go
func TrifectaVerdict(v policy.Verdict, isPrivate, isNet bool, st *session.State) *policy.Verdict {
	if v.Decision != policy.Allow {
		return nil
	}
	if (isPrivate && st.SawNetworkCall) || (isNet && st.SawPrivateRead) {
		return &policy.Verdict{Decision: policy.Ask, RuleID: "P7.trifecta",
			Reason: "this session already touched both private data and network egress — pausing on the second leg of the pattern"}
	}
	return nil
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `/usr/local/go/bin/go test ./internal/engine/ -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
gofmt -w internal/engine/
git add internal/engine/
git commit -m "feat(engine): TrifectaVerdict — pure allow-to-ask escalation on the second trifecta leg"
```

---

### Task 4: Wire trifecta tracking into `cmdHook`

**Files:**
- Modify: `cmd/guardrail/hook.go`
- Modify: `cmd/guardrail/hook_test.go`

**Interfaces:**
- After `v := engine.Evaluate(tc, merged)` and before building the `audit.Record`: if `tc.Event == "pre"` and `tc.SessionID != ""` and `!merged.Waived["P7.trifecta"]` — load session state, compute `isPrivate`/`isNet`, call `engine.TrifectaVerdict`, replace `v` if non-nil, then persist the OR-updated state (`SawPrivateRead = old || isPrivate`, same for network) regardless of whether escalation fired. A save error is reported to stderr, never changes the exit code.

- [ ] **Step 1: Write the failing test**

Add to `cmd/guardrail/hook_test.go`:

```go
func TestTrifectaEscalatesAcrossTwoCalls(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	cfg := filepath.Join(t.TempDir(), "guardrail.toml")
	os.WriteFile(cfg, []byte("waive = [\"P4.secret-path\"]\n"), 0o644)
	t.Setenv("GUARDRAIL_CONFIG", cfg)

	sid := "trifecta-sess-1"
	readPayload := `{"session_id":"` + sid + `","cwd":"/tmp","hook_event_name":"PreToolUse","tool_name":"Read","tool_input":{"file_path":"/tmp/.env"}}`
	var out1, err1 bytes.Buffer
	if code := run([]string{"hook", "claude"}, strings.NewReader(readPayload), &out1, &err1); code != 0 {
		t.Fatalf("first call (waived secret read): exit %d, want 0; stderr=%s", code, err1.String())
	}

	curlPayload := `{"session_id":"` + sid + `","cwd":"/tmp","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"curl http://localhost:9999/x"}}`
	var out2, err2 bytes.Buffer
	code2 := run([]string{"hook", "claude"}, strings.NewReader(curlPayload), &out2, &err2)
	if code2 != 0 {
		t.Fatalf("second call: exit %d, want 0 (ask, not deny); stderr=%s", code2, err2.String())
	}
	if !strings.Contains(out2.String(), "trifecta") {
		t.Fatalf("second call should ask citing the trifecta pattern, got stdout=%s", out2.String())
	}
}

func TestTrifectaSilentWithoutPriorSignal(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	t.Setenv("GUARDRAIL_CONFIG", "")
	payload := `{"session_id":"lone-sess","cwd":"/tmp","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"curl http://localhost:9999/x"}}`
	var out, errb bytes.Buffer
	code := run([]string{"hook", "claude"}, strings.NewReader(payload), &out, &errb)
	if code != 0 || strings.Contains(out.String(), "trifecta") {
		t.Fatalf("a lone network call should not trigger trifecta: code=%d out=%s", code, out.String())
	}
}
```

(Add `"path/filepath"` and `"os"` to `hook_test.go`'s imports if not already present.)

- [ ] **Step 2: Run the tests to verify they fail**

Run: `/usr/local/go/bin/go test ./cmd/guardrail/ -run TestTrifecta -v`
Expected: FAIL — the second call currently exits 0 with no trifecta mention (not wired yet).

- [ ] **Step 3: Write minimal implementation**

In `cmd/guardrail/hook.go`, add `"github.com/CtrlCarlitos/agent-guardrails/internal/session"` to imports. After the line computing `v := engine.Evaluate(tc, merged)` and before the `audit.Record{...}` construction, insert:

```go
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
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `/usr/local/go/bin/go test ./cmd/guardrail/ -v`
Expected: PASS. Run the full suite too: `/usr/local/go/bin/go test ./... -v` — confirm nothing else regressed.

- [ ] **Step 5: Commit**

```bash
gofmt -w cmd/guardrail/
git add cmd/guardrail/
git commit -m "feat(cli): wire the P7 trifecta heuristic into guardrail hook claude (pre-only, waivable)"
```

---

### Task 5: ADR-0005 (injection hygiene) + ADR-0006 (trifecta heuristic design)

**Files:**
- Create: `docs/adr/0005-injection-hygiene-already-satisfied.md`
- Create: `docs/adr/0006-two-signal-trifecta-heuristic.md`

- [ ] **Step 1: Write ADR-0005**

```markdown
# Prompt-injection hygiene (P7's coding-practice half) is already satisfied

DESIGN.md's P7 names a set of coding practices for hook code itself: treat
all tool input/output/fetched content as untrusted data, parse with a real
JSON parser rather than `eval`, never build model-facing text by string
interpolation, validate paths with `readlink`/prefix-checks rather than trust.

Audit: `internal/adapter/claude.go` uses `encoding/json.Unmarshal`, never
shells out to interpret payload content. `internal/adapter/claude.go`'s
`EmitClaude` builds its JSON response via `encoding/json.Marshal` on a
`map[string]any`, never string concatenation — a malicious `Reason` string
cannot break out of the JSON structure. `internal/engine/rules_path.go`'s
`checkSymlinkEscape` resolves paths with `filepath.EvalSymlinks` and a
prefix check, not string matching. No hook code anywhere in this repo shells
out to `eval`, `sh -c` with unsanitized interpolated text, or similar.

Decision: no new code for this half of P7. Recorded here so the practice is
traceable to a decision, and so a future contributor doesn't wonder why P7
has no corresponding "hygiene" module — [`0006`](./0006-two-signal-trifecta-heuristic.md) covers the other half.
```

- [ ] **Step 2: Write ADR-0006**

```markdown
# P7 lethal-trifecta gate: two signals, ask not deny, session-state, v1 scope

The classic lethal-trifecta pattern is three legs: private-data access,
untrusted-content ingestion, outbound network capability. The third leg
isn't classifiable from what this codebase tracks today — `PostToolUse`
`tool_response` content isn't parsed anywhere, and there's no taxonomy yet
of which tools/results count as "untrusted." Building that taxonomy well
is real design work with real false-positive risk, deferred until there's
a concrete case for it (confirmed scope decision, 2026-09-04).

Decision: v1 tracks only the two legs the existing `ToolCall` model already
observes — a P4-secret-glob-matching path access, and an invocation of a
P6 network tool — in a small per-session state file (`internal/session`).
When the *second* leg appears in a session that already saw the *first*,
an otherwise-`allow` verdict is escalated to `ask`, never `deny` (a
heuristic earns a confirmation prompt, not a hard block) and never
overrides an existing non-allow verdict (don't stomp a more specific
reason). Firing is scoped to `PreToolUse` only — by `PostToolUse` the
action already happened. `waive = ["P7.trifecta"]` turns it off per repo.

The private-data signal is deliberately independent of P4's own
enforcement: it fires even when `P4.secret-path` is waived. That is the
point — a waiver removes the primary read guard, and the trifecta gate is
what keeps watching for that data being followed by an egress attempt.

## Consequences

- Session state has no dedicated cleanup command; `internal/session.Save`
  opportunistically prunes files older than 24h as a side effect of every
  write. Acceptable for now — sessions are small JSON files, not a real
  storage concern.
- A network attempt to `localhost` or an allowlisted host still counts as
  the "network" leg for trifecta purposes, even though P6 itself would
  allow it — the trifecta gate cares about capability, not destination.
```

- [ ] **Step 3: Commit**

```bash
git add docs/adr/0005-injection-hygiene-already-satisfied.md docs/adr/0006-two-signal-trifecta-heuristic.md
git commit -m "docs(adr): 0005 injection hygiene already satisfied, 0006 two-signal trifecta scope"
```

---

## Arc P10 — SessionStart posture + waiver banner

### Task 6: Reference the live SessionStart implementation; extend `ParseClaude`

**Files:**
- Modify: `internal/adapter/claude.go`
- Modify: `internal/adapter/claude_test.go`

**Interfaces:**
- `ParseClaude` — `Event` mapping gains a third case: `p.HookEventName == "SessionStart"` → `Event: "session-start"`.

- [ ] **Step 1: Read the reference implementation**

Run:
```bash
cat ~/.claude/plugins/cache/superpowers-marketplace/superpowers/*/hooks/hooks.json
cat ~/.claude/plugins/cache/superpowers-marketplace/superpowers/*/hooks/session-start
```
Confirm: the `matcher` value used for `SessionStart` (expected `"startup|clear|compact"`), and the exact response JSON shape the script emits for a plain Claude Code harness (expected `{"hookSpecificOutput":{"hookEventName":"SessionStart","additionalContext":"..."}}`). This is a proven-working example on this exact Claude Code install — if it differs from what's written here, **follow the file on disk**, not this plan text, and note the discrepancy in your final report.

- [ ] **Step 2: Write the failing test**

Add to `internal/adapter/claude_test.go`:

```go
func TestParseClaudeSessionStart(t *testing.T) {
	raw := `{"session_id":"s1","cwd":"/tmp","hook_event_name":"SessionStart"}`
	tc, err := ParseClaude(strings.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	if tc.Event != "session-start" {
		t.Fatalf("Event = %q, want session-start", tc.Event)
	}
}
```

(Add `"strings"` to imports if absent.)

- [ ] **Step 3: Run the test to verify it fails**

Run: `/usr/local/go/bin/go test ./internal/adapter/ -run TestParseClaudeSessionStart -v`
Expected: FAIL — `Event` is `"pre"` (the current default branch).

- [ ] **Step 4: Write minimal implementation**

In `internal/adapter/claude.go`'s `ParseClaude`, change:

```go
	event := "pre"
	if p.HookEventName == "PostToolUse" {
		event = "post"
	}
```

to:

```go
	event := "pre"
	switch p.HookEventName {
	case "PostToolUse":
		event = "post"
	case "SessionStart":
		event = "session-start"
	}
```

- [ ] **Step 5: Run the test to verify it passes**

Run: `/usr/local/go/bin/go test ./internal/adapter/ -v`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
gofmt -w internal/adapter/
git add internal/adapter/
git commit -m "feat(adapter): ParseClaude recognizes the SessionStart event"
```

---

### Task 7: `PostureText` + `EmitClaudeSessionStart`

**Files:**
- Modify: `internal/adapter/claude.go`
- Modify: `internal/adapter/claude_test.go`

**Interfaces:**
- `func PostureText(waivers []string, warnings []string) string` — a fixed autonomy-posture paragraph, plus (if non-empty) an "Active policy waivers in this repo" line listing `waivers`, plus one paragraph per entry in `warnings` (these are the same `[]string` `policy.Merge` already returns — engine_min_version mismatches, active-waiver notices — now finally surfaced to the agent instead of only to stderr on a tool call).
- `func EmitClaudeSessionStart(text string, stdout io.Writer) int` — writes `{"hookSpecificOutput":{"hookEventName":"SessionStart","additionalContext":<text>}}` + newline to `stdout`, returns `0`. **If Task 6's Step 1 reference file shows a different response shape**, match that shape instead and note the deviation in the commit message.

- [ ] **Step 1: Write the failing test**

Add to `internal/adapter/claude_test.go`:

```go
func TestPostureText(t *testing.T) {
	txt := PostureText(nil, nil)
	if !strings.Contains(txt, "autonomously") {
		t.Fatalf("posture text missing the autonomy instruction: %q", txt)
	}
	txt = PostureText([]string{"P6"}, []string{"guardrail: binary older than engine_min_version"})
	if !strings.Contains(txt, "P6") {
		t.Fatalf("posture text should list active waivers: %q", txt)
	}
	if !strings.Contains(txt, "engine_min_version") {
		t.Fatalf("posture text should surface merge warnings: %q", txt)
	}
}

func TestEmitClaudeSessionStart(t *testing.T) {
	var out bytes.Buffer
	code := EmitClaudeSessionStart("hello agent", &out)
	if code != 0 {
		t.Fatalf("code = %d, want 0", code)
	}
	var got struct {
		HookSpecificOutput struct {
			HookEventName     string `json:"hookEventName"`
			AdditionalContext string `json:"additionalContext"`
		} `json:"hookSpecificOutput"`
	}
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.HookSpecificOutput.HookEventName != "SessionStart" || got.HookSpecificOutput.AdditionalContext != "hello agent" {
		t.Fatalf("bad payload: %+v", got.HookSpecificOutput)
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `/usr/local/go/bin/go test ./internal/adapter/ -run 'TestPostureText|TestEmitClaudeSessionStart' -v`
Expected: FAIL — undefined.

- [ ] **Step 3: Write minimal implementation**

Add to `internal/adapter/claude.go`:

```go
func PostureText(waivers []string, warnings []string) string {
	var b strings.Builder
	b.WriteString("guardrail is active. Operate autonomously on routine development steps — " +
		"do not stop to ask conversational permission; guardrail enforces destructive-command " +
		"and secret-access boundaries deterministically. Pause only when guardrail returns an " +
		"explicit block/ask, or you face genuine ambiguity outside its scope.")
	if len(waivers) > 0 {
		b.WriteString("\n\nActive policy waivers in this repo (these rules are OFF): " + strings.Join(waivers, ", "))
	}
	for _, w := range warnings {
		b.WriteString("\n\n" + w)
	}
	return b.String()
}

func EmitClaudeSessionStart(text string, stdout io.Writer) int {
	payload := map[string]any{
		"hookSpecificOutput": map[string]any{
			"hookEventName":     "SessionStart",
			"additionalContext": text,
		},
	}
	b, _ := json.Marshal(payload)
	stdout.Write(append(b, '\n'))
	return 0
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `/usr/local/go/bin/go test ./internal/adapter/ -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
gofmt -w internal/adapter/
git add internal/adapter/
git commit -m "feat(adapter): PostureText + EmitClaudeSessionStart — autonomy posture, waivers, warnings"
```

---

### Task 8: Wire the `session-start` branch into `cmdHook`

**Files:**
- Modify: `cmd/guardrail/hook.go`
- Modify: `cmd/guardrail/hook_test.go`

**Interfaces:**
- In `cmdHook`, after `merged, warnings, err := policy.Merge(...)` (and its error handling) and the `for _, w := range warnings { fmt.Fprintln(stderr, w) }` loop, insert a branch: if `tc.Event == "session-start"`, call `adapter.PostureText(policy.SortedWaivers(merged), warnings)` and `return adapter.EmitClaudeSessionStart(text, stdout)` — skip `engine.Evaluate`, the trifecta block (Task 4), and the tool-call `audit.Record` entirely (a session start isn't a tool call).

- [ ] **Step 1: Write the failing test**

Add to `cmd/guardrail/hook_test.go`:

```go
func TestHookSessionStart(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	cfg := filepath.Join(t.TempDir(), "guardrail.toml")
	os.WriteFile(cfg, []byte("waive = [\"P6\"]\n"), 0o644)
	t.Setenv("GUARDRAIL_CONFIG", cfg)

	payload := `{"session_id":"s1","cwd":"/tmp","hook_event_name":"SessionStart"}`
	var out, errb bytes.Buffer
	code := run([]string{"hook", "claude"}, strings.NewReader(payload), &out, &errb)
	if code != 0 {
		t.Fatalf("exit=%d stderr=%q", code, errb.String())
	}
	if !strings.Contains(out.String(), "autonomously") {
		t.Fatalf("missing posture text: %s", out.String())
	}
	if !strings.Contains(out.String(), "P6") {
		t.Fatalf("missing waiver banner: %s", out.String())
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `/usr/local/go/bin/go test ./cmd/guardrail/ -run TestHookSessionStart -v`
Expected: FAIL — `plane != "claude"` isn't the issue (it is claude), but nothing currently branches on `Event == "session-start"`, so it falls through to `engine.Evaluate` on an empty `Command`/`Tool` and likely emits nothing to stdout (`EmitClaude` with `Allow` writes nothing).

- [ ] **Step 3: Write minimal implementation**

In `cmd/guardrail/hook.go`, immediately after the `for _, w := range warnings { fmt.Fprintln(stderr, w) }` loop and before `v := engine.Evaluate(tc, merged)`, insert:

```go
	if tc.Event == "session-start" {
		text := adapter.PostureText(policy.SortedWaivers(merged), warnings)
		return adapter.EmitClaudeSessionStart(text, stdout)
	}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `/usr/local/go/bin/go test ./cmd/guardrail/ -v`
Expected: PASS. Run the full suite: `/usr/local/go/bin/go test ./... -v`.

- [ ] **Step 5: Commit**

```bash
gofmt -w cmd/guardrail/
git add cmd/guardrail/
git commit -m "feat(cli): guardrail hook claude answers SessionStart with posture text + waiver banner"
```

---

### Task 9: Register the `SessionStart` hook group in the declarative floor

**Files:**
- Modify: `internal/genconfig/claude.go`
- Modify: `internal/genconfig/claude_test.go`
- Modify: `test/fixtures/claude/settings-floor.golden.json` (regenerated)

**Interfaces:**
- `claudeHooks(binary string) map[string]any` gains a third top-level key, `"SessionStart"`, one group: `{"id":"guardrail-claude-session-start","matcher":"startup|clear|compact","hooks":[{"type":"command","command":<binary>+" hook claude"}]}`. **Use whatever matcher Task 6 Step 1 confirmed on disk** if it differs from `"startup|clear|compact"`.

- [ ] **Step 1: Write the failing test**

Add to `internal/genconfig/claude_test.go`:

```go
func TestClaudeHooksSessionStart(t *testing.T) {
	h := claudeHooks("/usr/local/bin/guardrail")
	ss, ok := h["SessionStart"].([]any)
	if !ok || len(ss) != 1 {
		t.Fatalf("SessionStart shape wrong: %#v", h["SessionStart"])
	}
	g := ss[0].(map[string]any)
	if g["id"] != "guardrail-claude-session-start" {
		t.Errorf("id = %v", g["id"])
	}
	cmd := g["hooks"].([]any)[0].(map[string]any)["command"].(string)
	if cmd != "/usr/local/bin/guardrail hook claude" {
		t.Errorf("command = %q", cmd)
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `/usr/local/go/bin/go test ./internal/genconfig/ -run TestClaudeHooksSessionStart -v`
Expected: FAIL — `h["SessionStart"]` is nil.

- [ ] **Step 3: Write minimal implementation**

In `internal/genconfig/claude.go`'s `claudeHooks`, add a third map entry:

```go
		"SessionStart": []any{
			map[string]any{
				"id":      "guardrail-claude-session-start",
				"matcher": "startup|clear|compact",
				"hooks": []any{
					map[string]any{"type": "command", "command": cmd},
				},
			},
		},
```

(alongside the existing `"PreToolUse"`/`"PostToolUse"` entries in the same returned map literal.)

- [ ] **Step 4: Run the test to verify it passes**

Run: `/usr/local/go/bin/go test ./internal/genconfig/ -v`
Expected: PASS.

- [ ] **Step 5: Regenerate the golden and confirm the merge still behaves**

Run:
```bash
/usr/local/go/bin/go test ./test/ -run Golden -update
/usr/local/go/bin/go test ./test/ -run Golden -v
/usr/local/go/bin/go test ./internal/genconfig/ -run 'TestMergeHooks|TestPermissionsStill' -v
```
Expected: golden gets a new `SessionStart` block; second run PASSES; Plan 3's merge tests still PASS unmodified — confirming `mergeHooks`'s generic `for event, sv := range src` loop needed zero changes to pick up the third event.

- [ ] **Step 6: Commit**

```bash
gofmt -w internal/genconfig/
git add internal/genconfig/ test/fixtures/claude/settings-floor.golden.json
git commit -m "feat(genconfig): register the SessionStart hook group in the Claude floor"
```

---

## Arc — wrap-up

### Task 10: docs + tag `v0.5.0-dev` + self-review

**Files:**
- Modify: `README.md`
- Modify: `docs/HANDOFF-2026-09-03.md`

- [ ] **Step 1: `make check` + full suite**

Run: `make check && /usr/local/go/bin/go test ./...`
Expected: all green, vet clean, gofmt clean.

- [ ] **Step 2: README Status**

```markdown
## Status

Plans 1–4 + the git -C/-c hotfix (v0.4.1) + Plan 4b implemented. `guardrail hook
claude` enforces P1/P2/P4/P5/P6, escalates via a two-signal P7 trifecta heuristic
(session-scoped, ask-only, waivable), and answers SessionStart with an autonomy
posture message + active-waiver banner (P10). `gen-config`/`doctor` cover Claude
installation and diagnostics. CI + real releases ship the binary; the chezmoi
installer wires it globally, currently pinned to v0.4.1. Pending: opencode adapter
(Plan 5), Antigravity adapter (Plan 6), recipes + `guardrail sync` (Plan 7). Known
parked gaps: `git -C <path>` target-repo validation (a different concern from the
v0.4.1 parsing fix), `docker … | xargs`, backslash-escaped words, `bash -lc`,
Windows-path engine semantics, macOS `sha256sum` fallback.
```

- [ ] **Step 3: HANDOFF plan table**

Mark Plan 4b done; note the confirmed v1 scope (two-signal heuristic, `SessionStart` posture) and that the `git -C <path>` target-validation gap rides with whatever future plan revisits P2's git module.

- [ ] **Step 4: Push and tag**

```bash
git add README.md docs/HANDOFF-2026-09-03.md
git commit -m "docs: Plan 4b done — P7 two-signal trifecta heuristic, P10 SessionStart posture"
git push origin main
git tag v0.5.0-dev
git push origin v0.5.0-dev
```

(`-dev`: same reasoning as Plan 4's `v0.4.0-dev` — a deliberate, reviewed bump decides when this becomes the installer-pinned version, not an automatic release.)

---

## Self-Review

**1. Spec coverage.**

| Item | Task |
|---|---|
| P7: private-data-access signal | 2 |
| P7: network-attempt signal | 2 |
| P7: escalation decision (ask-only, allow-only override, waivable) | 3, 4 |
| P7: session-state store, best-effort, 24h prune | 1 |
| P7: injection-hygiene half already satisfied (audited, not re-implemented) | 5 (ADR-0005) |
| P7: scope decision recorded | 5 (ADR-0006) |
| P10: SessionStart event recognized | 6 |
| P10: posture text + waiver banner + warnings surfaced | 7, 8 |
| P10: declarative-floor registration, reusing Plan 3's generic merge | 9 |

Deferred, confirmed out of scope for v1: the third trifecta leg (untrusted-content classification); `git -C <path>` target-repo validation (unrelated to the v0.4.1 parsing fix — this is about validating *what the path points at*, still parked); a dedicated session-state GC command (the 24h prune-on-write is the interim answer).

**2. Placeholder scan.** No `TBD`/"handle appropriately". Task 6's Step 1 instructs reading a live reference file before writing code and explicitly says to follow it over this plan's text if they differ — that is a real verification instruction, not a placeholder, precisely because the SessionStart response shape is the one detail in this plan not already proven by this codebase's own prior tests.

**3. Type consistency.**
- `session.State{SawPrivateRead, SawNetworkCall bool; UpdatedAt string}`, `session.Path/Load/Save` — Task 1; consumed by Task 4 and by `engine.TrifectaVerdict`'s `*session.State` parameter (Task 3).
- `engine.IsPrivateDataAccess(ToolCall, *policy.Policy) bool` / `IsNetworkAttempt(ToolCall) bool` — Task 2; called from Task 4's `cmdHook` wiring and reused nowhere else yet (future opencode/antigravity adapters will call the same two functions — no plane-specific logic here by design).
- `engine.TrifectaVerdict(policy.Verdict, bool, bool, *session.State) *policy.Verdict` — Task 3; called from Task 4.
- `adapter.ParseClaude` — `Event` gains `"session-start"` (Task 6); all existing PreToolUse/PostToolUse callers unaffected (switch's default path unchanged).
- `adapter.PostureText([]string, []string) string` / `EmitClaudeSessionStart(string, io.Writer) int` — Task 7; called from `cmdHook`'s new branch (Task 8).
- `genconfig.claudeHooks(string) map[string]any` — gains the `"SessionStart"` key (Task 9); `Fragment`/`ClaudeConfig`/`MergeInto`/`mergeHooks` signatures all unchanged — Plan 3's generic per-event merge loop absorbs the new key with zero code changes, confirmed in Task 9 Step 5.
- No signature changes to `Evaluate`, `checkBash`, `checkPaths`, `cmdGenConfig`, `cmdDoctor`.

---

## Execution Handoff

**Plan complete and saved to `docs/superpowers/plans/2026-09-04-trifecta-and-posture.md`. Two execution options:**

**1. Subagent-Driven (recommended)** — fresh subagent per task via `superpowers:subagent-driven-development`, review between tasks.

**2. Inline Execution** — `superpowers:executing-plans`, batch with checkpoints.

**Which approach?**
