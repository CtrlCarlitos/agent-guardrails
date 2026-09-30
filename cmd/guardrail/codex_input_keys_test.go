package main

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/CtrlCarlitos/agent-guardrails/internal/testenv"
)

// #454: Codex 0.159 dispatches PreToolUse on Windows, and whether its
// tool_input carries the command's working directory decides the fix
// (ADR-0014: 0.154 omitted unified exec's workdir). Codex audit records
// therefore list tool_input's field names, never their values, so one probe
// answers it and later contract drift shows up in the log.
func TestCodexAuditRecordsNameToolInputFields(t *testing.T) {
	testenv.SetState(t, t.TempDir())
	testenv.SetConfig(t, t.TempDir())
	t.Setenv("GUARDRAIL_CONFIG", "")
	dir := t.TempDir()
	raw, _ := json.Marshal(map[string]any{
		"hook_event_name": "PreToolUse", "session_id": "k1", "cwd": dir, "turn_id": "t", "tool_use_id": "u",
		"model": "m", "permission_mode": "default", "transcript_path": nil,
		"tool_name": "Bash", "tool_input": map[string]any{"command": "ls", "workdir": "C:/secret-looking/value", "timeout_ms": 1000},
	})
	var out, errb bytes.Buffer
	run([]string{"hook", "codex"}, bytes.NewReader(raw), &out, &errb)
	rec := lastAuditRecord(t)
	if want := []string{"command", "timeout_ms", "workdir"}; !reflect.DeepEqual(rec.InputKeys, want) {
		t.Fatalf("input_keys = %v, want %v (record %+v)", rec.InputKeys, want, rec)
	}
	line, _ := json.Marshal(rec)
	if strings.Contains(string(line), "secret-looking") {
		t.Fatalf("a tool_input value leaked into the audit record: %s", line)
	}
}

// The doctor line for Codex on Windows said dispatch was not observed
// (openai/codex#24453). On 0.159 dispatch works and guardrail fails closed on
// every allowed command instead; the line must say that.
func TestWindowsCodexPlaneStatusNamesTheCurrentBlocker(t *testing.T) {
	state := codexWindowsPlaneState
	if !strings.HasPrefix(state, "guardrail hooks registered, unenforced") {
		t.Fatalf("state lost its classification prefix: %q", state)
	}
	for _, want := range []string{"#454", "runs PreToolUse hooks", "fails closed"} {
		if !strings.Contains(state, want) {
			t.Errorf("state lacks %q: %q", want, state)
		}
	}
	if strings.Contains(state, "dispatch not observed") {
		t.Errorf("state still says dispatch is not observed: %q", state)
	}
}
