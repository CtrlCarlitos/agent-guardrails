package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/CtrlCarlitos/agent-guardrails/internal/testenv"
)

// #512: the hook tells the Engine which release it is, so a session's
// `guardrail update <older>` is refused and `<newer>` is not.
func TestHookRefusesADowngradeOfTheRunningRelease(t *testing.T) {
	testenv.SetState(t, t.TempDir())
	t.Setenv("GUARDRAIL_CONFIG", "")
	old := version
	version = "v0.23.32-dev"
	t.Cleanup(func() { version = old })
	repo := t.TempDir()
	for cmd, wantExit := range map[string]int{
		"guardrail update v0.1.0-dev":  2,
		"guardrail update v0.24.0-dev": 0,
	} {
		payload, _ := json.Marshal(map[string]any{"session_id": "s1", "cwd": repo, "hook_event_name": "PreToolUse",
			"tool_name": "Bash", "tool_input": map[string]any{"command": cmd}})
		var out, errb bytes.Buffer
		code := run([]string{"hook", "claude"}, bytes.NewReader(payload), &out, &errb)
		if code != wantExit {
			t.Errorf("%s: exit %d, want %d; stdout %s stderr %s", cmd, code, wantExit, out.String(), errb.String())
		}
		if wantExit == 2 && !strings.Contains(errb.String(), "downgrade") {
			t.Errorf("%s: the deny does not say it is a downgrade: %s", cmd, errb.String())
		}
	}
}
