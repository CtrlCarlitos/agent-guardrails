package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/CtrlCarlitos/agent-guardrails/internal/testenv"
)

func TestWindowsCodexHookExplainsDottedCollaborationDelegation(t *testing.T) {
	testenv.SetHome(t, t.TempDir())
	testenv.SetConfig(t, t.TempDir())
	testenv.SetState(t, t.TempDir())
	t.Setenv("GUARDRAIL_CONFIG", "")
	raw, err := json.Marshal(map[string]any{
		"hook_event_name": "PreToolUse",
		"session_id":      "fixture",
		"cwd":             t.TempDir(),
		"tool_name":       "collaboration.spawn_agent",
		"tool_input":      map[string]any{"task_name": "probe", "message": "work"},
	})
	if err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	if code := run([]string{"hook", "codex"}, bytes.NewReader(raw), &out, &errb); code != 2 || out.Len() != 0 {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, out.String(), errb.String())
	}
	for _, want := range []string{"guardrail: policy denial:", "perform the work yourself"} {
		if !strings.Contains(errb.String(), want) {
			t.Fatalf("stderr=%q, want %q", errb.String(), want)
		}
	}
	if strings.Contains(errb.String(), "unclassified native tool") {
		t.Fatalf("dotted collaboration tool fell through to unknown classification: %q", errb.String())
	}
}
