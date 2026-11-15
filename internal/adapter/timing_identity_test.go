package adapter

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestHookTimingPreservesNativeToolUseID(t *testing.T) {
	raw, _ := json.Marshal(map[string]any{"session_id": "timing-session", "tool_use_id": "native-call-530", "hook_event_name": "PreToolUse", "cwd": t.TempDir(), "tool_name": "Bash", "tool_input": map[string]any{"command": "git status"}})
	for _, host := range []string{"claude", "codex"} {
		t.Run(host, func(t *testing.T) {
			parse := ParseClaude
			if host == "codex" {
				parse = ParseCodex
			}
			tc, err := parse(strings.NewReader(string(raw)))
			if err != nil {
				t.Fatal(err)
			}
			if tc.CallID != "native-call-530" {
				t.Fatalf("CallID=%q, want native tool_use_id", tc.CallID)
			}
		})
	}
}
