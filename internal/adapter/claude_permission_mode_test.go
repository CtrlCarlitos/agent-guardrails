package adapter

import (
	"strings"
	"testing"
)

// #559: Claude Code reports the session's permission posture on every
// hook payload. bypassPermissions means the host answers permission asks
// itself, so the adapter flags it and the engine denies asks instead of
// handing the host a question it will rubber-stamp. Other modes leave the
// flag unset — acceptEdits and plan do not auto-approve tool asks.
func TestParseClaudeReadsPermissionMode(t *testing.T) {
	payload := func(mode string) string {
		return `{"session_id":"s","cwd":"/repo","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"ls"},"permission_mode":"` + mode + `"}`
	}
	tc, err := ParseClaude(strings.NewReader(payload("bypassPermissions")))
	if err != nil {
		t.Fatal(err)
	}
	if !tc.HostAutoApproves {
		t.Fatal("bypassPermissions must set HostAutoApproves")
	}
	for _, mode := range []string{"default", "acceptEdits", "plan"} {
		tc, err := ParseClaude(strings.NewReader(payload(mode)))
		if err != nil {
			t.Fatal(err)
		}
		if tc.HostAutoApproves {
			t.Fatalf("permission_mode %q must not set HostAutoApproves", mode)
		}
	}
	tc, err = ParseClaude(strings.NewReader(`{"session_id":"s","cwd":"/repo","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"ls"}}`))
	if err != nil {
		t.Fatal(err)
	}
	if tc.HostAutoApproves {
		t.Fatal("absent permission_mode must not set HostAutoApproves")
	}
}
