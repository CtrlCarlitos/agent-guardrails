package adapter

import (
	"strings"
	"testing"
)

// #559: Claude Code reports the session's permission posture on every
// hook payload. bypassPermissions and auto mean the host answers permission
// asks itself, so the adapter flags them and the engine denies asks instead
// of handing the host a question it will rubber-stamp (#151: auto mode was
// the live evidence on #555, and Claude Code reports it as "auto"). Other
// modes leave the flag unset — acceptEdits and plan do not auto-approve
// tool asks, and dontAsk denies them itself.
func TestParseClaudeReadsPermissionMode(t *testing.T) {
	payload := func(mode string) string {
		return `{"session_id":"s","cwd":"/repo","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"ls"},"permission_mode":"` + mode + `"}`
	}
	for _, mode := range []string{"bypassPermissions", "auto"} {
		tc, err := ParseClaude(strings.NewReader(payload(mode)))
		if err != nil {
			t.Fatal(err)
		}
		if !tc.HostAutoApproves {
			t.Fatalf("permission_mode %q must set HostAutoApproves", mode)
		}
	}
	for _, mode := range []string{"default", "acceptEdits", "plan", "dontAsk", "Auto", ""} {
		tc, err := ParseClaude(strings.NewReader(payload(mode)))
		if err != nil {
			t.Fatal(err)
		}
		if tc.HostAutoApproves {
			t.Fatalf("permission_mode %q must not set HostAutoApproves", mode)
		}
	}
	tc, err := ParseClaude(strings.NewReader(`{"session_id":"s","cwd":"/repo","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"ls"}}`))
	if err != nil {
		t.Fatal(err)
	}
	if tc.HostAutoApproves {
		t.Fatal("absent permission_mode must not set HostAutoApproves")
	}
}
