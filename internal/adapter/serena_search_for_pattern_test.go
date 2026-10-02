package adapter

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/CtrlCarlitos/agent-guardrails/internal/engine"
	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
)

// #510: `doctor --coverage codex --mcp` (#463) found serena's
// search_for_pattern uncontracted on Codex: a content search like Grep that
// ran under unknown_tool_posture. It is now a read-discovery tool scoped by
// relative_path (default: the working directory) and by paths_include_glob,
// so a search aimed at a secret meets the path rules.
func TestSerenaSearchForPatternIsContracted(t *testing.T) {
	pol, err := policy.LoadBase()
	if err != nil {
		t.Fatal(err)
	}
	repo := t.TempDir()
	for _, tc := range []struct {
		args    map[string]any
		allowed bool
	}{
		{map[string]any{"substring_pattern": "func main"}, true},
		{map[string]any{"substring_pattern": "TODO", "relative_path": "internal"}, true},
		{map[string]any{"substring_pattern": "x", "paths_include_glob": "**/*.go"}, true},
		{map[string]any{"substring_pattern": "PRIVATE", "relative_path": "/home/u/.ssh"}, false},
		{map[string]any{"substring_pattern": "KEY", "paths_include_glob": "**/.env"}, false},
		{map[string]any{"substring_pattern": "KEY", "paths_include_glob": ".env"}, false},
	} {
		for _, plane := range []string{"claude", "codex"} {
			raw, _ := json.Marshal(map[string]any{"session_id": "s", "hook_event_name": "PreToolUse", "cwd": repo,
				"tool_name": "mcp__serena__search_for_pattern", "tool_input": tc.args})
			var call engine.ToolCall
			if plane == "claude" {
				call, err = ParseClaude(strings.NewReader(string(raw)))
			} else {
				call, err = ParseCodex(strings.NewReader(string(raw)))
			}
			if err != nil {
				t.Fatalf("%s %v: %v", plane, tc.args, err)
			}
			if call.Capability != policy.CapabilityReadDiscovery {
				t.Errorf("%s %v: capability %q, want read_discovery", plane, tc.args, call.Capability)
			}
			v := engine.Evaluate(call, pol)
			if got := v.Decision == policy.Allow; got != tc.allowed {
				t.Errorf("%s %v: %s %s; want allowed=%v", plane, tc.args, v.Decision, v.RuleID, tc.allowed)
			}
		}
	}
}
