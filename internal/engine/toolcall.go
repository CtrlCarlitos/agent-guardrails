// Package engine normalizes attempted tool calls and evaluates them against a policy.
package engine

import (
	"encoding/json"
	"strings"
)

// ToolCall is a plane-agnostic view of one attempted tool call.
type ToolCall struct {
	Plane     string // "claude", "opencode", "antigravity"
	Event     string // "pre" or "post"
	Tool      string // normalized tool name, e.g. "Bash", "Read", "Edit", "Write"
	Command   string // shell command, when the tool is a shell
	Paths     []string
	SessionID string
	CWD       string
	RepoRoot  string // git top-level for CWD, or CWD if not a repo
	Raw       json.RawMessage
}

func (tc ToolCall) IsBash() bool {
	return strings.EqualFold(tc.Tool, "bash") || tc.Command != ""
}
