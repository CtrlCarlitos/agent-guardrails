// Package adapter translates each plane's native hook payload/response and the engine.
package adapter

import (
	"encoding/json"
	"io"
	"os/exec"
	"strings"

	"github.com/CtrlCarlitos/agent-guardrails/internal/engine"
)

type claudePayload struct {
	SessionID     string `json:"session_id"`
	CWD           string `json:"cwd"`
	HookEventName string `json:"hook_event_name"`
	ToolName      string `json:"tool_name"`
	ToolInput     struct {
		Command  string `json:"command"`
		FilePath string `json:"file_path"`
	} `json:"tool_input"`
}

func ParseClaude(r io.Reader) (engine.ToolCall, error) {
	raw, err := io.ReadAll(r)
	if err != nil {
		return engine.ToolCall{}, err
	}
	var p claudePayload
	if err := json.Unmarshal(raw, &p); err != nil {
		return engine.ToolCall{}, err
	}
	event := "pre"
	if p.HookEventName == "PostToolUse" {
		event = "post"
	}
	tc := engine.ToolCall{
		Plane:     "claude",
		Event:     event,
		Tool:      p.ToolName,
		Command:   p.ToolInput.Command,
		SessionID: p.SessionID,
		CWD:       p.CWD,
		Raw:       raw,
	}
	if p.ToolInput.FilePath != "" {
		tc.Paths = []string{p.ToolInput.FilePath}
	}
	tc.RepoRoot = repoRoot(p.CWD)
	return tc, nil
}

func repoRoot(cwd string) string {
	if cwd == "" {
		return ""
	}
	out, err := exec.Command("git", "-C", cwd, "rev-parse", "--show-toplevel").Output()
	if err != nil {
		return cwd
	}
	return strings.TrimSpace(string(out))
}
