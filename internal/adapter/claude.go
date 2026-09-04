// Package adapter translates each plane's native hook payload/response and the engine.
package adapter

import (
	"encoding/json"
	"fmt"
	"io"
	"os/exec"
	"strings"

	"github.com/CtrlCarlitos/agent-guardrails/internal/engine"
	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
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
	switch p.HookEventName {
	case "PostToolUse":
		event = "post"
	case "SessionStart":
		event = "session-start"
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

func EmitClaude(v policy.Verdict, event string, stdout, stderr io.Writer) int {
	switch v.Decision {
	case policy.Deny:
		fmt.Fprintf(stderr, "guardrail: %s\n", v.Reason)
		return 2
	case policy.Ask:
		hookEvent := "PreToolUse"
		if event == "post" {
			hookEvent = "PostToolUse"
		}
		payload := map[string]any{
			"hookSpecificOutput": map[string]any{
				"hookEventName":            hookEvent,
				"permissionDecision":       "ask",
				"permissionDecisionReason": v.Reason,
			},
		}
		b, _ := json.Marshal(payload)
		stdout.Write(append(b, '\n'))
		return 0
	default:
		return 0
	}
}

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
