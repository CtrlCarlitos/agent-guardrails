package adapter

import (
	"encoding/json"
	"io"
	"strings"

	"github.com/CtrlCarlitos/agent-guardrails/internal/engine"
	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
)

type opencodePayload struct {
	SessionID string   `json:"session_id"`
	Event     string   `json:"event"`
	Tool      string   `json:"tool"`
	Command   string   `json:"command"`
	Paths     []string `json:"paths"`
	CWD       string   `json:"cwd"`
}

func ParseOpencode(r io.Reader) (engine.ToolCall, error) {
	raw, err := io.ReadAll(r)
	if err != nil {
		return engine.ToolCall{}, err
	}
	var p opencodePayload
	if err := json.Unmarshal(raw, &p); err != nil {
		return engine.ToolCall{}, err
	}
	event := p.Event
	if event != "pre" && event != "post" {
		event = "pre"
	}
	tc := engine.ToolCall{
		Plane:     "opencode",
		Event:     event,
		Tool:      normalizeOpencodeTool(p.Tool),
		Command:   p.Command,
		Paths:     p.Paths,
		SessionID: p.SessionID,
		CWD:       p.CWD,
		Raw:       raw,
	}
	tc.RepoRoot = repoRoot(p.CWD)
	return tc, nil
}

func normalizeOpencodeTool(t string) string {
	switch strings.ToLower(t) {
	case "bash":
		return "Bash"
	case "read":
		return "Read"
	case "edit":
		return "Edit"
	case "write":
		return "Write"
	case "list":
		return "List"
	default:
		return t
	}
}

func EmitOpencode(v policy.Verdict, stdout, stderr io.Writer) int {
	payload := map[string]any{"decision": string(v.Decision), "reason": sanitizeForModel(v.Reason)}
	b, _ := json.Marshal(payload)
	stdout.Write(append(b, '\n'))
	if v.Decision == policy.Deny {
		return 2
	}
	return 0
}
