package adapter

import (
	"encoding/json"
	"io"

	"github.com/CtrlCarlitos/agent-guardrails/internal/engine"
	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
)

type antigravityArgs struct {
	CommandLine  string `json:"CommandLine"`
	Cwd          string `json:"Cwd"`
	AbsolutePath string `json:"AbsolutePath"`
	TargetFile   string `json:"TargetFile"`
}

type antigravityToolCall struct {
	Name string          `json:"name"`
	Args antigravityArgs `json:"args"`
}

type antigravityPayload struct {
	ConversationID string              `json:"conversationId"`
	ToolCall       antigravityToolCall `json:"toolCall"`
	WorkspacePaths []string            `json:"workspacePaths"`
}

func ParseAntigravity(phase string, r io.Reader) (engine.ToolCall, error) {
	raw, err := io.ReadAll(r)
	if err != nil {
		return engine.ToolCall{}, err
	}
	var p antigravityPayload
	if err := json.Unmarshal(raw, &p); err != nil {
		return engine.ToolCall{}, err
	}

	event := "pre"
	if phase == "post" {
		event = "post"
	}

	cwd := p.ToolCall.Args.Cwd
	if cwd == "" && len(p.WorkspacePaths) > 0 {
		cwd = p.WorkspacePaths[0]
	}

	var paths []string
	if p.ToolCall.Args.AbsolutePath != "" {
		paths = []string{p.ToolCall.Args.AbsolutePath}
	} else if p.ToolCall.Args.TargetFile != "" {
		paths = []string{p.ToolCall.Args.TargetFile}
	}

	tc := engine.ToolCall{
		Plane:     "antigravity",
		Event:     event,
		Tool:      normalizeAntigravityTool(p.ToolCall.Name),
		Command:   p.ToolCall.Args.CommandLine,
		Paths:     paths,
		SessionID: p.ConversationID,
		CWD:       cwd,
		Raw:       raw,
	}
	tc.RepoRoot = repoRoot(cwd)
	return tc, nil
}

func normalizeAntigravityTool(name string) string {
	switch name {
	case "run_command":
		return "Bash"
	case "view_file":
		return "Read"
	case "write_to_file":
		return "Write"
	case "replace_file_content", "multi_replace_file_content":
		return "Edit"
	default:
		return name
	}
}

// EmitAntigravity is defined in Task 3 — declared here only as a forward
// reference in this doc comment for readers; the real function lives in
// this same file once Task 3 lands.
var _ = policy.Allow // placeholder import anchor removed once EmitAntigravity (Task 3) uses the policy package
