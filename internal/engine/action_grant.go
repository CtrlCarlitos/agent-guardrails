package engine

import (
	"encoding/json"
	"path/filepath"

	"github.com/CtrlCarlitos/agent-guardrails/internal/actiongrant"
	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
)

// ExactGrantAction binds only supported, pre-execution Codex Asks. Unknown
// capabilities and post-edit findings cannot mint an approval request.
func ExactGrantAction(tc ToolCall, v policy.Verdict) (actiongrant.Action, bool) {
	a := actiongrant.Action{}
	if tc.Plane != "codex" || tc.Event != "pre" || v.Decision != policy.Ask || policy.NeverGrantable(v.RuleID) ||
		tc.RepoRoot == "" || tc.CWD == "" || tc.SessionID == "" {
		return a, false
	}
	a = actiongrant.Action{Plane: tc.Plane, Session: tc.SessionID, Repo: filepath.Clean(tc.RepoRoot), CWD: filepath.Clean(tc.CWD), Tool: tc.Tool, Rule: v.RuleID, Paths: append([]string(nil), tc.Paths...)}
	switch {
	case tc.Capability == policy.CapabilityCommand && tc.Tool == "Bash" && tc.Command != "":
		a.Kind = "command"
		a.Text = tc.Command
	case tc.Capability == policy.CapabilityMutation && tc.ContractTool == "apply_patch" && len(tc.Paths) > 0:
		a.Tool = "apply_patch"
		var input struct {
			Command string `json:"command"`
		}
		if json.Unmarshal(tc.Arguments, &input) != nil || input.Command == "" {
			return actiongrant.Action{}, false
		}
		a.Kind = "patch"
		a.Text = input.Command
	default:
		return actiongrant.Action{}, false
	}
	return a, true
}
