// Package engine normalizes attempted tool calls and evaluates them against a policy.
package engine

import (
	"encoding/json"
	"strings"

	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
)

// ToolCall is a plane-agnostic view of one attempted tool call.
type ToolCall struct {
	Plane          string // "claude", "opencode", "antigravity"
	Event          string // "pre" or "post"
	Tool           string // normalized tool name, e.g. "Bash", "Read", "Edit", "Write"
	NativeTool     string // original plane tool name for model-facing action guidance
	ContractTool   string // canonical native identity matched by the plane contract; empty when unclassified
	Capability     policy.Capability
	URL            string
	InputShape     string
	Command        string // shell command, when the tool is a shell
	Paths          []string
	Arguments      json.RawMessage // complete native argument payload when the plane exposes it
	SessionID      string
	CallID         string // plane-native per-call identity when the plane exposes one
	HostApproved   bool   // host-owned dialog approval evidence supplied by our adapter
	CWD            string
	RepoRoot       string // git top-level for CWD, or CWD if not a repo
	Raw            json.RawMessage
	PermittedRoots []string // plane-owned writable roots for this call (e.g. Antigravity session brain dir)

	// DegradedAllows carries adapter-reported records of calls that were
	// allowed locally while the engine was unreachable (the B+ communication
	// valve): the engine was down, the ask channel stayed open, and these
	// reports restore the audit evidence the outage would otherwise lose.
	DegradedAllows []DegradedAllowReport
}

// DegradedAllowReport is one adapter-reported degraded allow. The engine
// validates eligibility and boundedness on parse and writes each report as
// an audit record tagged Transport "plugin-degraded".
type DegradedAllowReport struct {
	Tool   string `json:"tool"`
	CallID string `json:"call_id,omitempty"`
	TS     string `json:"ts"`
}

func (tc ToolCall) IsBash() bool {
	return strings.EqualFold(tc.Tool, "bash") || tc.Command != ""
}
