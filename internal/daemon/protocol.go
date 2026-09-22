package daemon

import (
	"errors"

	"github.com/CtrlCarlitos/agent-guardrails/internal/engine"
	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
)

var (
	ErrServerClosed     = errors.New("daemon server closed")
	ErrMalformedRequest = errors.New("malformed daemon request")
)

// Request is sent from plane adapters to the resident daemon over IPC.
type Request struct {
	Action   string           `json:"action"`              // "evaluate", "shutdown", "ping"
	ToolCall *engine.ToolCall `json:"tool_call,omitempty"` // populated when Action == "evaluate"
}

// Response is returned from the resident daemon to the caller over IPC.
type Response struct {
	Status  string          `json:"status"`            // "ok", "error", "shutting_down"
	Verdict *policy.Verdict `json:"verdict,omitempty"` // populated on successful evaluation
	Error   string          `json:"error,omitempty"`   // populated on error
	Version string          `json:"version,omitempty"` // populated on ping
}
