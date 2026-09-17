package adapter

import (
	"encoding/json"
	"errors"
	"io"

	"github.com/CtrlCarlitos/agent-guardrails/internal/engine"
	"github.com/CtrlCarlitos/agent-guardrails/internal/planecontract"
	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
)

// Adapter contract mirrored by MAX_OPENCODE_HOOK_ENVELOPE_BYTES in opencode_plugin.js.
const maxOpencodeHookEnvelopeBytes = 8 << 20

var errOpencodeHookEnvelopeTooLarge = errors.New("OpenCode hook envelope exceeds 8 MiB")

type opencodePayload struct {
	SessionID string          `json:"session_id"`
	Event     string          `json:"event"`
	Tool      string          `json:"tool"`
	Command   string          `json:"command"`
	Paths     []string        `json:"paths"`
	CWD       string          `json:"cwd"`
	Arguments json.RawMessage `json:"arguments"`
}

func ParseOpencode(r io.Reader) (engine.ToolCall, error) {
	raw, err := io.ReadAll(io.LimitReader(r, maxOpencodeHookEnvelopeBytes+1))
	if err != nil {
		return engine.ToolCall{}, err
	}
	if len(raw) > maxOpencodeHookEnvelopeBytes {
		return engine.ToolCall{}, errOpencodeHookEnvelopeTooLarge
	}
	var p opencodePayload
	if err := json.Unmarshal(raw, &p); err != nil {
		return engine.ToolCall{}, err
	}
	event := p.Event
	if event != "pre" && event != "post" {
		event = "pre"
	}
	spec, known := planecontract.OpencodeTool(p.Tool)
	if !known {
		spec = planecontract.ToolSpec{NativeTool: p.Tool, Tool: p.Tool, Capability: policy.CapabilityUnknown}
	}
	tc := engine.ToolCall{
		Plane:      "opencode",
		Event:      event,
		Tool:       spec.Tool,
		NativeTool: p.Tool,
		Capability: spec.Capability,
		Command:    p.Command,
		Paths:      p.Paths,
		Arguments:  p.Arguments,
		SessionID:  p.SessionID,
		CWD:        p.CWD,
		Raw:        raw,
	}
	if tc.Capability == policy.CapabilityCommand {
		tc.InputShape = "command"
	}
	if tc.Capability == policy.CapabilityReadDiscovery || tc.Capability == policy.CapabilityMutation {
		tc.InputShape = "path"
	}
	if tc.Capability == policy.CapabilityWebFetch {
		var input struct {
			URL string `json:"url"`
		}
		if err := json.Unmarshal(p.Arguments, &input); err != nil {
			return engine.ToolCall{}, err
		}
		tc.URL = input.URL
		tc.InputShape = "url"
	}
	if tc.Capability == policy.CapabilityWebSearch {
		tc.InputShape = "query"
	}
	if tc.InputShape == "" {
		tc.InputShape = "opaque-object"
	}
	tc.RepoRoot = repoRoot(p.CWD)
	return tc, nil
}

func EmitOpencode(v policy.Verdict, tc engine.ToolCall, stdout, stderr io.Writer) int {
	if v.Decision == policy.Complete {
		payload := map[string]any{"decision": "deny", "operator_action": v.OperatorAction, "request_id": v.RequestID, "status": "pending"}
		b, _ := json.Marshal(payload)
		stdout.Write(append(b, '\n'))
		return 2
	}
	payload := map[string]any{"decision": string(v.Decision), "reason": guidanceForModel(v, nativeAction(tc.NativeTool, tc.Arguments))}
	b, _ := json.Marshal(payload)
	stdout.Write(append(b, '\n'))
	if v.Decision == policy.Deny {
		return 2
	}
	return 0
}
