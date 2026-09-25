package adapter

import (
	"encoding/json"
	"errors"
	"io"
	"strings"
	"time"

	"github.com/CtrlCarlitos/agent-guardrails/internal/engine"
	"github.com/CtrlCarlitos/agent-guardrails/internal/planecontract"
	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
)

// Adapter contract mirrored by MAX_OPENCODE_HOOK_ENVELOPE_BYTES in opencode_plugin.js.
const maxOpencodeHookEnvelopeBytes = 8 << 20

var errOpencodeHookEnvelopeTooLarge = errors.New("OpenCode hook envelope exceeds 8 MiB")

type opencodePayload struct {
	SessionID      string                       `json:"session_id"`
	Event          string                       `json:"event"`
	Tool           string                       `json:"tool"`
	CallID         string                       `json:"call_id"`
	HostApproved   bool                         `json:"host_approved"`
	Command        string                       `json:"command"`
	Paths          []string                     `json:"paths"`
	CWD            string                       `json:"cwd"`
	Arguments      json.RawMessage              `json:"arguments"`
	DegradedAllows []engine.DegradedAllowReport `json:"degraded_allows,omitempty"`
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
	var mcpPaths []string
	spec, known := planecontract.OpencodeTool(p.Tool)
	if !known || spec.Capability == policy.CapabilityDeny {
		// Known MCP families are typed with projected paths (ADR-0017),
		// outranking the mcp/custom prefix deny; everything else stays
		// Unknown and the Engine asks.
		if mcp, ok := planecontract.MatchMCPTool(p.Tool); ok {
			spec = planecontract.ToolSpec{NativeTool: p.Tool, Tool: mcp.Tool, Capability: mcp.Capability}
			known = true
			mcpPaths = projectMCPPaths(mcp, p.Arguments)
		} else if !known {
			spec = planecontract.ToolSpec{NativeTool: p.Tool, Tool: p.Tool, Capability: policy.CapabilityUnknown}
		}
	}
	tc := engine.ToolCall{
		Plane:        "opencode",
		Event:        event,
		Tool:         spec.Tool,
		NativeTool:   p.Tool,
		Capability:   spec.Capability,
		Command:      p.Command,
		Paths:        p.Paths,
		Arguments:    p.Arguments,
		SessionID:    p.SessionID,
		CallID:       p.CallID,
		HostApproved: p.HostApproved,
		CWD:          p.CWD,
		Raw:          raw,
	}
	if tc.Capability == policy.CapabilityCommand {
		tc.InputShape = "command"
	}
	if tc.Capability == policy.CapabilityReadDiscovery || tc.Capability == policy.CapabilityMutation {
		tc.InputShape = "path"
	}
	if len(mcpPaths) > 0 {
		tc.Paths = append(tc.Paths, mcpPaths...)
	}
	if p.Tool == "apply_patch" {
		var input struct {
			Patch string `json:"patch"`
		}
		if err := json.Unmarshal(p.Arguments, &input); err != nil {
			return engine.ToolCall{}, err
		}
		tc.Paths = append(tc.Paths, patchPaths(input.Patch)...)
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
	tc.NativeWebResearch = nativeResearchCall(tc)
	tc.DegradedAllows = sanitizeDegradedAllows(p.DegradedAllows)
	return tc, nil
}

// sanitizeDegradedAllows keeps only contract-eligible, bounded, well-formed
// reports: an adapter must never land audit records for tools outside the
// DegradedAllow contract, and the batch is capped so a reporting loop
// cannot bloat the audit log.
func sanitizeDegradedAllows(reports []engine.DegradedAllowReport) []engine.DegradedAllowReport {
	kept := make([]engine.DegradedAllowReport, 0, len(reports))
	for _, report := range reports {
		if len(kept) >= 32 {
			break
		}
		if report.Tool == "" || len(report.Tool) > 64 || len(report.CallID) > 128 {
			continue
		}
		if !planecontract.DegradedAllow("opencode", report.Tool) && !planecontract.FloorFallback("opencode", report.Tool) {
			continue
		}
		if _, err := time.Parse(time.RFC3339, report.TS); err != nil {
			continue
		}
		kept = append(kept, report)
	}
	return kept
}

func EmitOpencode(v policy.Verdict, tc engine.ToolCall, stdout, stderr io.Writer) int {
	if v.Decision == policy.Complete {
		payload := map[string]any{"decision": "deny", "operator_action": v.OperatorAction, "request_id": v.RequestID, "status": "pending", "approval_url": v.ApprovalURL}
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

// patchPaths extracts the file paths named by an apply_patch payload
// (*** Update File:, *** Add File:, *** Delete File:). Unparseable patches
// yield no paths, and the engine fails closed on a path capability without
// paths.
func patchPaths(patch string) []string {
	var paths []string
	for _, line := range strings.Split(patch, "\n") {
		for _, header := range []string{"*** Update File: ", "*** Add File: ", "*** Delete File: "} {
			if strings.HasPrefix(line, header) {
				if p := strings.TrimSpace(strings.TrimPrefix(line, header)); p != "" {
					paths = append(paths, p)
				}
			}
		}
	}
	return paths
}
