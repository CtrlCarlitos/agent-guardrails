// Package adapter translates each plane's native hook payload/response and the engine.
package adapter

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/CtrlCarlitos/agent-guardrails/internal/engine"
	"github.com/CtrlCarlitos/agent-guardrails/internal/planecontract"
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
	var native struct {
		ToolInput json.RawMessage `json:"tool_input"`
	}
	if err := json.Unmarshal(raw, &native); err != nil {
		return engine.ToolCall{}, err
	}
	event := "pre"
	switch p.HookEventName {
	case "PostToolUse":
		event = "post"
	case "SessionStart":
		event = "session-start"
	}
	var mcpPaths []string
	isMCP := false
	spec, known := planecontract.ClaudeTool(p.ToolName)
	if strings.HasPrefix(p.ToolName, "mcp__") {
		// Known MCP families are typed with projected paths (ADR-0017),
		// outranking the mcp__ prefix rule; unknown families keep its
		// External posture.
		if mcp, ok := planecontract.MatchMCPTool(p.ToolName); ok {
			spec = planecontract.ToolSpec{NativeTool: p.ToolName, Tool: mcp.Tool, Capability: mcp.Capability}
			known = true
			isMCP = true
			mcpPaths = projectMCPPaths(mcp, native.ToolInput)
		}
	}
	if !known {
		spec = planecontract.ToolSpec{NativeTool: p.ToolName, Tool: p.ToolName, Capability: policy.CapabilityUnknown}
	}
	tc := engine.ToolCall{
		Plane:      "claude",
		Event:      event,
		Tool:       spec.Tool,
		NativeTool: p.ToolName,
		Capability: spec.Capability,
		Command:    p.ToolInput.Command,
		SessionID:  p.SessionID,
		CWD:        p.CWD,
		Arguments:  native.ToolInput,
		Raw:        raw,
	}
	var input map[string]any
	if len(native.ToolInput) != 0 {
		if err := json.Unmarshal(native.ToolInput, &input); err != nil {
			return engine.ToolCall{}, err
		}
	}
	if tc.Capability == policy.CapabilityCommand {
		tc.InputShape = "command"
	}
	if tc.Capability == policy.CapabilityReadDiscovery || tc.Capability == policy.CapabilityMutation {
		if isMCP {
			tc.Paths = mcpPaths
		} else {
			tc.Paths = claudeInputPaths(input)
		}
		tc.InputShape = "path"
	}
	if tc.Capability == policy.CapabilityWebFetch {
		if url, ok := input["url"].(string); ok {
			tc.URL = url
		}
		tc.InputShape = "url"
	}
	if tc.InputShape == "" {
		tc.InputShape = "opaque-object"
	}
	tc.RepoRoot = repoRoot(p.CWD)
	return tc, nil
}

var claudePathKeys = []string{"file_path", "path", "notebook_path"}

// claudeInputPaths collects every path a path-capability call names: each
// top-level path key, plus per-entry path keys inside an `edits` list
// (MultiEdit shape). Order is preserved and duplicates dropped, so the engine
// evaluates every distinct path exactly once; empty values are skipped and
// a call naming none fails closed in the engine.
func claudeInputPaths(input map[string]any) []string {
	var paths []string
	seen := make(map[string]bool)
	add := func(v any) {
		if path, ok := v.(string); ok && path != "" && !seen[path] {
			seen[path] = true
			paths = append(paths, path)
		}
	}
	for _, key := range claudePathKeys {
		add(input[key])
	}
	if edits, ok := input["edits"].([]any); ok {
		for _, entry := range edits {
			edit, ok := entry.(map[string]any)
			if !ok {
				continue
			}
			for _, key := range claudePathKeys {
				add(edit[key])
			}
		}
	}
	return paths
}

func repoRoot(cwd string) string {
	if root, ok := policy.FindRepoRoot(cwd); ok {
		return root
	}
	return cwd
}

func nativeAction(tool string, arguments any) string {
	b, err := json.Marshal(arguments)
	if err != nil {
		return tool
	}
	return tool + " " + string(b)
}

func EmitClaude(v policy.Verdict, event string, tc engine.ToolCall, stdout, stderr io.Writer) int {
	switch v.Decision {
	case policy.Complete:
		guidance := operatorActionGuidance(v)
		output := map[string]any{
			"hookEventName":            "PreToolUse",
			"permissionDecision":       "deny",
			"permissionDecisionReason": guidance,
			"additionalContext":        guidance,
			"operator_action":          v.OperatorAction,
			"request_id":               v.RequestID,
		}
		if v.ApprovalURL != "" {
			output["approval_url"] = v.ApprovalURL
		}
		b, _ := json.Marshal(map[string]any{"hookSpecificOutput": output})
		stdout.Write(append(b, '\n'))
		return 0
	case policy.Deny:
		fmt.Fprintf(stderr, "guardrail: %s\n", guidanceForModel(v, nativeAction(tc.NativeTool, tc.Arguments)))
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
				"permissionDecisionReason": guidanceForModel(v, nativeAction(tc.NativeTool, tc.Arguments)),
			},
		}
		b, _ := json.Marshal(payload)
		stdout.Write(append(b, '\n'))
		return 0
	default:
		return 0
	}
}

// operatorActionGuidance is the model-facing text for a brokered operator
// action. Claude Code shows the model only additionalContext and the reason,
// never the bare operator_action/request_id fields, so the text must carry
// the request identity, the approval URL, and what happens next: the broker
// applies the action on approval, so the command is never re-run.
func operatorActionGuidance(v policy.Verdict) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Operator approval requested for %s (request %s).", v.OperatorAction, v.RequestID)
	if v.ApprovalURL != "" {
		fmt.Fprintf(&b, " Approval URL: %s.", v.ApprovalURL)
	}
	b.WriteString(" The operator approves with their passkey and the action is applied at that moment; do not re-run this command (that files a new request). Continue other work meanwhile and use the granted capability once they confirm.")
	return sanitizeForModel(b.String())
}

func PostureText(waivers []string, warnings []string) string {
	var b strings.Builder
	b.WriteString("guardrail is active. Operate autonomously on routine development steps — " +
		"do not stop to ask conversational permission; guardrail enforces destructive-command " +
		"and secret-access boundaries deterministically. Pause only when guardrail returns an " +
		"explicit block/ask, or you face genuine ambiguity outside its scope.")
	waivers = sanitizeWaiverIDs(waivers)
	if len(waivers) > 0 {
		b.WriteString("\n\nActive policy waivers in this repo (these rules are OFF): " + strings.Join(waivers, ", "))
	}
	for _, w := range sanitizeWarnings(warnings) {
		b.WriteString("\n\n" + w)
	}
	return b.String()
}

// PlaneLifecycleLine describes the plane's Guardrail integration as recorded
// in its global config, so the SessionStart posture reflects lifecycle state
// (registered, drifted, or absent) rather than only the fact that this hook
// happened to fire. The recovery step is always the operator's terminal
// command, never an in-session edit (self-config is P5-denied).
func PlaneLifecycleLine(plane, state string, unmarkedGroups int) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s plane lifecycle: %s.", planeDisplayName(plane), sanitizeForModel(state))
	switch {
	case strings.HasPrefix(state, "guardrail hook registered") || strings.HasPrefix(state, "guardrail integration registered"):
		if unmarkedGroups > 0 {
			fmt.Fprintf(&b, " %d unmarked legacy guardrail hook group%s remain (drift): the operator should run `guardrail plane enable %s` to absorb %s.",
				unmarkedGroups, plural(unmarkedGroups), plane, pronoun(unmarkedGroups))
		}
	default:
		fmt.Fprintf(&b, " This session is guarded by the hook that launched it, but future sessions may not be: tell the operator to run `guardrail plane enable %s`.", plane)
	}
	return b.String()
}

func planeDisplayName(plane string) string {
	switch plane {
	case "claude":
		return "Claude"
	case "opencode":
		return "OpenCode"
	case "antigravity":
		return "Antigravity"
	}
	return plane
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

func pronoun(n int) string {
	if n == 1 {
		return "it"
	}
	return "them"
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
