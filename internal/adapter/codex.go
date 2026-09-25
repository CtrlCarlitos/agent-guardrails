package adapter

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/CtrlCarlitos/agent-guardrails/internal/engine"
	"github.com/CtrlCarlitos/agent-guardrails/internal/planecontract"
	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
)

// ParseCodex consumes the native synchronous lifecycle-hook envelope (ADR-0014).
func ParseCodex(r io.Reader) (engine.ToolCall, error) {
	raw, err := io.ReadAll(io.LimitReader(r, (8<<20)+1))
	if err != nil {
		return engine.ToolCall{}, err
	}
	if len(raw) > 8<<20 {
		return engine.ToolCall{}, fmt.Errorf("Codex hook envelope exceeds 8 MiB")
	}
	var p struct {
		SessionID string          `json:"session_id"`
		CWD       string          `json:"cwd"`
		Event     string          `json:"hook_event_name"`
		Tool      string          `json:"tool_name"`
		Input     json.RawMessage `json:"tool_input"`
	}
	if err := json.Unmarshal(raw, &p); err != nil {
		return engine.ToolCall{}, err
	}
	event := map[string]string{"PreToolUse": "pre", "PostToolUse": "post", "SessionStart": "session-start"}[p.Event]
	if event == "" || !filepath.IsAbs(p.CWD) || p.SessionID == "" {
		return engine.ToolCall{}, fmt.Errorf("Codex hook requires a supported event, absolute cwd and session_id")
	}
	tc := engine.ToolCall{Plane: "codex", Event: event, CWD: p.CWD, RepoRoot: repoRoot(p.CWD), SessionID: p.SessionID, NativeTool: p.Tool, Arguments: p.Input, Raw: raw, InputShape: "opaque-object"}
	if event == "session-start" {
		return tc, nil
	}
	if p.Tool == "" {
		return engine.ToolCall{}, fmt.Errorf("Codex hook missing tool_name")
	}
	var input map[string]json.RawMessage
	if err := json.Unmarshal(p.Input, &input); err != nil || input == nil {
		return engine.ToolCall{}, fmt.Errorf("Codex tool_input must be an object")
	}
	spec, known := planecontract.CodexTool(p.Tool)
	if !known || spec.Capability == policy.CapabilityDeny {
		// Consult the shared registry before applying the MCP prefix deny,
		// exactly as OpenCode does. MCP path arguments are not native patch
		// or view_image inputs; project them with the shared registry helper.
		if mcp, ok := planecontract.MatchMCPTool(p.Tool); ok {
			tc.Tool, tc.Capability = mcp.Tool, mcp.Capability
			tc.ContractTool = "mcp:" + mcp.Family + "/" + mcp.Tool
			tc.Paths = projectMCPPaths(mcp, p.Input)
			if tc.Capability == policy.CapabilityReadDiscovery || tc.Capability == policy.CapabilityMutation {
				tc.InputShape = "path"
			}
			return tc, nil
		}
	}
	if !known {
		spec = planecontract.ToolSpec{NativeTool: p.Tool, Tool: p.Tool, Capability: policy.CapabilityUnknown}
	} else {
		tc.ContractTool = spec.NativeTool
	}
	tc.Tool, tc.Capability = spec.Tool, spec.Capability
	if tc.Tool == "web.run" {
		tc.Capability, tc.URL = codexWebCapability(input)
	}
	stringField := func(key string) (string, error) {
		var value string
		if len(input[key]) == 0 || string(input[key]) == "null" {
			return "", fmt.Errorf("Codex tool_input missing %s", key)
		}
		err := json.Unmarshal(input[key], &value)
		return value, err
	}
	switch tc.Capability {
	case policy.CapabilityCommand:
		tc.Command, err = stringField("command")
		tc.InputShape = "command"
	case policy.CapabilityMutation:
		var patch string
		patch, err = stringField("command")
		tc.InputShape = "patch"
		if err == nil {
			tc.Paths, err = codexPatchPaths(patch, p.CWD, event == "post")
			if err == nil && event == "post" && len(tc.Paths) == 0 {
				tc.Capability = policy.CapabilitySafeControl
			}
		}
	case policy.CapabilityReadDiscovery:
		var path string
		path, err = stringField("path")
		if path != "" {
			tc.Paths = []string{path}
		}
		tc.InputShape = "path"
	}
	if err != nil {
		return tc, err
	}
	return tc, nil
}

// Include move destinations as well as sources. Deleted files are evaluated
// before execution but omitted after execution so recipes never format them.
func codexPatchPaths(patch, cwd string, post bool) ([]string, error) {
	lines := strings.Split(strings.TrimSpace(patch), "\n")
	if len(lines) < 3 || lines[0] != "*** Begin Patch" || lines[len(lines)-1] != "*** End Patch" {
		return nil, fmt.Errorf("invalid Codex patch envelope")
	}
	var paths []string
	headers := 0
	for _, line := range lines[1 : len(lines)-1] {
		for _, header := range []string{"*** Add File: ", "*** Update File: ", "*** Delete File: ", "*** Move to: "} {
			if !strings.HasPrefix(line, header) {
				continue
			}
			headers++
			path := strings.TrimPrefix(line, header)
			if strings.TrimSpace(path) == "" {
				return nil, fmt.Errorf("empty Codex patch path")
			}
			if post && header == "*** Delete File: " {
				continue
			}
			if post && header == "*** Move to: " && len(paths) > 0 {
				paths = paths[:len(paths)-1]
			}
			if !filepath.IsAbs(path) {
				path = filepath.Join(cwd, path)
			}
			paths = append(paths, path)
		}
	}
	if headers == 0 {
		return nil, fmt.Errorf("Codex patch has no file operations")
	}
	return paths, nil
}

func EmitCodex(v policy.Verdict, event string, tc engine.ToolCall, stdout, stderr io.Writer) int {
	if v.Decision == policy.Allow {
		if event == "pre" && tc.Capability == policy.CapabilityCommand {
			if runtime.GOOS == "windows" {
				reason := "guardrail: cannot prove the Windows command shell; refusing to emit a POSIX updatedInput rewrite and failing closed"
				fmt.Fprintln(stderr, reason)
				if codexStructuredWindowsEnabled() {
					return emitCodexBlock("pre", reason, stdout)
				}
				return 2
			}
			cwd, err := filepath.EvalSymlinks(tc.CWD)
			if err != nil {
				fmt.Fprintln(stderr, "guardrail: cannot verify Codex working directory; failing closed")
				return 2
			}
			quoted := "'" + strings.ReplaceAll(cwd, "'", "'\"'\"'") + "'"
			command := "if [ \"$(pwd -P)\" != " + quoted + " ]; then printf '%s\\n' 'guardrail: Codex workdir differs from the evaluated directory. Use the session working directory and an explicit cd in the command so Guardrail can evaluate path changes.' >&2; exit 1; fi\n" + tc.Command
			payload := map[string]any{"hookSpecificOutput": map[string]any{"hookEventName": "PreToolUse", "permissionDecision": "allow", "updatedInput": map[string]any{"command": command}}}
			if err := json.NewEncoder(stdout).Encode(payload); err != nil {
				return 2
			}
		}
		return 0
	}
	reason := guidanceForModel(v, nativeAction(tc.NativeTool, tc.Arguments))
	if v.Decision == policy.Deny && tc.Tool == "write_stdin" {
		reason = "Guardrail denies write_stdin: Codex does not reliably run PreToolUse before delivering terminal input (ADR-0014). Do not send or retry input to the running process. Use a fresh, explicit non-interactive exec_command that can be reviewed before execution, or ask the operator to perform the interactive step outside this session; continue independent work."
	}
	if v.Decision == policy.Deny && tc.Tool == "functions.exec" {
		reason = "Guardrail denies functions.exec: composite tool indirection cannot guarantee mediation of every nested action. Do not retry through another wrapper. Invoke the required supported tools directly, then continue."
	}
	if v.Decision == policy.Deny && tc.Tool == "web.run" && tc.Capability == policy.CapabilityDeny {
		reason = "Guardrail cannot project this web.run request safely. Use a search-only request or open one explicit HTTP(S) URL per call; do not mix operations or use opaque result references. Continue independent work."
	}
	if v.Decision == policy.Ask {
		reason = "Guardrail requires operator authorization: " + sanitizeForModel(v.Reason) + ". Codex PreToolUse cannot request approval. Have the operator perform this exact action outside this session, or authorize the relevant policy through Guardrail; continue independent work. Do not retry based on conversational approval."
	}
	if v.Decision == policy.Complete {
		reason = fmt.Sprintf("Operator action pending: %s; request %s; open %s. Wait for completion before continuing this action.", v.OperatorAction, v.RequestID, v.ApprovalURL)
	}
	fmt.Fprintln(stderr, "guardrail: policy denial: "+reason)
	if codexStructuredWindowsEnabled() {
		return emitCodexBlock(event, reason, stdout)
	}
	return 2 // Native blocking status; never emit unsupported permissionDecision: ask.
}

func codexStructuredWindowsEnabled() bool {
	return runtime.GOOS == "windows" && os.Getenv("GUARDRAIL_CODEX_STRUCTURED_WINDOWS") == "1"
}

func emitCodexBlock(event, reason string, stdout io.Writer) int {
	var payload map[string]any
	switch event {
	case "pre":
		payload = map[string]any{"hookSpecificOutput": map[string]any{"hookEventName": "PreToolUse", "permissionDecision": "deny", "permissionDecisionReason": reason}}
	case "post":
		payload = map[string]any{"decision": "block", "reason": reason}
	default:
		return 2
	}
	if err := json.NewEncoder(stdout).Encode(payload); err != nil {
		return 2
	}
	return 0
}
