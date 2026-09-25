package adapter

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/CtrlCarlitos/agent-guardrails/internal/engine"
	"github.com/CtrlCarlitos/agent-guardrails/internal/planecontract"
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

type antigravityPathSchema struct {
	key     string
	allowed map[string]struct{}
}

var antigravityPathSchemas = map[string]antigravityPathSchema{
	"view_file":                  {"AbsolutePath", allowedFields("AbsolutePath", "StartLine", "EndLine", "ContentOffset", "IsSkillFile")},
	"write_to_file":              {"TargetFile", allowedFields("TargetFile", "Overwrite", "CodeContent", "Description", "IsArtifact", "ArtifactMetadata")},
	"replace_file_content":       {"TargetFile", allowedFields("TargetFile", "Instruction", "Description", "AllowMultiple", "TargetContent", "ReplacementContent", "StartLine", "EndLine", "TargetLintErrorIds")},
	"multi_replace_file_content": {"TargetFile", allowedFields("TargetFile", "Instruction", "Description", "ReplacementChunks", "TargetLintErrorIds", "ArtifactMetadata")},
	"list_dir":                   {"DirectoryPath", allowedFields("DirectoryPath")},
	"find_by_name":               {"SearchDirectory", allowedFields("SearchDirectory", "Pattern", "Type", "Excludes", "Extensions", "FullPath", "MaxDepth")},
	"grep_search":                {"SearchPath", allowedFields("SearchPath", "Query", "IsRegex", "CaseInsensitive", "Includes", "MatchPerLine")},
}

func allowedFields(fields ...string) map[string]struct{} {
	allowed := make(map[string]struct{}, len(fields)+2)
	allowed["toolAction"] = struct{}{}
	allowed["toolSummary"] = struct{}{}
	for _, field := range fields {
		allowed[field] = struct{}{}
	}
	return allowed
}

func documentedAntigravityPaths(tool string, input map[string]any) ([]string, error) {
	if tool == "multi_replace_file_content" {
		return extractMultiReplacePaths(input)
	}

	switch tool {
	case "notebook_edit":
		for _, key := range []string{"NotebookPath", "TargetFile", "FilePath", "Path"} {
			if p, ok := input[key].(string); ok && p != "" {
				return []string{p}, nil
			}
		}
		return nil, fmt.Errorf("notebook_edit requires NotebookPath")
	case "sed_file":
		for _, key := range []string{"TargetFile", "FilePath", "Path", "AbsolutePath"} {
			if p, ok := input[key].(string); ok && p != "" {
				return []string{p}, nil
			}
		}
		return nil, fmt.Errorf("sed_file requires TargetFile or FilePath")
	case "delete_knowledge":
		for _, key := range []string{"PathToDelete", "TargetFile", "FilePath", "Path"} {
			if p, ok := input[key].(string); ok && p != "" {
				return []string{p}, nil
			}
		}
		return nil, fmt.Errorf("delete_knowledge requires PathToDelete")
	}

	schema, ok := antigravityPathSchemas[tool]
	if !ok {
		return nil, nil
	}
	for key := range input {
		if _, ok := schema.allowed[key]; !ok {
			return nil, fmt.Errorf("%s argument %q is not documented", tool, key)
		}
	}

	path, ok := input[schema.key].(string)
	if !ok || path == "" {
		return nil, fmt.Errorf("%s requires string argument %q", tool, schema.key)
	}
	return []string{path}, nil
}

func extractMultiReplacePaths(input map[string]any) ([]string, error) {
	var paths []string
	seen := make(map[string]bool)
	addPath := func(p string) {
		p = strings.TrimSpace(p)
		if p != "" && !seen[p] {
			seen[p] = true
			paths = append(paths, p)
		}
	}

	if target, ok := input["TargetFile"].(string); ok && target != "" {
		addPath(target)
	}

	if chunks, ok := input["ReplacementChunks"].([]any); ok {
		allowedChunkKeys := allowedFields("TargetFile", "FilePath", "Path", "TargetContent", "ReplacementContent", "StartLine", "EndLine", "Instruction", "AllowMultiple")
		for _, rawChunk := range chunks {
			chunk, ok := rawChunk.(map[string]any)
			if !ok {
				continue
			}
			for key := range chunk {
				if _, ok := allowedChunkKeys[key]; !ok {
					return nil, fmt.Errorf("multi_replace_file_content chunk argument %q is not documented", key)
				}
			}
			for _, key := range []string{"TargetFile", "FilePath", "Path"} {
				if chunkPath, ok := chunk[key].(string); ok && chunkPath != "" {
					addPath(chunkPath)
					break
				}
			}
		}
	}

	if len(paths) == 0 {
		return nil, fmt.Errorf("multi_replace_file_content requires at least one target file path")
	}
	return paths, nil
}

func isAntigravityOneShotTimer(input map[string]any) bool {
	rawDur, ok := input["DurationSeconds"]
	if !ok {
		return false
	}
	var dur float64
	switch v := rawDur.(type) {
	case float64:
		dur = v
	case int:
		dur = float64(v)
	case int64:
		dur = float64(v)
	case json.Number:
		var err error
		dur, err = v.Float64()
		if err != nil {
			return false
		}
	default:
		return false
	}
	if dur <= 0 {
		return false
	}
	if _, ok := input["CronExpression"]; ok {
		return false
	}
	if _, ok := input["MaxIterations"]; ok {
		return false
	}
	return true
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
	var native struct {
		ToolCall struct {
			Args json.RawMessage `json:"args"`
		} `json:"toolCall"`
	}
	if err := json.Unmarshal(raw, &native); err != nil {
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

	var input map[string]any
	if err := json.Unmarshal(native.ToolCall.Args, &input); err != nil {
		return engine.ToolCall{}, err
	}
	var mcpPaths []string
	spec, known := planecontract.AntigravityTool(p.ToolCall.Name)
	if !known || spec.Capability == policy.CapabilityDeny {
		if mcp, ok := planecontract.MatchMCPTool(p.ToolCall.Name); ok {
			spec = planecontract.ToolSpec{NativeTool: p.ToolCall.Name, Tool: mcp.Tool, Capability: mcp.Capability}
			known = true
			mcpPaths = projectMCPPaths(mcp, native.ToolCall.Args)
		} else if !known {
			spec = planecontract.ToolSpec{NativeTool: p.ToolCall.Name, Tool: p.ToolCall.Name, Capability: policy.CapabilityUnknown}
		}
	}

	tc := engine.ToolCall{
		Plane:      "antigravity",
		Event:      event,
		Tool:       spec.Tool,
		NativeTool: p.ToolCall.Name,
		Capability: spec.Capability,
		Command:    p.ToolCall.Args.CommandLine,
		SessionID:  p.ConversationID,
		CWD:        cwd,
		Arguments:  native.ToolCall.Args,
		Raw:        raw,
	}
	if brainDir := AntigravityBrainDir(p.ConversationID); brainDir != "" {
		tc.PermittedRoots = []string{brainDir}
	}
	if p.ToolCall.Name == "manage_task" {
		action, _ := input["Action"].(string)
		switch action {
		case "list", "status", "kill":
			tc.Capability = policy.CapabilitySafeControl
		default:
			tc.Capability = policy.CapabilityDeny
		}
	}
	if p.ToolCall.Name == "schedule" {
		if isAntigravityOneShotTimer(input) {
			tc.Capability = policy.CapabilitySafeControl
		} else {
			tc.Capability = policy.CapabilityExternal
		}
	}
	if tc.Capability == policy.CapabilityCommand {
		if tc.Command == "" {
			if cmd, ok := input["CommandLine"].(string); ok && cmd != "" {
				tc.Command = cmd
			} else if cmd, ok := input["Command"].(string); ok && cmd != "" {
				tc.Command = cmd
			} else if code, ok := input["Code"].(string); ok && code != "" {
				tc.Command = code
			} else if nb, ok := input["NotebookPath"].(string); ok && nb != "" {
				tc.Command = "jupyter execute " + nb
			}
		}
		tc.InputShape = "command"
	}
	if tc.Capability == policy.CapabilityReadDiscovery || tc.Capability == policy.CapabilityMutation {
		paths, err := documentedAntigravityPaths(p.ToolCall.Name, input)
		if err != nil {
			return engine.ToolCall{}, err
		}
		tc.Paths = paths
		if len(mcpPaths) > 0 {
			tc.Paths = append(tc.Paths, mcpPaths...)
		}
		tc.InputShape = "path"
	}
	if tc.Capability == policy.CapabilityWebFetch {
		if _, present := input["URL"]; present {
			return engine.ToolCall{}, fmt.Errorf("antigravity %s has undocumented URL argument", p.ToolCall.Name)
		}
		if _, present := input["url"]; present {
			return engine.ToolCall{}, fmt.Errorf("antigravity %s has undocumented url argument", p.ToolCall.Name)
		}
		url, ok := input["Url"].(string)
		if !ok {
			return engine.ToolCall{}, fmt.Errorf("antigravity %s requires Url", p.ToolCall.Name)
		}
		tc.URL = url
		tc.InputShape = "url"
	}
	if tc.Capability == policy.CapabilityWebSearch {
		tc.InputShape = "query"
	}
	if tc.InputShape == "" {
		tc.InputShape = "opaque-object"
	}
	tc.RepoRoot = repoRoot(cwd)
	tc.NativeWebResearch = nativeResearchCall(tc)
	return tc, nil
}

func EmitAntigravity(v policy.Verdict, phase string, tc engine.ToolCall, stdout io.Writer) int {
	if phase == "post" {
		stdout.Write([]byte("{}\n"))
		return 0
	}
	decision := string(v.Decision)
	if v.Decision == policy.Complete {
		decision = "deny"
	}
	if v.Decision == policy.Ask {
		decision = "force_ask"
	}
	payload := map[string]any{"decision": decision}
	if v.Decision == policy.Complete {
		payload["operator_action"] = v.OperatorAction
		payload["request_id"] = v.RequestID
		payload["status"] = "pending"
	}
	if reason := guidanceForModel(v, nativeAction(tc.NativeTool, tc.Arguments)); reason != "" {
		payload["reason"] = reason
	}
	b, _ := json.Marshal(payload)
	stdout.Write(append(b, '\n'))
	return 0
}

func AntigravityAppDataDir() string {
	if dir := os.Getenv("ANTIGRAVITY_APP_DATA_DIR"); dir != "" {
		return filepath.Clean(dir)
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return ""
	}
	return filepath.Join(home, ".gemini", "antigravity-cli")
}

func AntigravityBrainDir(sessionID string) string {
	sessionID = strings.TrimSpace(sessionID)
	if sessionID == "" || strings.Contains(sessionID, "..") || strings.ContainsAny(sessionID, `/\`) {
		return ""
	}
	appData := AntigravityAppDataDir()
	if appData == "" {
		return ""
	}
	return filepath.Join(appData, "brain", sessionID)
}
