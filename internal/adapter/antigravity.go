package adapter

import (
	"encoding/json"
	"fmt"
	"io"

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
	"view_file":                  {"AbsolutePath", allowedFields("AbsolutePath", "StartLine", "EndLine", "IsSkillFile")},
	"write_to_file":              {"TargetFile", allowedFields("TargetFile", "Overwrite", "CodeContent", "Description", "IsArtifact", "ArtifactMetadata")},
	"replace_file_content":       {"TargetFile", allowedFields("TargetFile", "Instruction", "Description", "AllowMultiple", "TargetContent", "ReplacementContent", "StartLine", "EndLine", "TargetLintErrorIds")},
	"multi_replace_file_content": {"TargetFile", allowedFields("TargetFile", "Instruction", "Description", "ReplacementChunks", "TargetLintErrorIds", "ArtifactMetadata")},
	"list_dir":                   {"DirectoryPath", allowedFields("DirectoryPath")},
	"find_by_name":               {"SearchDirectory", allowedFields("SearchDirectory", "Pattern", "Type", "Excludes", "Extensions", "FullPath", "MaxDepth")},
	"grep_search":                {"SearchPath", allowedFields("SearchPath", "Query", "IsRegex", "CaseInsensitive", "Includes", "MatchPerLine")},
}

func allowedFields(fields ...string) map[string]struct{} {
	allowed := make(map[string]struct{}, len(fields))
	for _, field := range fields {
		allowed[field] = struct{}{}
	}
	return allowed
}

func documentedAntigravityPath(tool string, input map[string]any) (string, error) {
	schema, ok := antigravityPathSchemas[tool]
	if !ok {
		return "", nil
	}
	for key := range input {
		if _, ok := schema.allowed[key]; !ok {
			return "", fmt.Errorf("%s argument %q is not documented", tool, key)
		}
	}
	path, ok := input[schema.key].(string)
	if !ok || path == "" {
		return "", fmt.Errorf("%s requires string argument %q", tool, schema.key)
	}
	return path, nil
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
	spec, known := planecontract.AntigravityTool(p.ToolCall.Name)
	if !known {
		spec = planecontract.ToolSpec{NativeTool: p.ToolCall.Name, Tool: p.ToolCall.Name, Capability: policy.CapabilityUnknown}
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
	if tc.Capability == policy.CapabilityCommand {
		tc.InputShape = "command"
	}
	if tc.Capability == policy.CapabilityReadDiscovery || tc.Capability == policy.CapabilityMutation {
		path, err := documentedAntigravityPath(p.ToolCall.Name, input)
		if err != nil {
			return engine.ToolCall{}, err
		}
		tc.Paths = []string{path}
		tc.InputShape = "path"
	}
	if tc.Capability == policy.CapabilityWebFetch {
		for _, key := range []string{"Url", "URL", "url"} {
			if url, ok := input[key].(string); ok {
				tc.URL = url
				break
			}
		}
		tc.InputShape = "url"
	}
	if tc.Capability == policy.CapabilityWebSearch {
		tc.InputShape = "query"
	}
	if tc.InputShape == "" {
		tc.InputShape = "opaque-object"
	}
	tc.RepoRoot = repoRoot(cwd)
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
