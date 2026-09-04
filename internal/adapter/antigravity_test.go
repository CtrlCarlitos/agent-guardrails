package adapter

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
)

func TestParseAntigravityBash(t *testing.T) {
	raw := `{"conversationId":"c1","toolCall":{"name":"run_command","args":{"CommandLine":"rm -rf /","Cwd":"/tmp"}},"workspacePaths":["/tmp"]}`
	tc, err := ParseAntigravity("pre", strings.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	if tc.Plane != "antigravity" || tc.Tool != "Bash" || tc.Command != "rm -rf /" || tc.Event != "pre" || tc.SessionID != "c1" {
		t.Fatalf("bad ToolCall: %+v", tc)
	}
}

func TestParseAntigravityFileTool(t *testing.T) {
	raw := `{"conversationId":"c1","toolCall":{"name":"write_to_file","args":{"AbsolutePath":"/tmp/.env"}}}`
	tc, err := ParseAntigravity("pre", strings.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	if tc.Tool != "Write" || len(tc.Paths) != 1 || tc.Paths[0] != "/tmp/.env" {
		t.Fatalf("bad ToolCall: %+v", tc)
	}
}

func TestParseAntigravityPostPhase(t *testing.T) {
	tc, err := ParseAntigravity("post", strings.NewReader(`{"toolCall":{"name":"replace_file_content","args":{"TargetFile":"/tmp/x.go"}}}`))
	if err != nil {
		t.Fatal(err)
	}
	if tc.Event != "post" || tc.Tool != "Edit" || tc.Paths[0] != "/tmp/x.go" {
		t.Fatalf("bad ToolCall: %+v", tc)
	}
}

func TestParseAntigravityCWDFallsBackToWorkspacePaths(t *testing.T) {
	raw := `{"toolCall":{"name":"run_command","args":{"CommandLine":"ls"}},"workspacePaths":["/repo"]}`
	tc, err := ParseAntigravity("pre", strings.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	if tc.CWD != "/repo" {
		t.Fatalf("CWD = %q, want /repo (from workspacePaths)", tc.CWD)
	}
}

func TestParseAntigravityUnknownToolPassesThrough(t *testing.T) {
	tc, err := ParseAntigravity("pre", strings.NewReader(`{"toolCall":{"name":"grep_search","args":{}}}`))
	if err != nil {
		t.Fatal(err)
	}
	if tc.Tool != "grep_search" {
		t.Fatalf("Tool = %q, want passthrough grep_search", tc.Tool)
	}
}

func TestEmitAntigravityPre(t *testing.T) {
	var out bytes.Buffer
	code := EmitAntigravity(policy.Verdict{Decision: policy.Deny, Reason: "no"}, "pre", &out)
	if code != 0 {
		t.Fatalf("code = %d, want 0 (exit code carries no meaning here)", code)
	}
	var got map[string]string
	json.Unmarshal(out.Bytes(), &got)
	if got["decision"] != "deny" || got["reason"] != "no" {
		t.Fatalf("bad payload: %v", got)
	}
}

func TestEmitAntigravityPost(t *testing.T) {
	var out bytes.Buffer
	code := EmitAntigravity(policy.Verdict{Decision: policy.Deny, Reason: "irrelevant"}, "post", &out)
	if code != 0 || out.String() != "{}\n" {
		t.Fatalf("post phase must always emit {} regardless of v; got code=%d out=%q", code, out.String())
	}
}

func TestEmitAntigravityAllowOmitsReason(t *testing.T) {
	var out bytes.Buffer
	EmitAntigravity(policy.Verdict{Decision: policy.Allow}, "pre", &out)
	var got map[string]any
	json.Unmarshal(out.Bytes(), &got)
	if _, ok := got["reason"]; ok {
		t.Errorf("reason should be omitted when empty: %v", got)
	}
}
