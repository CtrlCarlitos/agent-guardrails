package adapter

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/CtrlCarlitos/agent-guardrails/internal/engine"
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

func TestParseAntigravityGrepSearchIsDiscovery(t *testing.T) {
	tc, err := ParseAntigravity("pre", strings.NewReader(`{"toolCall":{"name":"grep_search","args":{}}}`))
	if err != nil {
		t.Fatal(err)
	}
	if tc.Tool != "Grep" || tc.Capability != policy.CapabilityReadDiscovery {
		t.Fatalf("ToolCall = %+v, want Grep read discovery", tc)
	}
}

func TestParseAntigravityClassifiesAndExtractsTypedInputs(t *testing.T) {
	for _, tt := range []struct {
		name     string
		raw      string
		wantCap  policy.Capability
		wantURL  string
		wantPath string
	}{
		{"list", `{"toolCall":{"name":"list_dir","args":{"AbsolutePath":"/repo/.env"}}}`, policy.CapabilityReadDiscovery, "", "/repo/.env"},
		{"search", `{"toolCall":{"name":"grep_search","args":{"AbsolutePath":"/repo/.env"}}}`, policy.CapabilityReadDiscovery, "", "/repo/.env"},
		{"fetch", `{"toolCall":{"name":"read_url_content","args":{"Url":"https://example.test/docs"}}}`, policy.CapabilityWebFetch, "https://example.test/docs", ""},
		{"web search", `{"toolCall":{"name":"search_web","args":{"Query":"guardrails"}}}`, policy.CapabilityWebSearch, "", ""},
		{"custom", `{"toolCall":{"name":"custom","args":{}}}`, policy.CapabilityDeny, "", ""},
	} {
		t.Run(tt.name, func(t *testing.T) {
			tc, err := ParseAntigravity("pre", strings.NewReader(tt.raw))
			if err != nil {
				t.Fatal(err)
			}
			if tc.Capability != tt.wantCap || tc.URL != tt.wantURL {
				t.Fatalf("ToolCall = %+v, want capability %q and URL %q", tc, tt.wantCap, tt.wantURL)
			}
			if tt.wantPath != "" && (len(tc.Paths) != 1 || tc.Paths[0] != tt.wantPath) {
				t.Fatalf("paths = %q, want %q", tc.Paths, tt.wantPath)
			}
		})
	}
}

func TestEmitAntigravityPreSanitizesReasonForEveryDecision(t *testing.T) {
	tc, err := ParseAntigravity("pre", strings.NewReader(`{"conversationId":"c1","toolCall":{"name":"run_command","args":{"CommandLine":"chmod -R 777 /tmp","Cwd":"/tmp"}}}`))
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		decision policy.Decision
		want     string
	}{
		{decision: policy.Allow, want: "allow"},
		{decision: policy.Ask, want: "force_ask"},
		{decision: policy.Deny, want: "deny"},
	} {
		t.Run(string(test.decision), func(t *testing.T) {
			var out bytes.Buffer
			code := EmitAntigravity(policy.Verdict{Decision: test.decision, Reason: "needs approval"}, "pre", tc, &out)
			if code != 0 {
				t.Fatalf("code = %d, want 0 (exit code carries no meaning here)", code)
			}
			var got map[string]string
			if err := json.Unmarshal(out.Bytes(), &got); err != nil {
				t.Fatal(err)
			}
			if got["decision"] != test.want {
				t.Fatalf("bad payload: %v", got)
			}
			if test.decision == policy.Ask && (!strings.Contains(got["reason"], "Operator authorization required: needs approval.") || !strings.Contains(got["reason"], `Request authorization for this exact action: run_command {"CommandLine":"chmod -R 777 /tmp","Cwd":"/tmp"}.`) || !strings.Contains(got["reason"], "If the operator approves, retry this exact tool call once.") || !strings.Contains(got["reason"], "Do not alter or broaden the action.")) {
				t.Fatalf("ask guidance = %q", got["reason"])
			}
			if test.decision == policy.Deny && (!strings.Contains(got["reason"], "Guardrail denied this action: needs approval.") || !strings.Contains(got["reason"], "It cannot be authorized.") || !strings.Contains(got["reason"], "Choose a safe alternative.")) {
				t.Fatalf("deny guidance = %q", got["reason"])
			}
		})
	}
}

func TestEmitAntigravityPost(t *testing.T) {
	var out bytes.Buffer
	code := EmitAntigravity(policy.Verdict{Decision: policy.Deny, Reason: "irrelevant"}, "post", engine.ToolCall{}, &out)
	if code != 0 || out.String() != "{}\n" {
		t.Fatalf("post phase must always emit {} regardless of v; got code=%d out=%q", code, out.String())
	}
}

func TestEmitAntigravityAllowOmitsReason(t *testing.T) {
	var out bytes.Buffer
	EmitAntigravity(policy.Verdict{Decision: policy.Allow}, "pre", engine.ToolCall{}, &out)
	var got map[string]any
	json.Unmarshal(out.Bytes(), &got)
	if _, ok := got["reason"]; ok {
		t.Errorf("reason should be omitted when empty: %v", got)
	}
}
