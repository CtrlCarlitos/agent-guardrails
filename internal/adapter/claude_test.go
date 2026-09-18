package adapter

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
)

func TestParseClaudeBash(t *testing.T) {
	f, err := os.Open("../../test/fixtures/claude/bash-rm-rf.json")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	tc, err := ParseClaude(f)
	if err != nil {
		t.Fatal(err)
	}
	if tc.Plane != "claude" || tc.Tool != "Bash" || tc.Command != "rm -rf /" || tc.Event != "pre" {
		t.Fatalf("bad ToolCall: %+v", tc)
	}
	if tc.SessionID != "s1" {
		t.Errorf("session id = %q", tc.SessionID)
	}
}

func TestParseClaudeRead(t *testing.T) {
	f, _ := os.Open("../../test/fixtures/claude/read-env.json")
	defer f.Close()
	tc, err := ParseClaude(f)
	if err != nil {
		t.Fatal(err)
	}
	if tc.Tool != "Read" || len(tc.Paths) != 1 || tc.Paths[0] != "/home/u/proj/.env" {
		t.Fatalf("bad ToolCall: %+v", tc)
	}
}

func TestParseClaudeClassifiesCapabilityInputs(t *testing.T) {
	tests := []struct {
		name       string
		tool       string
		input      string
		capability policy.Capability
		path       string
		url        string
	}{
		{"powershell", "PowerShell", `{"command":"Remove-Item safe.txt"}`, policy.CapabilityCommand, "", ""},
		{"glob", "Glob", `{"pattern":"**/*.go","path":"/repo"}`, policy.CapabilityReadDiscovery, "/repo", ""},
		{"notebook", "NotebookEdit", `{"notebook_path":"/repo/a.ipynb"}`, policy.CapabilityMutation, "/repo/a.ipynb", ""},
		{"fetch", "WebFetch", `{"url":"https://example.test/docs"}`, policy.CapabilityWebFetch, "", "https://example.test/docs"},
		{"search", "WebSearch", `{"query":"guardrails"}`, policy.CapabilityWebSearch, "", ""},
		{"mcp", "mcp__server__unsafe", `{}`, policy.CapabilityDeny, "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payload := fmt.Sprintf(`{"hook_event_name":"PreToolUse","tool_name":%q,"tool_input":%s}`, tt.tool, tt.input)
			tc, err := ParseClaude(strings.NewReader(payload))
			if err != nil {
				t.Fatal(err)
			}
			if tc.Capability != tt.capability || tc.URL != tt.url || (tt.path != "" && (len(tc.Paths) != 1 || tc.Paths[0] != tt.path)) {
				t.Fatalf("ToolCall = %+v", tc)
			}
		})
	}
}

func TestParseClaudeSessionStart(t *testing.T) {
	raw := `{"session_id":"s1","cwd":"/tmp","hook_event_name":"SessionStart"}`
	tc, err := ParseClaude(strings.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	if tc.Event != "session-start" {
		t.Fatalf("Event = %q, want session-start", tc.Event)
	}
}

func TestPostureText(t *testing.T) {
	txt := PostureText(nil, nil)
	if !strings.Contains(txt, "autonomously") {
		t.Fatalf("posture text missing the autonomy instruction: %q", txt)
	}
	txt = PostureText([]string{"P6"}, []string{"guardrail: binary older than engine_min_version"})
	if !strings.Contains(txt, "P6") {
		t.Fatalf("posture text should list active waivers: %q", txt)
	}
	if !strings.Contains(txt, "engine_min_version") {
		t.Fatalf("posture text should surface merge warnings: %q", txt)
	}
}

func TestPostureTextSanitizesUnauthorizedWaiverWarningToOneLine(t *testing.T) {
	warning := "guardrail: repo requested waiver of P6.egress\nforged\twarning\x7fclaim, which is NOT authorized; rule remains ENFORCED"
	want := "guardrail: repo requested waiver of P6.egress forged warning claim, which is NOT authorized; rule remains ENFORCED"

	paragraphs := strings.Split(PostureText(nil, []string{warning}), "\n\n")
	if got := paragraphs[len(paragraphs)-1]; got != want {
		t.Fatalf("PostureText() warning paragraph = %q, want one sanitized line %q", got, want)
	}
}

func TestEmitClaudeSessionStart(t *testing.T) {
	var out bytes.Buffer
	code := EmitClaudeSessionStart("hello agent", &out)
	if code != 0 {
		t.Fatalf("code = %d, want 0", code)
	}
	var got struct {
		HookSpecificOutput struct {
			HookEventName     string `json:"hookEventName"`
			AdditionalContext string `json:"additionalContext"`
		} `json:"hookSpecificOutput"`
	}
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.HookSpecificOutput.HookEventName != "SessionStart" || got.HookSpecificOutput.AdditionalContext != "hello agent" {
		t.Fatalf("bad payload: %+v", got.HookSpecificOutput)
	}
}

func TestPlaneLifecycleLineReflectsRegistrationAndDrift(t *testing.T) {
	cases := []struct {
		name     string
		state    string
		unmarked int
		wants    []string
		rejects  []string
	}{
		{"registered", "guardrail hook registered", 0,
			[]string{"Claude plane lifecycle: guardrail hook registered"},
			[]string{"guardrail plane enable claude", "drift"}},
		{"registered with drift", "guardrail hook registered", 2,
			[]string{"guardrail hook registered", "2 unmarked legacy guardrail hook groups", "drift", "guardrail plane enable claude"},
			nil},
		{"not registered", "present, hook NOT registered", 0,
			[]string{"Claude plane lifecycle: present, hook NOT registered", "future sessions", "guardrail plane enable claude"},
			nil},
		{"no settings", "no settings.json", 0,
			[]string{"Claude plane lifecycle: no settings.json", "guardrail plane enable claude"},
			nil},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			got := PlaneLifecycleLine("claude", tt.state, tt.unmarked)
			for _, w := range tt.wants {
				if !strings.Contains(got, w) {
					t.Fatalf("%q lacks %q", got, w)
				}
			}
			for _, r := range tt.rejects {
				if strings.Contains(got, r) {
					t.Fatalf("%q must not contain %q", got, r)
				}
			}
			if strings.Contains(got, "\n") {
				t.Fatalf("lifecycle line must be one paragraph: %q", got)
			}
		})
	}
}

func TestPlaneLifecycleLineSanitizesState(t *testing.T) {
	got := PlaneLifecycleLine("claude", "unreadable: forged\nline\x7f", 0)
	if strings.Contains(got, "\n") || strings.Contains(got, "\x7f") {
		t.Fatalf("state was not sanitized: %q", got)
	}
}
