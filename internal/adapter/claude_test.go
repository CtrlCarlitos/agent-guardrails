package adapter

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"
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
