package adapter

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
)

func TestParseOpencodeBash(t *testing.T) {
	raw := `{"session_id":"s1","event":"pre","tool":"bash","command":"rm -rf /","cwd":"/tmp"}`
	tc, err := ParseOpencode(strings.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	if tc.Plane != "opencode" || tc.Tool != "Bash" || tc.Command != "rm -rf /" || tc.Event != "pre" {
		t.Fatalf("bad ToolCall: %+v", tc)
	}
}

func TestParseOpencodeFileTool(t *testing.T) {
	raw := `{"session_id":"s1","event":"pre","tool":"read","paths":["/tmp/.env"],"cwd":"/tmp"}`
	tc, err := ParseOpencode(strings.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	if tc.Tool != "Read" || len(tc.Paths) != 1 || tc.Paths[0] != "/tmp/.env" {
		t.Fatalf("bad ToolCall: %+v", tc)
	}
}

func TestParseOpencodeUnknownEventDefaultsPre(t *testing.T) {
	tc, err := ParseOpencode(strings.NewReader(`{"session_id":"s1","tool":"bash","command":"ls"}`))
	if err != nil {
		t.Fatal(err)
	}
	if tc.Event != "pre" {
		t.Fatalf("Event = %q, want pre", tc.Event)
	}
}

func TestEmitOpencodeDeny(t *testing.T) {
	var out, errb bytes.Buffer
	code := EmitOpencode(policy.Verdict{Decision: policy.Deny, Reason: "no"}, &out, &errb)
	if code != 2 {
		t.Fatalf("code = %d, want 2", code)
	}
	var got map[string]string
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got["decision"] != "deny" || got["reason"] != "no" {
		t.Fatalf("bad payload: %v", got)
	}
}

func TestEmitOpencodeAllow(t *testing.T) {
	var out, errb bytes.Buffer
	code := EmitOpencode(policy.Verdict{Decision: policy.Allow}, &out, &errb)
	if code != 0 {
		t.Fatalf("code = %d, want 0", code)
	}
	var got map[string]string
	json.Unmarshal(out.Bytes(), &got)
	if got["decision"] != "allow" {
		t.Fatalf("decision = %q, want allow", got["decision"])
	}
}
