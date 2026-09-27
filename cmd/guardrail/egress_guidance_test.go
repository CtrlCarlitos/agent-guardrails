package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
	"github.com/CtrlCarlitos/agent-guardrails/internal/testenv"
)

// #125: agents skipped web fetches because nothing told them the path exists
// before their first deny. The session posture names it up front.
func TestSessionStartPostureNamesTheWebAccessPath(t *testing.T) {
	testenv.SetState(t, t.TempDir())
	testenv.SetConfig(t, t.TempDir())
	t.Setenv("GUARDRAIL_CONFIG", "")
	payload := `{"session_id":"s1","cwd":"/tmp","hook_event_name":"SessionStart"}`
	var out, errb bytes.Buffer
	if code := run([]string{"hook", "claude"}, strings.NewReader(payload), &out, &errb); code != 0 {
		t.Fatalf("exit=%d stderr=%q", code, errb.String())
	}
	var got struct {
		HookSpecificOutput struct {
			AdditionalContext string `json:"additionalContext"`
		} `json:"hookSpecificOutput"`
	}
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatalf("decode %q: %v", out.String(), err)
	}
	posture := got.HookSpecificOutput.AdditionalContext
	for _, want := range []string{"guardrail fetch <url>", "guardrail egress grant --scope repo --host", "passkey", "instead of assuming it will be denied", "guardrail explain"} {
		if !strings.Contains(posture, want) {
			t.Errorf("SessionStart posture missing %q:\n%s", want, posture)
		}
	}
}

// `guardrail fetch` to an unapproved host must print the exact grant to run.
func TestFetchUnapprovedHostPrintsTheExactGrant(t *testing.T) {
	testenv.SetState(t, t.TempDir())
	testenv.SetConfig(t, t.TempDir())
	t.Setenv("GUARDRAIL_CONFIG", "")
	t.Chdir(t.TempDir())
	var out, errb bytes.Buffer
	if code := run([]string{"fetch", "https://starship.rs/presets/"}, strings.NewReader(""), &out, &errb); code != 1 {
		t.Fatalf("exit=%d stderr=%q", code, errb.String())
	}
	if want := policy.WebHostGrantCommand("starship.rs"); !strings.Contains(errb.String(), want) {
		t.Fatalf("stderr %q does not name %q", errb.String(), want)
	}
}
