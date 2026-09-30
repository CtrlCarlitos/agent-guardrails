package main

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/CtrlCarlitos/agent-guardrails/internal/testenv"
)

// #469: six Antigravity view_file calls failed closed on an argument name the
// adapter did not know, and the records could not say which arguments came:
// the raw call was never found. A fail-closed record now carries the
// payload's argument names (never their values), per plane.
func TestFailClosedRecordsNameThePayloadArguments(t *testing.T) {
	for plane, c := range map[string]struct {
		args    []string
		payload string
		want    []string
	}{
		"antigravity": {[]string{"hook", "antigravity", "pre"}, `{"toolCall":{"name":"view_file","args":{"AbsolutePath":"/a","Brand-New":"secret-value"}}}`, []string{"AbsolutePath", "Brand-New"}},
		// Codex requires session_id; without it the call fails closed.
		"codex": {[]string{"hook", "codex"}, `{"hook_event_name":"PreToolUse","cwd":"/repo","tool_name":"Bash","tool_input":{"command":"x","secret":"secret-value"}}`, []string{"command", "secret"}},
	} {
		testenv.SetState(t, t.TempDir())
		testenv.SetConfig(t, t.TempDir())
		t.Setenv("GUARDRAIL_CONFIG", "")
		var out, errb strings.Builder
		run(c.args, strings.NewReader(c.payload), &out, &errb)
		rec := lastAuditRecord(t)
		if rec.AuditKind != "hook-fail-closed" {
			t.Fatalf("%s: want a fail-closed record, got %+v", plane, rec)
		}
		if !reflect.DeepEqual(rec.InputKeys, c.want) {
			t.Errorf("%s: input_keys = %v, want %v", plane, rec.InputKeys, c.want)
		}
		line, _ := json.Marshal(rec)
		if strings.Contains(string(line), "secret-value") {
			t.Errorf("%s: a payload value leaked into the record: %s", plane, line)
		}
	}
}
