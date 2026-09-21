package main

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/CtrlCarlitos/agent-guardrails/internal/audit"
	"github.com/CtrlCarlitos/agent-guardrails/internal/testenv"
)

// TestHookDegradedAllowReportsWrittenToAudit pins the B+ evidence path: a
// healthy engine call that carries adapter-reported degraded allows writes
// each as an audit record tagged plugin-degraded, so ADR-0020's record
// counting still sees mediation across an outage window.
func TestHookDegradedAllowReportsWrittenToAudit(t *testing.T) {
	testenv.SetState(t, t.TempDir())
	testenv.SetConfig(t, t.TempDir())
	t.Setenv("GUARDRAIL_CONFIG", "")
	payload := `{"event":"pre","tool":"question","cwd":"/repo","arguments":{},"degraded_allows":[{"tool":"question","call_id":"c1","ts":"2026-09-20T05:00:00Z"},{"tool":"read","call_id":"c2","ts":"2026-09-20T05:00:01Z"},{"tool":"bash","ts":"2026-09-20T05:00:02Z"}]}`
	var out, errb bytes.Buffer
	run([]string{"hook", "opencode"}, strings.NewReader(payload), &out, &errb)

	raw, err := os.ReadFile(audit.DefaultPath(""))
	if err != nil {
		t.Fatalf("audit log not written: %v", err)
	}
	found := false
	floorFound := false
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		var rec audit.Record
		if json.Unmarshal([]byte(line), &rec) != nil {
			continue
		}
		if rec.Transport == "plugin-degraded" && rec.Tool == "question" && rec.Decision == "allow" && rec.TS == "2026-09-20T05:00:00Z" {
			found = true
		}
		if rec.Transport == "plugin-degraded" && rec.Tool == "read" && rec.TS == "2026-09-20T05:00:01Z" {
			floorFound = true
		}
	}
	if !found || !floorFound {
		t.Fatalf("plugin-degraded audit records missing (question=%t read=%t):\n%s", found, floorFound, raw)
	}
}
