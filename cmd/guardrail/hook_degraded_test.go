package main

import (
	"bytes"
	"encoding/json"
	"os"
	"runtime"
	"strings"
	"testing"

	"github.com/CtrlCarlitos/agent-guardrails/internal/audit"
)

// TestHookDegradedAllowReportsWrittenToAudit pins the B+ evidence path: a
// healthy engine call that carries adapter-reported degraded allows writes
// each as an audit record tagged plugin-degraded, so ADR-0020's record
// counting still sees mediation across an outage window.
func TestHookDegradedAllowReportsWrittenToAudit(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	if runtime.GOOS == "windows" {
		t.Setenv("APPDATA", t.TempDir())
		t.Setenv("LOCALAPPDATA", t.TempDir())
	}
	t.Setenv("GUARDRAIL_CONFIG", "")
	payload := `{"event":"pre","tool":"question","cwd":"/repo","arguments":{},"degraded_allows":[{"tool":"question","call_id":"c1","ts":"2026-09-20T05:00:00Z"},{"tool":"bash","ts":"2026-09-20T05:00:01Z"}]}`
	var out, errb bytes.Buffer
	run([]string{"hook", "opencode"}, strings.NewReader(payload), &out, &errb)

	raw, err := os.ReadFile(audit.DefaultPath(""))
	if err != nil {
		t.Fatalf("audit log not written: %v", err)
	}
	found := false
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		var rec audit.Record
		if json.Unmarshal([]byte(line), &rec) != nil {
			continue
		}
		if rec.Transport == "plugin-degraded" && rec.Tool == "question" && rec.Decision == "allow" && rec.TS == "2026-09-20T05:00:00Z" {
			found = true
		}
	}
	if !found {
		t.Fatalf("no plugin-degraded audit record in log:\n%s", raw)
	}
}
