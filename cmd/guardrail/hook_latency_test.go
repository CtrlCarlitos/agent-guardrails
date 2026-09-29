package main

import (
	"strings"
	"testing"

	"github.com/CtrlCarlitos/agent-guardrails/internal/audit"
	"github.com/CtrlCarlitos/agent-guardrails/internal/testenv"
)

// #456: the server-vs-spawn decision needs per-call hook time, per plane.
// Every hook record now carries hook_ms (in-process handling) and, for a
// spawned hook, startup_ms (process start to handling).
func TestHookAuditRecordsCarryLatency(t *testing.T) {
	testenv.SetState(t, t.TempDir())
	testenv.SetConfig(t, t.TempDir())
	t.Setenv("GUARDRAIL_CONFIG", "")
	cwd := t.TempDir()
	for name, payload := range map[string]string{
		"evaluated":   string(mustJSON(t, map[string]any{"session_id": "lat1", "cwd": cwd, "hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": map[string]any{"command": "ls"}})),
		"fail-closed": "{",
	} {
		var out, errb strings.Builder
		run([]string{"hook", "claude"}, strings.NewReader(payload), &out, &errb)
		rec := lastAuditRecord(t)
		if rec.HookMS <= 0 {
			t.Errorf("%s: hook_ms = %v, want > 0 (%+v)", name, rec.HookMS, rec)
		}
		if rec.StartupMS < 0 {
			t.Errorf("%s: startup_ms = %v, want >= 0", name, rec.StartupMS)
		}
	}
}

// Doctor summarizes the recorded latency per plane from real sessions:
// selftest probes and records without a measurement are left out.
func TestHookLatencySummaryPerPlane(t *testing.T) {
	var recs []audit.Record
	for i := 1; i <= 20; i++ {
		recs = append(recs, audit.Record{Plane: "claude", SessionID: "s", Event: "pre", HookMS: float64(i)})
	}
	recs = append(recs,
		audit.Record{Plane: "claude", SessionID: "selftest-1", Event: "pre", HookMS: 900},
		audit.Record{Plane: "opencode", SessionID: "s", Event: "pre", HookMS: 5, Transport: "named-pipe-daemon"},
		audit.Record{Plane: "opencode", SessionID: "s", Event: "pre", HookMS: 7},
		audit.Record{Plane: "codex", SessionID: "s", Event: "pre"}, // written before #456
	)
	got := hookLatencyLine(recs)
	for _, want := range []string{"claude p50 10", "p95 19", "n=20", "opencode", "n=2", "1 via daemon"} {
		if !strings.Contains(got, want) {
			t.Errorf("summary lacks %q: %q", want, got)
		}
	}
	if strings.Contains(got, "900") || strings.Contains(got, "codex") {
		t.Errorf("summary counted a selftest probe or an unmeasured record: %q", got)
	}
	if hookLatencyLine(nil) != "" {
		t.Error("no measured records must print nothing")
	}
}
