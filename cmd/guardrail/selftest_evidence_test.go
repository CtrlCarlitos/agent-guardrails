package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/CtrlCarlitos/agent-guardrails/internal/testenv"
)

func TestSelftestCodexEvidence(t *testing.T) {
	cutoff := time.Date(2026, 9, 18, 12, 0, 0, 0, time.UTC)
	record := `{"ts":"2026-09-18T12:00:01Z","plane":"codex","session_id":"live","event":"pre","tool":"Bash","command":"pwd","decision":"allow"}`
	for _, tc := range []struct {
		name, data string
		exit       int
		want       string
	}{
		{"none", "", 1, "eligible=0"},
		{"singleton", record + "\n", 1, "eligible=1"},
		{"duplicate", record + "\n" + record + "\n", 1, "duplicates=1"},
		{"synthetic", strings.ReplaceAll(record, "live", "selftest-123") + "\n" + strings.ReplaceAll(strings.ReplaceAll(record, "live", "codex-fixture"), "pwd", "ls") + "\n", 1, "synthetic=2"},
		{"live", record + "\n" + strings.ReplaceAll(record, "12:00:01Z", "12:00:02Z") + "\n", 0, "qualifying_sessions=1"},
		{"stale", strings.ReplaceAll(record, "12:00:01Z", "11:59:59Z") + "\n", 1, "stale=1"},
		{"malformed", record + "\n{bad\n", 1, "malformed=1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "audit.jsonl")
			if err := os.WriteFile(path, []byte(tc.data), 0600); err != nil {
				t.Fatal(err)
			}
			sessionsRoot := filepath.Join(dir, "sessions")
			if strings.Contains(tc.data, `"session_id":"live"`) {
				writeCodexRollout(t, sessionsRoot, "live", cutoff.Add(time.Second))
			}
			var out, errb bytes.Buffer
			code := printCodexEvidence(path, sessionsRoot, cutoff, cutoff.Add(time.Hour), codexEvidenceOptions{}, &out, &errb)
			if code != tc.exit || !strings.Contains(out.String(), tc.want) {
				t.Fatalf("exit=%d output=%s errors=%s", code, &out, &errb)
			}
			if !strings.Contains(out.String(), "heuristic only") || !strings.Contains(out.String(), "selected session") {
				t.Fatalf("missing boundary: %s", &out)
			}
			if strings.Contains(tc.data, `"session_id":"live"`) && strings.Contains(out.String(), "diagnostic class: transport") {
				t.Fatalf("an existing selected-session hook record was mislabeled as a transport miss: %s", &out)
			}
			after, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if string(after) != tc.data {
				t.Fatal("evidence mode mutated audit records")
			}
		})
	}
}

func TestSelftestCodexEvidenceNewestSilentSessionWins(t *testing.T) {
	cutoff := time.Date(2026, 9, 18, 12, 0, 0, 0, time.UTC)
	dir := t.TempDir()
	auditPath := filepath.Join(dir, "audit.jsonl")
	record := `{"ts":"2026-09-18T12:00:02Z","plane":"codex","session_id":"older","event":"pre","tool":"Bash","decision":"allow"}`
	data := record + "\n" + strings.ReplaceAll(record, "12:00:02Z", "12:00:03Z") + "\n"
	if err := os.WriteFile(auditPath, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	sessionsRoot := filepath.Join(dir, "sessions")
	writeCodexRollout(t, sessionsRoot, "older", cutoff.Add(time.Second))
	writeCodexRollout(t, sessionsRoot, "newest-silent", cutoff.Add(10*time.Minute))

	var out, errb bytes.Buffer
	code := printCodexEvidence(auditPath, sessionsRoot, cutoff, cutoff.Add(time.Hour), codexEvidenceOptions{}, &out, &errb)
	if code != 1 || !strings.Contains(out.String(), "selected_session=newest-silent") || !strings.Contains(out.String(), "newest known Codex session is silent") || !strings.Contains(out.String(), "diagnostic class: transport") {
		t.Fatalf("exit=%d output=%s errors=%s", code, &out, &errb)
	}
	if !strings.Contains(out.String(), "raw evidence: session=newest-silent hook_records=0") {
		t.Fatalf("silent session lacks transport evidence: %s", &out)
	}
	if strings.Contains(out.String(), "gate opens") {
		t.Fatalf("older evidence masked newest silence: %s", &out)
	}
}

func TestSelftestCodexEvidenceSessionAndExpectedTools(t *testing.T) {
	cutoff := time.Date(2026, 9, 18, 12, 0, 0, 0, time.UTC)
	dir := t.TempDir()
	auditPath := filepath.Join(dir, "audit.jsonl")
	sessionsRoot := filepath.Join(dir, "sessions")
	writeCodexRollout(t, sessionsRoot, "selected", cutoff.Add(time.Minute))
	writeCodexRollout(t, sessionsRoot, "newer", cutoff.Add(2*time.Minute))
	records := []string{
		`{"ts":"2026-09-18T12:01:01Z","plane":"codex","session_id":"selected","event":"pre","tool":"Bash","native_tool":"command_execution","decision":"allow"}`,
		`{"ts":"2026-09-18T12:01:02Z","plane":"codex","session_id":"selected","event":"pre","tool":"Bash","native_tool":"command_execution","decision":"deny"}`,
	}
	if err := os.WriteFile(auditPath, []byte(strings.Join(records, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	opts := codexEvidenceOptions{SessionID: "selected", ExpectedTools: []string{"command_execution", "apply_patch"}}
	var out, errb bytes.Buffer
	if code := printCodexEvidence(auditPath, sessionsRoot, cutoff, cutoff.Add(time.Hour), opts, &out, &errb); code != 1 || !strings.Contains(out.String(), "missing_expected_tools=apply_patch") {
		t.Fatalf("exit=%d output=%s errors=%s", code, &out, &errb)
	}
	records = append(records, `{"ts":"2026-09-18T12:01:03Z","plane":"codex","session_id":"selected","event":"pre","tool":"apply_patch","native_tool":"apply_patch","decision":"allow"}`)
	if err := os.WriteFile(auditPath, []byte(strings.Join(records, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	errb.Reset()
	if code := printCodexEvidence(auditPath, sessionsRoot, cutoff, cutoff.Add(time.Hour), opts, &out, &errb); code != 0 || !strings.Contains(out.String(), "missing_expected_tools=none") {
		t.Fatalf("exit=%d output=%s errors=%s", code, &out, &errb)
	}
}

func TestParseCodexEvidenceOptions(t *testing.T) {
	now := time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC)
	opts, ok := parseCodexEvidenceOptions([]string{"--session", "abc", "--since", "30m", "--expect-tool", "command_execution", "--expect-tool", "apply_patch"}, now, &bytes.Buffer{})
	if !ok || opts.SessionID != "abc" || opts.Since == nil || !opts.Since.Equal(now.Add(-30*time.Minute)) || strings.Join(opts.ExpectedTools, ",") != "command_execution,apply_patch" {
		t.Fatalf("options = %+v ok=%v", opts, ok)
	}
	for _, args := range [][]string{
		{"--session"}, {"--session", ""}, {"--session", "a", "--session", "b"},
		{"--since", "bad"}, {"--since", "-1h"}, {"--expect-tool", ""}, {"--unknown"},
	} {
		if _, ok := parseCodexEvidenceOptions(args, now, &bytes.Buffer{}); ok {
			t.Errorf("accepted %v", args)
		}
	}
}

func writeCodexRollout(t *testing.T, root, sessionID string, started time.Time) {
	t.Helper()
	dir := filepath.Join(root, started.Format("2006"), started.Format("01"), started.Format("02"))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	line := `{"timestamp":"` + started.Format(time.RFC3339Nano) + `","type":"session_meta","payload":{"id":"` + sessionID + `","timestamp":"` + started.Format(time.RFC3339Nano) + `"}}` + "\n"
	if err := os.WriteFile(filepath.Join(dir, "rollout-"+sessionID+".jsonl"), []byte(line), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestSelftestEvidenceDoesNotRunProbes(t *testing.T) {
	state := t.TempDir()
	testenv.SetState(t, state)
	t.Setenv("CODEX_HOME", filepath.Join(state, "codex"))
	var out, errb bytes.Buffer
	if code := cmdSelftest([]string{"--evidence", "codex"}, &out, &errb); code != 1 {
		t.Fatalf("exit=%d output=%s errors=%s", code, &out, &errb)
	}
	entries, err := os.ReadDir(state)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("evidence mode wrote state: %v", entries)
	}
	// `--evidence claude` became a supported gate (#149), so it leaves this
	// list; opencode and antigravity have no gate and take its place, and
	// claude with a trailing argument exercises the guard that it takes none.
	for _, args := range [][]string{
		{"--evidence"},
		{"--evidence", "opencode"},
		{"--evidence", "antigravity"},
		{"--evidence", "claude", "extra"},
		{"--evidence", "codex", "extra"},
		{"--evidence", "codex", "--session"},
	} {
		if code := cmdSelftest(args, &out, &errb); code != 2 {
			t.Errorf("args=%v exit=%d", args, code)
		}
	}
}
