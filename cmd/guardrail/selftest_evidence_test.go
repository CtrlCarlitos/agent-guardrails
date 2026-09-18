package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
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
		{"live", record + "\n" + strings.ReplaceAll(record, "pwd", "ls") + "\n", 0, "qualifying_sessions=1"},
		{"stale", strings.ReplaceAll(record, "12:00:01Z", "11:59:59Z") + "\n", 1, "stale=1"},
		{"malformed", record + "\n{bad\n", 1, "malformed=1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "audit.jsonl")
			if err := os.WriteFile(path, []byte(tc.data), 0600); err != nil {
				t.Fatal(err)
			}
			var out, errb bytes.Buffer
			code := printCodexEvidence(path, cutoff, cutoff.Add(time.Hour), &out, &errb)
			if code != tc.exit || !strings.Contains(out.String(), tc.want) {
				t.Fatalf("exit=%d output=%s errors=%s", code, &out, &errb)
			}
			if !strings.Contains(out.String(), "heuristic only") || !strings.Contains(out.String(), "not a per-session regression tripwire") {
				t.Fatalf("missing boundary: %s", &out)
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

func TestSelftestEvidenceDoesNotRunProbes(t *testing.T) {
	state := t.TempDir()
	t.Setenv("XDG_STATE_HOME", state)
	t.Setenv("LOCALAPPDATA", state)
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
	for _, args := range [][]string{{"--evidence"}, {"--evidence", "claude"}, {"--evidence", "codex", "extra"}} {
		if code := cmdSelftest(args, &out, &errb); code != 2 {
			t.Errorf("args=%v exit=%d", args, code)
		}
	}
}
