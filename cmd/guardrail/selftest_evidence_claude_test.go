package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writeEvidenceSegment(t *testing.T, lines ...string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func claudePreRecord(session, ts, tool, decision string) string {
	return `{"ts":"` + ts + `","plane":"claude","session_id":"` + session +
		`","event":"pre","tool":"` + tool + `","decision":"` + decision + `"}`
}

// `selftest --evidence claude` answers the question doctor cannot: not "is the
// hook registered" but "did it run". Exit 1 while unobserved, 0 once a real
// session has been mediated.
func TestSelftestClaudeEvidenceGate(t *testing.T) {
	cutoff := time.Date(2026, 9, 20, 0, 0, 0, 0, time.UTC)
	const real = "78f4afb7-748f-4af6-b026-51882e1865f3"
	for _, tt := range []struct {
		name  string
		lines []string
		want  int
		says  string
	}{
		{"never fired", []string{claudePreRecord("night-claude", "2026-09-20T00:10:00Z", "Bash", "allow")},
			1, "not yet observed"},
		{"fixtures only", []string{
			claudePreRecord("trifecta-sess-1", "2026-09-20T00:10:00Z", "Bash", "allow"),
			claudePreRecord("trifecta-sess-1", "2026-09-20T00:10:05Z", "Read", "deny"),
		}, 1, "not yet observed"},
		{"one real record", []string{claudePreRecord(real, "2026-09-20T00:10:00Z", "Bash", "allow")},
			1, "not yet observed"},
		{"mediated", []string{
			claudePreRecord(real, "2026-09-20T00:10:00Z", "Bash", "allow"),
			claudePreRecord(real, "2026-09-20T00:10:05Z", "Read", "deny"),
		}, 0, "live mediation observed"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var out, errb strings.Builder
			code := printClaudeEvidence(writeEvidenceSegment(t, tt.lines...), cutoff, cutoff.Add(time.Hour), &out, &errb)
			if code != tt.want {
				t.Fatalf("exit = %d, want %d\n%s", code, tt.want, out.String())
			}
			if !strings.Contains(out.String(), tt.says) {
				t.Fatalf("output missing %q:\n%s", tt.says, out.String())
			}
		})
	}
}

// The subcommand has to accept the plane, and still reject anything else.
func TestSelftestEvidenceAcceptsClaudeAndRejectsUnknownPlanes(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	var out, errb strings.Builder
	if code := cmdSelftest([]string{"--evidence", "claude"}, &out, &errb); code != 1 {
		t.Fatalf("--evidence claude exit = %d, want 1 on a machine with no real records\n%s%s", code, out.String(), errb.String())
	}
	if !strings.Contains(out.String(), "claude evidence:") {
		t.Fatalf("--evidence claude did not print a claude report:\n%s", out.String())
	}
	for _, args := range [][]string{{"--evidence", "opencode"}, {"--evidence"}, {"--evidence", "claude", "extra"}} {
		out.Reset()
		errb.Reset()
		if code := cmdSelftest(args, &out, &errb); code != 2 {
			t.Fatalf("%v exit = %d, want 2", args, code)
		}
	}
}
