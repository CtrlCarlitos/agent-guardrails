package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func verdictLog(t *testing.T, lines ...string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func verdictLine(ts, session, decision, rule string) string {
	return fmt.Sprintf(`{"ts":%q,"session_id":%q,"plane":"claude","tool":"Bash","event":"pre","decision":%q,"rule_id":%q}`,
		ts, session, decision, rule)
}

// The operator-facing question this answers is "is the guard deciding, and on
// what" — the evidence gate only answers "is the guard present". The output
// has to name rules, because a rule id is what an operator can act on: waive
// it, fix it, or recognise it as the one that keeps saving them.
func TestVerdictsOutputNamesRulesAndCounts(t *testing.T) {
	cutoff := time.Date(2026, 9, 21, 0, 0, 0, 0, time.UTC)
	path := verdictLog(t,
		verdictLine("2026-09-21T01:00:00Z", "s1", "deny", "P1.rm-rf"),
		verdictLine("2026-09-21T02:00:00Z", "s2", "deny", "P1.rm-rf"),
		verdictLine("2026-09-21T03:00:00Z", "s2", "ask", "P2.git-push-protected"),
		verdictLine("2026-09-21T04:00:00Z", "s3", "allow", ""),
	)

	var stdout, stderr bytes.Buffer
	if code := printVerdictProfile(path, "claude", cutoff, cutoff.Add(24*time.Hour), &stdout, &stderr); code != 0 {
		t.Fatalf("exit=%d stderr=%q", code, stderr.String())
	}
	out := stdout.String()
	for _, want := range []string{
		"P1.rm-rf",
		"P2.git-push-protected",
		"allow=1 ask=1 deny=2",
		"sessions=3",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
}

// Ask pressure is the metric that survives guardrail never learning how a
// human answered: a rule asked repeatedly inside one session is the shape
// that turns a gate into a formality. The worst session has to be visible,
// because the average hides it.
func TestVerdictsOutputSurfacesAskPressure(t *testing.T) {
	cutoff := time.Date(2026, 9, 21, 0, 0, 0, 0, time.UTC)
	var lines []string
	for i := 0; i < 6; i++ {
		lines = append(lines, verdictLine(fmt.Sprintf("2026-09-21T01:%02d:00Z", i), "s1", "ask", "capability-external"))
	}
	lines = append(lines, verdictLine("2026-09-21T02:00:00Z", "s2", "ask", "capability-external"))

	var stdout, stderr bytes.Buffer
	if code := printVerdictProfile(verdictLog(t, lines...), "claude", cutoff, cutoff.Add(24*time.Hour), &stdout, &stderr); code != 0 {
		t.Fatalf("exit=%d stderr=%q", code, stderr.String())
	}
	out := stdout.String()
	if !strings.Contains(out, "ask pressure") {
		t.Errorf("output does not surface ask pressure:\n%s", out)
	}
	// The worst single session saw 6 asks from one rule; that number is the point.
	if !strings.Contains(out, "6") {
		t.Errorf("worst-session ask count missing:\n%s", out)
	}
}

// The limitation is stated in the output, not just in a commit message. An
// operator reading "ask pressure" must not conclude the tool knows how the
// prompts were answered, because it does not and cannot from this log.
func TestVerdictsOutputStatesWhatItCannotSee(t *testing.T) {
	cutoff := time.Date(2026, 9, 21, 0, 0, 0, 0, time.UTC)
	path := verdictLog(t, verdictLine("2026-09-21T01:00:00Z", "s1", "ask", "P1.chmod"))

	var stdout, stderr bytes.Buffer
	printVerdictProfile(path, "claude", cutoff, cutoff.Add(24*time.Hour), &stdout, &stderr)
	out := strings.ToLower(stdout.String())
	if !strings.Contains(out, "answer") {
		t.Errorf("output does not say that answers are unobservable:\n%s", out)
	}
}

// An empty window is an answer, not an error: a freshly deployed binary has
// decided nothing yet, which is exactly what the evidence gate's eligible=0
// means on its first run.
func TestVerdictsEmptyWindowIsNotAnError(t *testing.T) {
	cutoff := time.Date(2026, 9, 21, 12, 0, 0, 0, time.UTC)
	path := verdictLog(t, verdictLine("2026-09-21T01:00:00Z", "s1", "deny", "P1.rm-rf"))

	var stdout, stderr bytes.Buffer
	if code := printVerdictProfile(path, "claude", cutoff, cutoff.Add(time.Hour), &stdout, &stderr); code != 0 {
		t.Fatalf("exit=%d, want 0: an empty window is a finding, not a failure", code)
	}
	if !strings.Contains(stdout.String(), "no decisions") {
		t.Errorf("empty window not explained:\n%s", stdout.String())
	}
}

// A path that is not there must not read as "the guard decided nothing".
func TestVerdictsMissingLogFailsLoudly(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := printVerdictProfile(filepath.Join(t.TempDir(), "absent.jsonl"), "claude",
		time.Now().Add(-time.Hour), time.Now(), &stdout, &stderr)
	if code == 0 {
		t.Errorf("missing audit log exited 0:\n%s", stdout.String())
	}
}

// The subcommand is wired and rejects unknown flags rather than ignoring them.
func TestAuditVerdictsFlagIsWired(t *testing.T) {
	path := verdictLog(t, verdictLine(time.Now().UTC().Format(time.RFC3339Nano), "s1", "deny", "P1.rm-rf"))
	var stdout, stderr bytes.Buffer
	if code := cmdAudit([]string{"--verdicts", "--path", path}, &stdout, &stderr); code != 0 {
		t.Fatalf("audit --verdicts exit=%d stderr=%q", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "rule") {
		t.Errorf("audit --verdicts produced no rule table:\n%s", stdout.String())
	}

	stdout.Reset()
	stderr.Reset()
	if code := cmdAudit([]string{"--verdicts", "--bogus"}, &stdout, &stderr); code != 2 {
		t.Errorf("unknown flag exit=%d, want 2", code)
	}
}
