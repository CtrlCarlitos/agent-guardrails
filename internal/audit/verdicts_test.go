package audit

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The evidence gate answers "is the guard present" — it counts records and
// looks for two pre-hook records in one real session. It cannot answer "is the
// guard deciding, and on what", which is the question an operator actually has
// after a deploy. The audit log already carries decision, rule_id and
// session_id; this is the view over them.

func verdictSegment(t *testing.T, lines ...string) []string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return []string{path}
}

func verdictRecord(ts, session, decision, rule string) string {
	return fmt.Sprintf(`{"ts":%q,"session_id":%q,"plane":"claude","tool":"Bash","event":"pre","decision":%q,"rule_id":%q}`,
		ts, session, decision, rule)
}

func findRule(profile VerdictProfile, rule string) (RuleProfile, bool) {
	for _, r := range profile.Rules {
		if r.RuleID == rule {
			return r, true
		}
	}
	return RuleProfile{}, false
}

// The per-rule breakdown is the deliverable: which rules are deciding, how
// often, and across how many distinct sessions.
func TestVerdictProfileCountsDecisionsPerRule(t *testing.T) {
	cutoff := time.Date(2026, 9, 21, 0, 0, 0, 0, time.UTC)
	now := cutoff.Add(24 * time.Hour)
	segments := verdictSegment(t,
		verdictRecord("2026-09-21T01:00:00Z", "s1", "deny", "P1.rm-rf"),
		verdictRecord("2026-09-21T02:00:00Z", "s1", "deny", "P1.rm-rf"),
		verdictRecord("2026-09-21T03:00:00Z", "s2", "deny", "P1.rm-rf"),
		verdictRecord("2026-09-21T04:00:00Z", "s2", "ask", "P2.git-push-protected"),
		verdictRecord("2026-09-21T05:00:00Z", "s3", "allow", ""),
	)

	profile, err := ReadVerdictProfile(segments, "claude", cutoff, now)
	if err != nil {
		t.Fatal(err)
	}
	if profile.Sessions != 3 {
		t.Errorf("distinct sessions = %d, want 3", profile.Sessions)
	}
	rm, ok := findRule(profile, "P1.rm-rf")
	if !ok {
		t.Fatalf("P1.rm-rf missing from profile %+v", profile.Rules)
	}
	if rm.Deny != 3 {
		t.Errorf("P1.rm-rf deny = %d, want 3", rm.Deny)
	}
	if rm.Sessions != 2 {
		t.Errorf("P1.rm-rf fired in %d sessions, want 2", rm.Sessions)
	}
}

// Ask pressure, the metric that survives the fact that guardrail never learns
// how a human answered. A rule firing repeatedly inside one session is the
// shape that erodes trust, whether or not the answers are observable.
func TestVerdictProfileReportsRepeatAskSessions(t *testing.T) {
	cutoff := time.Date(2026, 9, 21, 0, 0, 0, 0, time.UTC)
	now := cutoff.Add(24 * time.Hour)
	segments := verdictSegment(t,
		// s1 is asked the same thing four times: the fatigue shape.
		verdictRecord("2026-09-21T01:00:00Z", "s1", "ask", "capability-external"),
		verdictRecord("2026-09-21T01:01:00Z", "s1", "ask", "capability-external"),
		verdictRecord("2026-09-21T01:02:00Z", "s1", "ask", "capability-external"),
		verdictRecord("2026-09-21T01:03:00Z", "s1", "ask", "capability-external"),
		// s2 is asked once: ordinary.
		verdictRecord("2026-09-21T02:00:00Z", "s2", "ask", "capability-external"),
	)

	profile, err := ReadVerdictProfile(segments, "claude", cutoff, now)
	if err != nil {
		t.Fatal(err)
	}
	rule, ok := findRule(profile, "capability-external")
	if !ok {
		t.Fatal("capability-external missing")
	}
	if rule.Ask != 5 {
		t.Errorf("ask count = %d, want 5", rule.Ask)
	}
	if rule.Sessions != 2 {
		t.Errorf("sessions = %d, want 2", rule.Sessions)
	}
	if rule.RepeatSessions != 1 {
		t.Errorf("repeat-ask sessions = %d, want 1 (only s1 was asked more than once)", rule.RepeatSessions)
	}
	if rule.MaxPerSession != 4 {
		t.Errorf("worst session saw %d asks, want 4", rule.MaxPerSession)
	}
}

// The window is the deployed binary's mtime, the same one the evidence gate
// uses: the question is whether *this* build is deciding, so records from
// before it are not evidence about it.
func TestVerdictProfileHonoursTheMtimeWindow(t *testing.T) {
	cutoff := time.Date(2026, 9, 21, 12, 0, 0, 0, time.UTC)
	now := cutoff.Add(12 * time.Hour)
	segments := verdictSegment(t,
		verdictRecord("2026-09-21T06:00:00Z", "old", "deny", "P1.rm-rf"),
		verdictRecord("2026-09-21T18:00:00Z", "new", "deny", "P1.rm-rf"),
	)

	profile, err := ReadVerdictProfile(segments, "claude", cutoff, now)
	if err != nil {
		t.Fatal(err)
	}
	if profile.Stale != 1 {
		t.Errorf("stale = %d, want 1", profile.Stale)
	}
	rule, _ := findRule(profile, "P1.rm-rf")
	if rule.Deny != 1 {
		t.Errorf("deny inside the window = %d, want 1", rule.Deny)
	}
}

// An allow carries no rule id, and counting it under a rule would invent
// precision the log does not have. It still counts toward the decision totals,
// because "the guard allowed 11,000 things" is part of the answer.
func TestVerdictProfileKeepsUnruledAllowsOutOfTheRuleTable(t *testing.T) {
	cutoff := time.Date(2026, 9, 21, 0, 0, 0, 0, time.UTC)
	now := cutoff.Add(24 * time.Hour)
	segments := verdictSegment(t,
		verdictRecord("2026-09-21T01:00:00Z", "s1", "allow", ""),
		verdictRecord("2026-09-21T02:00:00Z", "s1", "deny", "P1.rm-rf"),
	)

	profile, err := ReadVerdictProfile(segments, "claude", cutoff, now)
	if err != nil {
		t.Fatal(err)
	}
	if profile.Allow != 1 || profile.Deny != 1 {
		t.Errorf("decision totals allow=%d deny=%d, want 1/1", profile.Allow, profile.Deny)
	}
	if _, ok := findRule(profile, ""); ok {
		t.Error("an empty rule id became a row in the rule table")
	}
}

// Rules are reported worst-first so the operator reads the pressure without
// sorting: most decisions first, ties broken by name for a stable output.
func TestVerdictProfileOrdersRulesByVolume(t *testing.T) {
	cutoff := time.Date(2026, 9, 21, 0, 0, 0, 0, time.UTC)
	now := cutoff.Add(24 * time.Hour)
	var lines []string
	for i := 0; i < 5; i++ {
		lines = append(lines, verdictRecord("2026-09-21T01:00:00Z", "s1", "ask", "loud"))
	}
	lines = append(lines, verdictRecord("2026-09-21T02:00:00Z", "s1", "deny", "quiet"))
	profile, err := ReadVerdictProfile(verdictSegment(t, lines...), "claude", cutoff, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(profile.Rules) != 2 || profile.Rules[0].RuleID != "loud" {
		t.Fatalf("rules = %+v, want loud first", profile.Rules)
	}
}

// Other planes are not this plane's evidence.
func TestVerdictProfileFiltersByPlane(t *testing.T) {
	cutoff := time.Date(2026, 9, 21, 0, 0, 0, 0, time.UTC)
	now := cutoff.Add(24 * time.Hour)
	segments := verdictSegment(t,
		verdictRecord("2026-09-21T01:00:00Z", "s1", "deny", "P1.rm-rf"),
		`{"ts":"2026-09-21T02:00:00Z","session_id":"s2","plane":"opencode","tool":"Bash","event":"pre","decision":"deny","rule_id":"P1.rm-rf"}`,
	)
	profile, err := ReadVerdictProfile(segments, "claude", cutoff, now)
	if err != nil {
		t.Fatal(err)
	}
	rule, _ := findRule(profile, "P1.rm-rf")
	if rule.Deny != 1 {
		t.Errorf("deny = %d, want 1: the opencode record is not claude's evidence", rule.Deny)
	}
}
