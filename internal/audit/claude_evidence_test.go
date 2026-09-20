package audit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writeClaudeSegment(t *testing.T, lines ...string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func claudeRecord(session, ts, tool, decision string) string {
	return `{"ts":"` + ts + `","plane":"claude","session_id":"` + session +
		`","event":"pre","tool":"` + tool + `","decision":"` + decision + `"}`
}

// Registration is a claim; an audit record is evidence. doctor could only ever
// check the first, so a hook that registered and could not spawn read as green
// for four days while nothing was enforced (#149, fail-open class #151). The
// claude gate answers the other question, the same way ADR-0020's codex gate
// does: two distinct pre-hook records in one real session.
func TestClaudeEvidenceOpensOnTwoRecordsInOneRealSession(t *testing.T) {
	cutoff := time.Date(2026, 9, 20, 0, 0, 0, 0, time.UTC)
	now := cutoff.Add(time.Hour)
	const session = "78f4afb7-748f-4af6-b026-51882e1865f3"
	path := writeClaudeSegment(t,
		claudeRecord(session, "2026-09-20T00:10:00Z", "Bash", "allow"),
		claudeRecord(session, "2026-09-20T00:10:05Z", "Read", "deny"),
	)
	e, err := ReadClaudeEvidence([]string{path}, cutoff, now)
	if err != nil {
		t.Fatal(err)
	}
	if !e.Observed() {
		t.Fatalf("two distinct pre records in one real session did not open the gate: %+v", e)
	}
}

// One record is one tool call. It proves a hook ran once, not that the plane
// is mediated; the codex gate wants two and so does this one.
func TestClaudeEvidenceStaysClosedOnASingleRecord(t *testing.T) {
	cutoff := time.Date(2026, 9, 20, 0, 0, 0, 0, time.UTC)
	path := writeClaudeSegment(t,
		claudeRecord("78f4afb7-748f-4af6-b026-51882e1865f3", "2026-09-20T00:10:00Z", "Bash", "allow"))
	e, err := ReadClaudeEvidence([]string{path}, cutoff, cutoff.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if e.Observed() {
		t.Fatalf("a single record opened the gate: %+v", e)
	}
}

// This is the case that matters on a real machine, and the reason the claude
// gate does not reuse codex's prefix denylist.
//
// Every claude record in this repo's own audit log came from a test fixture or
// a probe: `night-claude`, `trifecta-sess-1`, `waived-session`, `lone-sess`,
// `../unsafe`, `c1`, `s1`, `approval-claude`, `manual-probe-1`. A denylist
// would have to enumerate all of them and every one added later, and an
// incomplete denylist opens the gate falsely — the exact failure class this
// gate exists to catch. A real Claude Code session id is a UUID, so the gate
// asks for that shape instead: forging one is a deliberate act, forgetting to
// add a prefix is an accident.
func TestClaudeEvidenceStaysClosedForFixtureSessions(t *testing.T) {
	cutoff := time.Date(2026, 9, 20, 0, 0, 0, 0, time.UTC)
	for _, session := range []string{
		"night-claude", "trifecta-sess-1", "waived-session", "lone-sess",
		"../unsafe", "c1", "s1", "approval-claude", "manual-probe-1",
		"selftest-1789900447215", "fixture-a", "live-shape-149",
	} {
		path := writeClaudeSegment(t,
			claudeRecord(session, "2026-09-20T00:10:00Z", "Bash", "allow"),
			claudeRecord(session, "2026-09-20T00:10:05Z", "Read", "deny"),
		)
		e, err := ReadClaudeEvidence([]string{path}, cutoff, cutoff.Add(time.Hour))
		if err != nil {
			t.Fatal(err)
		}
		if e.Observed() {
			t.Errorf("fixture session %q opened the gate: %+v", session, e)
		}
	}
}

// Other planes' traffic is not claude's evidence. opencode and antigravity
// were mediated continuously on the machine where claude was not, so a gate
// that counted any record would have reported claude healthy throughout.
func TestClaudeEvidenceIgnoresOtherPlanes(t *testing.T) {
	cutoff := time.Date(2026, 9, 20, 0, 0, 0, 0, time.UTC)
	const session = "78f4afb7-748f-4af6-b026-51882e1865f3"
	path := writeClaudeSegment(t,
		strings.Replace(claudeRecord(session, "2026-09-20T00:10:00Z", "Bash", "allow"), `"claude"`, `"opencode"`, 1),
		strings.Replace(claudeRecord(session, "2026-09-20T00:10:05Z", "Read", "deny"), `"claude"`, `"antigravity"`, 1),
	)
	e, err := ReadClaudeEvidence([]string{path}, cutoff, cutoff.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if e.Observed() {
		t.Fatalf("another plane's records opened the claude gate: %+v", e)
	}
}

// The codex gate keeps its exact semantics: this change generalises the
// scanner, and a shared scanner that quietly changed codex's answer would be a
// regression in an ADR-0020 invariant.
func TestCodexEvidenceSemanticsAreUnchangedByTheSharedScanner(t *testing.T) {
	cutoff := time.Date(2026, 9, 20, 0, 0, 0, 0, time.UTC)
	now := cutoff.Add(time.Hour)
	// codex's real session ids are not UUIDs; the codex gate must not start
	// demanding the shape the claude gate demands.
	path := writeClaudeSegment(t,
		strings.Replace(claudeRecord("ses_f42343a24ffechTGgmk6Go7BVS", "2026-09-20T00:10:00Z", "Bash", "allow"), `"claude"`, `"codex"`, 1),
		strings.Replace(claudeRecord("ses_f42343a24ffechTGgmk6Go7BVS", "2026-09-20T00:10:05Z", "Read", "deny"), `"claude"`, `"codex"`, 1),
	)
	e, err := ReadCodexEvidence([]string{path}, cutoff, now)
	if err != nil {
		t.Fatal(err)
	}
	if !e.Observed() {
		t.Fatalf("codex gate no longer opens on its own evidence shape: %+v", e)
	}
}
