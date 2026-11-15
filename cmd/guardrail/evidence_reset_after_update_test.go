package main

import (
	"regexp"
	"strings"
	"testing"
	"time"
)

// #520: right after an update every real Claude record predates the new
// binary's mtime, so the scan counts them all stale and doctor printed the
// same "NEVER OBSERVED FIRING" warning it prints for a hook that never ran.
// The two states are different facts and must read differently; only the
// second is a warning.

const evidenceRealSession = "78f4afb7-748f-4af6-b026-51882e1865f3"

var evidenceCutoff = time.Date(2026, 10, 5, 10, 36, 3, 0, time.UTC) // binary mtime

func preUpdateRecords() []string {
	return []string{
		claudePreRecord(evidenceRealSession, "2026-10-05T09:00:00Z", "Bash", "allow"),
		claudePreRecord(evidenceRealSession, "2026-10-05T09:00:05Z", "Read", "deny"),
		claudePreRecord(evidenceRealSession, "2026-10-05T09:00:09Z", "Edit", "ask"),
	}
}

// The dotfiles console filter hides `<plane> settings: guardrail hook
// registered` followed by end-of-line or ';'. The reset line is information
// the operator should see after `dot up`, so it must not match.
var dotfilesRoutineSettingsLine = regexp.MustCompile(`^(claude|opencode|antigravity|codex) settings: guardrail (hook|hooks|integration) registered($|;)`)

func TestDoctorClaudeCaveatSeparatesWindowResetFromNeverFired(t *testing.T) {
	now := evidenceCutoff.Add(time.Hour)
	t.Run("all records predate this binary", func(t *testing.T) {
		got := claudeMediationCaveatFor(writeEvidenceSegment(t, preUpdateRecords()...), evidenceCutoff, now)
		want := " — evidence window reset by the recent update (3 earlier real-session records predate this binary): start a Claude session, then re-run `guardrail selftest --evidence claude`"
		if got != want {
			t.Fatalf("caveat =\n%q\nwant\n%q", got, want)
		}
		line := "claude settings: guardrail hook registered" + got
		if strings.Contains(line, "NEVER OBSERVED FIRING") {
			t.Fatalf("window reset must not read as the never-fired warning: %s", line)
		}
		if dotfilesRoutineSettingsLine.MatchString(line) {
			t.Fatalf("dotfiles console filter would hide the line: %s", line)
		}
	})
	t.Run("no qualifying records at all", func(t *testing.T) {
		got := claudeMediationCaveatFor(writeEvidenceSegment(t,
			claudePreRecord("night-claude", "2026-10-05T11:00:00Z", "Bash", "allow")), evidenceCutoff, now)
		want := " but NEVER OBSERVED FIRING — no audit record from a real session since this binary was built." +
			" Registration is not enforcement; confirm with `guardrail selftest --evidence claude`"
		if got != want {
			t.Fatalf("caveat =\n%q\nwant today's warning verbatim\n%q", got, want)
		}
	})
	t.Run("observed after the update", func(t *testing.T) {
		lines := append(preUpdateRecords(),
			claudePreRecord(evidenceRealSession, "2026-10-05T11:00:00Z", "Bash", "allow"),
			claudePreRecord(evidenceRealSession, "2026-10-05T11:00:05Z", "Read", "allow"))
		if got := claudeMediationCaveatFor(writeEvidenceSegment(t, lines...), evidenceCutoff, now); got != "" {
			t.Fatalf("caveat = %q, want none once mediation is observed", got)
		}
	})
}

func TestSelftestClaudeEvidenceSeparatesWindowResetFromNeverFired(t *testing.T) {
	now := evidenceCutoff.Add(time.Hour)
	t.Run("all records predate this binary", func(t *testing.T) {
		var out, errb strings.Builder
		code := printClaudeEvidence(writeEvidenceSegment(t, preUpdateRecords()...), evidenceCutoff, now, &out, &errb)
		if code != 1 {
			t.Fatalf("exit = %d, want 1: mediation by this binary is still unevidenced", code)
		}
		want := "claude: evidence window reset by the recent update (3 earlier real-session records predate this binary); start a Claude session, then re-run `guardrail selftest --evidence claude`\n"
		if !strings.HasSuffix(out.String(), want) {
			t.Fatalf("output does not end with\n%q\n%s", want, out.String())
		}
		if strings.Contains(out.String(), "not yet observed") {
			t.Fatalf("window reset must not read as never fired:\n%s", out.String())
		}
	})
	t.Run("no qualifying records at all", func(t *testing.T) {
		var out, errb strings.Builder
		code := printClaudeEvidence(writeEvidenceSegment(t,
			claudePreRecord("night-claude", "2026-10-05T11:00:00Z", "Bash", "allow")), evidenceCutoff, now, &out, &errb)
		want := "claude: live mediation not yet observed; the registered hook has produced no record from a real session\n"
		if code != 1 || !strings.HasSuffix(out.String(), want) {
			t.Fatalf("exit = %d, want 1 and today's line verbatim:\n%s", code, out.String())
		}
	})
}
