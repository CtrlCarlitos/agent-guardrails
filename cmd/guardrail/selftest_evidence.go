package main

import (
	"fmt"
	"io"
	"os"
	"time"

	"github.com/CtrlCarlitos/agent-guardrails/internal/audit"
	"github.com/CtrlCarlitos/agent-guardrails/internal/safetext"
)

func cmdCodexEvidence(stdout, stderr io.Writer) int {
	return cmdPlaneEvidence("codex", stdout, stderr)
}

// cmdClaudeEvidence answers for claude the question ADR-0020 asks for codex:
// not whether the hook is registered, which doctor can see, but whether it
// ran, which only an audit record can show. #149 is why it exists.
func cmdClaudeEvidence(stdout, stderr io.Writer) int {
	return cmdPlaneEvidence("claude", stdout, stderr)
}

func cmdPlaneEvidence(plane string, stdout, stderr io.Writer) int {
	binary, err := os.Executable()
	if err != nil {
		fmt.Fprintln(stderr, "guardrail: evidence unavailable: cannot locate running binary")
		return 1
	}
	info, err := os.Stat(binary)
	if err != nil {
		fmt.Fprintln(stderr, "guardrail: evidence unavailable: cannot stat running binary")
		return 1
	}
	if plane == "claude" {
		return printClaudeEvidence(audit.DefaultPath(""), info.ModTime(), time.Now(), stdout, stderr)
	}
	return printCodexEvidence(audit.DefaultPath(""), info.ModTime(), time.Now(), stdout, stderr)
}

// printClaudeEvidence mirrors printCodexEvidence. The notes differ because the
// two gates answer differently-shaped doubts: codex's is about hosted tools
// bypassing hooks at runtime, claude's is about the hook command spawning at
// all.
func printClaudeEvidence(path string, cutoff, now time.Time, stdout, stderr io.Writer) int {
	fmt.Fprintf(stdout, "claude evidence: audit %s\nbinary mtime cutoff: %s\n", safetext.SingleLine(path), cutoff.UTC().Format(time.RFC3339Nano))
	segments, scanErr := audit.Segments(path)
	var evidence audit.CodexEvidence
	if scanErr == nil {
		evidence, scanErr = audit.ReadClaudeEvidence(segments, cutoff, now)
	}
	fmt.Fprintf(stdout, "segments=%d records=%d claude=%d synthetic=%d stale=%d rejected=%d duplicates=%d malformed=%d eligible=%d sessions=%d qualifying_sessions=%d\n",
		len(segments), evidence.Records, evidence.Codex, evidence.Synthetic, evidence.Stale, evidence.Rejected, evidence.Duplicates, evidence.Malformed, evidence.Eligible, evidence.Sessions, evidence.QualifiedSessions)
	fmt.Fprintln(stdout, "note: heuristic only; a real session id and two pre-hook records show the hook ran, not that every tool call reached it")
	fmt.Fprintln(stdout, "note: counts cover retained segments after the running binary's mtime, so a rebuild resets the window")
	if scanErr != nil {
		fmt.Fprintf(stderr, "guardrail: evidence scan incomplete: %s\n", safetext.SingleLine(scanErr.Error()))
	}
	if scanErr == nil && evidence.Observed() {
		fmt.Fprintln(stdout, "claude: live mediation observed (heuristic); the registered hook is running")
		return 0
	}
	fmt.Fprintln(stdout, "claude: live mediation not yet observed; the registered hook has produced no record from a real session")
	return 1
}

func printCodexEvidence(path string, cutoff, now time.Time, stdout, stderr io.Writer) int {
	fmt.Fprintf(stdout, "codex evidence: audit %s\nbinary mtime cutoff: %s\n", safetext.SingleLine(path), cutoff.UTC().Format(time.RFC3339Nano))
	segments, scanErr := audit.Segments(path)
	var evidence audit.CodexEvidence
	if scanErr == nil {
		evidence, scanErr = audit.ReadCodexEvidence(segments, cutoff, now)
	}
	fmt.Fprintf(stdout, "segments=%d records=%d codex=%d synthetic=%d stale=%d rejected=%d duplicates=%d malformed=%d eligible=%d sessions=%d qualifying_sessions=%d\n",
		len(segments), evidence.Records, evidence.Codex, evidence.Synthetic, evidence.Stale, evidence.Rejected, evidence.Duplicates, evidence.Malformed, evidence.Eligible, evidence.Sessions, evidence.QualifiedSessions)
	fmt.Fprintln(stdout, "note: heuristic only; two distinct pre-hook records in one non-synthetic session do not prove runtime provenance or complete tool mediation")
	fmt.Fprintln(stdout, "note: older qualifying sessions can mask a newer silent session; this is not a per-session regression tripwire and does not verify hosted tools or write_stdin")
	if scanErr != nil {
		fmt.Fprintf(stderr, "guardrail: evidence scan incomplete: %s\n", safetext.SingleLine(scanErr.Error()))
	}
	if scanErr == nil && evidence.Observed() {
		fmt.Fprintln(stdout, "codex: live mediation observed (heuristic); approval-proposal gate opens")
		return 0
	}
	fmt.Fprintln(stdout, "codex: live mediation not yet observed; approval-proposal gate remains closed")
	return 1
}
