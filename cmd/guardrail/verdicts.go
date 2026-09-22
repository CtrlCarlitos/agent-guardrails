package main

import (
	"fmt"
	"io"
	"os"
	"text/tabwriter"
	"time"

	"github.com/CtrlCarlitos/agent-guardrails/internal/audit"
	"github.com/CtrlCarlitos/agent-guardrails/internal/safetext"
)

// cmdVerdicts is the operator's answer to "is the guard deciding correctly",
// as distinct from the evidence gate's "is the guard present". The gate counts
// records; a guard that runs and allows everything passes it. This names the
// rules that fired.
func cmdVerdicts(path string, stdout, stderr io.Writer) int {
	binary, err := os.Executable()
	if err != nil {
		fmt.Fprintln(stderr, "guardrail: verdicts unavailable: cannot locate running binary")
		return 1
	}
	info, err := os.Stat(binary)
	if err != nil {
		fmt.Fprintln(stderr, "guardrail: verdicts unavailable: cannot stat running binary")
		return 1
	}
	return printVerdictProfile(path, "claude", info.ModTime(), time.Now(), stdout, stderr)
}

func printVerdictProfile(path, plane string, cutoff, now time.Time, stdout, stderr io.Writer) int {
	fmt.Fprintf(stdout, "verdict profile: audit %s\nbinary mtime cutoff: %s\n",
		safetext.SingleLine(path), cutoff.UTC().Format(time.RFC3339Nano))

	segments, err := audit.Segments(path)
	if err != nil {
		fmt.Fprintf(stderr, "guardrail: audit log unavailable: %v\n", err)
		return 1
	}
	if len(segments) == 0 {
		// "There is no audit log" and "the guard decided nothing" are
		// different answers, and the second one is reassuring. Never let the
		// first render as the second.
		fmt.Fprintf(stderr, "guardrail: no audit log at %s -- this is not evidence that nothing was decided\n",
			safetext.SingleLine(path))
		return 1
	}
	profile, err := audit.ReadVerdictProfile(segments, plane, cutoff, now)
	if err != nil {
		fmt.Fprintf(stderr, "guardrail: verdict profile unavailable: %v\n", err)
		return 1
	}

	fmt.Fprintf(stdout, "decisions: allow=%d ask=%d deny=%d  sessions=%d  stale=%d malformed=%d\n",
		profile.Allow, profile.Ask, profile.Deny, profile.Sessions, profile.Stale, profile.Malformed)

	if len(profile.Rules) == 0 {
		// Not an error. A freshly deployed binary has decided nothing yet,
		// which is the same state the evidence gate reports as eligible=0 on
		// its first run.
		fmt.Fprintln(stdout, "no decisions attributed to a rule in this window (a fresh deploy starts here)")
		fmt.Fprintln(stdout, "note: rule attribution covers ask and deny; an allow usually matches no rule")
		return 0
	}

	table := tabwriter.NewWriter(stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(table, "rule\tdeny\task\tallow\tsessions\tworst session")
	for _, rule := range profile.Rules {
		fmt.Fprintf(table, "%s\t%d\t%d\t%d\t%d\t%d\n",
			safetext.SingleLine(rule.RuleID), rule.Deny, rule.Ask, rule.Allow, rule.Sessions, rule.MaxPerSession)
	}
	_ = table.Flush()

	printAskPressure(profile, stdout)

	fmt.Fprintln(stdout, "note: rule attribution covers ask and deny; an allow usually matches no rule")
	fmt.Fprintln(stdout, "note: counts cover retained segments after the running binary's mtime, so a redeploy resets the window")
	return 0
}

// printAskPressure reports how hard the asking rules lean on a single session.
//
// This is deliberately not the answered-yes-without-reading ratio that would
// measure fatigue directly. guardrail never learns how a prompt was answered:
// the hook returns "ask", the human answers inside the plane, and no record
// comes back — there is no second event to time or to read an outcome from.
// What the log does show is concentration, and a rule asked six times in one
// session is eroding trust whether or not the answers are visible.
func printAskPressure(profile audit.VerdictProfile, stdout io.Writer) {
	var worst audit.RuleProfile
	repeated := 0
	for _, rule := range profile.Rules {
		if rule.Ask == 0 {
			continue
		}
		repeated += rule.RepeatSessions
		if rule.MaxPerSession > worst.MaxPerSession {
			worst = rule
		}
	}
	if worst.RuleID == "" {
		fmt.Fprintln(stdout, "ask pressure: no asks in this window")
		return
	}
	fmt.Fprintf(stdout, "ask pressure: worst is %s at %d asks in one session; %d rule-session pairs asked more than once\n",
		safetext.SingleLine(worst.RuleID), worst.MaxPerSession, repeated)
	fmt.Fprintln(stdout, "note: guardrail cannot see how an ask was answered -- the plane owns the prompt -- so this measures how often the operator is interrupted, not whether they stopped reading")
}
