package main

import (
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/CtrlCarlitos/agent-guardrails/internal/audit"
	"github.com/CtrlCarlitos/agent-guardrails/internal/safetext"
)

type codexEvidenceOptions struct {
	SessionID     string
	Since         *time.Time
	ExpectedTools []string
}

func parseCodexEvidenceOptions(args []string, now time.Time, stderr io.Writer) (codexEvidenceOptions, bool) {
	var opts codexEvidenceOptions
	seenSince := false
	seenTools := map[string]bool{}
	for i := 0; i < len(args); i++ {
		flag := args[i]
		if i+1 >= len(args) {
			fmt.Fprintf(stderr, "guardrail: selftest --evidence codex: %s needs a value\n", safetext.SingleLine(flag))
			return opts, false
		}
		i++
		value := strings.TrimSpace(args[i])
		switch flag {
		case "--session":
			if opts.SessionID != "" || value == "" || len(value) > 256 {
				fmt.Fprintln(stderr, "guardrail: --session requires one nonempty session ID of at most 256 bytes")
				return opts, false
			}
			opts.SessionID = value
		case "--since":
			if seenSince || value == "" {
				fmt.Fprintln(stderr, "guardrail: --since may be supplied once")
				return opts, false
			}
			seenSince = true
			since, err := time.Parse(time.RFC3339Nano, value)
			if err != nil {
				duration, durationErr := time.ParseDuration(value)
				if durationErr != nil || duration <= 0 {
					fmt.Fprintln(stderr, "guardrail: --since requires RFC3339 or a positive duration such as 30m")
					return opts, false
				}
				since = now.Add(-duration)
			}
			if since.After(now) {
				fmt.Fprintln(stderr, "guardrail: --since cannot be in the future")
				return opts, false
			}
			opts.Since = &since
		case "--expect-tool":
			if value == "" {
				fmt.Fprintln(stderr, "guardrail: --expect-tool requires a nonempty tool name")
				return opts, false
			}
			for _, tool := range strings.Split(value, ",") {
				tool = strings.TrimSpace(tool)
				if tool == "" || len(tool) > 256 {
					fmt.Fprintln(stderr, "guardrail: --expect-tool names must be nonempty and at most 256 bytes")
					return opts, false
				}
				if !seenTools[tool] {
					seenTools[tool] = true
					opts.ExpectedTools = append(opts.ExpectedTools, tool)
				}
			}
		default:
			fmt.Fprintf(stderr, "guardrail: selftest --evidence codex: unknown argument %q\n", safetext.SingleLine(flag))
			return opts, false
		}
	}
	return opts, true
}

func cmdCodexEvidence(opts codexEvidenceOptions, stdout, stderr io.Writer) int {
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
	cutoff := info.ModTime()
	if opts.Since != nil {
		cutoff = *opts.Since
	}
	sessionsRoot, err := defaultCodexSessionsRoot()
	if err != nil {
		fmt.Fprintln(stderr, "guardrail: evidence unavailable: cannot locate Codex sessions")
		return 1
	}
	return printCodexEvidence(audit.DefaultPath(""), sessionsRoot, cutoff, time.Now(), opts, stdout, stderr)
}

func printCodexEvidence(path, sessionsRoot string, cutoff, now time.Time, opts codexEvidenceOptions, stdout, stderr io.Writer) int {
	fmt.Fprintf(stdout, "codex evidence: audit %s\ncutoff: %s\n", safetext.SingleLine(path), cutoff.UTC().Format(time.RFC3339Nano))
	if opts.Since != nil {
		fmt.Fprintln(stdout, "cutoff source: explicit --since")
	} else {
		fmt.Fprintln(stdout, "cutoff source: binary mtime")
	}
	fmt.Fprintf(stdout, "Codex sessions: %s\n", safetext.SingleLine(sessionsRoot))
	known, sessionErr := readCodexKnownSessions(sessionsRoot)
	var selected *codexKnownSession
	selection := "newest known session"
	if opts.SessionID != "" {
		selection = "explicit --session"
		for i := range known {
			if known[i].ID == opts.SessionID {
				selected = &known[i]
				break
			}
		}
	} else {
		for i := range known {
			if known[i].Started.After(cutoff) && !known[i].Started.After(now) {
				selected = &known[i]
				break
			}
		}
	}
	fmt.Fprintf(stdout, "known_sessions=%d selection=%s\n", len(known), selection)
	selectedID := "__guardrail_no_known_codex_session__"
	if selected == nil {
		fmt.Fprintln(stdout, "selected_session=none")
	} else {
		selectedID = selected.ID
		fmt.Fprintf(stdout, "selected_session=%s started=%s\n", safetext.SingleLine(selected.ID), selected.Started.UTC().Format(time.RFC3339Nano))
	}
	segments, scanErr := audit.Segments(path)
	var evidence audit.CodexEvidence
	if scanErr == nil {
		evidence, scanErr = audit.ReadCodexEvidenceFiltered(segments, cutoff, now, selectedID, opts.ExpectedTools)
	}
	fmt.Fprintf(stdout, "segments=%d records=%d codex=%d synthetic=%d stale=%d rejected=%d other_sessions=%d duplicates=%d malformed=%d eligible=%d sessions=%d qualifying_sessions=%d\n",
		len(segments), evidence.Records, evidence.Codex, evidence.Synthetic, evidence.Stale, evidence.Rejected, evidence.OtherSessions, evidence.Duplicates, evidence.Malformed, evidence.Eligible, evidence.Sessions, evidence.QualifiedSessions)
	fmt.Fprintf(stdout, "observed_tools=%s\n", evidenceList(evidence.ObservedTools))
	fmt.Fprintf(stdout, "expected_tools=%s\n", evidenceList(opts.ExpectedTools))
	fmt.Fprintf(stdout, "missing_expected_tools=%s\n", evidenceList(evidence.MissingExpectedTools))
	fmt.Fprintln(stdout, "note: heuristic only; two distinct pre-hook records in one non-synthetic session do not prove runtime provenance or complete tool mediation")
	fmt.Fprintln(stdout, "note: selected session evidence does not verify hosted tools or write_stdin; only explicitly expected tools are asserted")
	if selected != nil && evidence.Eligible == 0 {
		if opts.SessionID == "" {
			fmt.Fprintln(stdout, "codex: newest known Codex session is silent in the selected audit window")
		} else {
			fmt.Fprintln(stdout, "codex: explicitly selected Codex session is silent in the selected audit window")
		}
	}
	if sessionErr != nil {
		fmt.Fprintf(stderr, "guardrail: Codex session inventory incomplete: %s\n", safetext.SingleLine(sessionErr.Error()))
	}
	if opts.SessionID != "" && selected == nil && sessionErr == nil {
		fmt.Fprintf(stderr, "guardrail: requested Codex session %q is not present in the local rollout inventory\n", safetext.SingleLine(opts.SessionID))
	}
	if scanErr != nil {
		fmt.Fprintf(stderr, "guardrail: evidence scan incomplete: %s\n", safetext.SingleLine(scanErr.Error()))
	}
	if selected != nil && sessionErr == nil && scanErr == nil && evidence.Observed() {
		fmt.Fprintln(stdout, "codex: live mediation observed (heuristic); approval-proposal gate opens")
		return 0
	}
	fmt.Fprintln(stdout, "codex: live mediation not yet observed; approval-proposal gate remains closed")
	return 1
}

func evidenceList(values []string) string {
	if len(values) == 0 {
		return "none"
	}
	copyValues := append([]string(nil), values...)
	sort.Strings(copyValues)
	return safetext.SingleLine(strings.Join(copyValues, ","))
}
