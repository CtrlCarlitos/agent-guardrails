package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"github.com/CtrlCarlitos/agent-guardrails/internal/audit"
	"github.com/CtrlCarlitos/agent-guardrails/internal/safetext"
)

const reportUsage = "guardrail: report accepts [--id <timestamp|request-id|session-id> | --last N] [--all] [--path <file>]"

const reportNewIssueURL = "https://github.com/CtrlCarlitos/agent-guardrails/issues/new"

// cmdReport turns one audit record into a ready-to-paste GitHub issue (#124):
// a title and a Markdown body on stdout, with what to review on stderr.
//
// It prints and does nothing else. Filing stays the reporter's own act: the
// body can hold paths and commands they consider private, and a command
// that reached the network to file it would itself need egress the session
// may not have. It never imports net or os/exec (a test pins that).
func cmdReport(args []string, cwd string, stdout, stderr io.Writer) int {
	var path, id string
	all := false
	nth := 0
	for i := 0; i < len(args); i++ {
		switch arg := args[i]; arg {
		case "--path", "--id", "--last":
			if i+1 >= len(args) {
				fmt.Fprintln(stderr, reportUsage)
				return 2
			}
			i++
			switch arg {
			case "--path":
				path = args[i]
			case "--id":
				id = args[i]
			default:
				n, err := strconv.Atoi(args[i])
				if err != nil || n < 1 {
					fmt.Fprintln(stderr, "guardrail: --last needs a positive number")
					return 2
				}
				nth = n
			}
		case "--all":
			all = true
		default:
			fmt.Fprintln(stderr, reportUsage)
			return 2
		}
	}
	if id != "" && nth != 0 {
		fmt.Fprintln(stderr, "guardrail: report takes --id or --last, not both")
		return 2
	}
	if nth == 0 {
		nth = 1
	}

	repo := explainRepoRoot(cwd)
	if path == "" {
		path = explainAuditPath(cwd, repo)
	}
	segments, err := audit.Segments(path)
	if err != nil {
		fmt.Fprintf(stderr, "guardrail: audit log unavailable: %s\n", safetext.SingleLine(err.Error()))
		return 2
	}
	if len(segments) == 0 {
		fmt.Fprintf(stderr, "guardrail: no audit log at %s; nothing to report\n", safetext.SingleLine(path))
		return 1
	}
	records, _, err := audit.ReadRecords(segments)
	if err != nil {
		fmt.Fprintf(stderr, "guardrail: audit log unreadable: %s\n", safetext.SingleLine(err.Error()))
		return 2
	}
	matches, scope := selectExplainRecords(records, id, repo, all)
	if len(matches) == 0 {
		fmt.Fprintf(stderr, "guardrail: no ask or deny record %s in %s (selftest probes excluded)\n", scope, safetext.SingleLine(path))
		return 1
	}
	if nth > len(matches) {
		fmt.Fprintf(stderr, "guardrail: --last %d, but there are only %d matching record(s) %s\n", nth, len(matches), scope)
		return 1
	}
	rec := matches[nth-1]
	fmt.Fprint(stdout, renderReport(rec, newReportScrubber()))
	fmt.Fprintf(stderr, "guardrail: review this report before posting: secrets the audit redaction recognises show as «redacted» and your home directory as ~, but paths and commands you consider private may remain. Paste the title and body at %s\n", reportNewIssueURL)
	return 0
}

// reportScrubber is the redaction guarantee: every field a report prints
// goes through the audit log's own redaction, then has the reporter's home
// directory replaced by ~.
type reportScrubber struct{ homes []string }

func newReportScrubber() reportScrubber {
	var s reportScrubber
	if home, err := os.UserHomeDir(); err == nil && home != "" && home != string(filepath.Separator) {
		s.homes = append(s.homes, home)
		if slash := filepath.ToSlash(home); slash != home {
			s.homes = append(s.homes, slash)
		}
	}
	return s
}

func (s reportScrubber) clean(v string) string {
	v = audit.Redact(v)
	for _, home := range s.homes {
		if runtime.GOOS == "windows" {
			v = replaceFold(v, home, "~")
		} else {
			v = strings.ReplaceAll(v, home, "~")
		}
	}
	return v
}

// replaceFold replaces every case-insensitive occurrence of old: Windows
// spells the same home directory with any letter case.
func replaceFold(s, old, repl string) string {
	if old == "" {
		return s
	}
	lower, lowerOld := strings.ToLower(s), strings.ToLower(old)
	var b strings.Builder
	for {
		i := strings.Index(lower, lowerOld)
		if i < 0 {
			b.WriteString(s)
			return b.String()
		}
		b.WriteString(s[:i])
		b.WriteString(repl)
		s, lower = s[i+len(old):], lower[i+len(old):]
	}
}

func renderReport(rec audit.Record, scrub reportScrubber) string {
	clean := func(v string) string { return safetext.SingleLine(scrub.clean(v)) }
	rule := rec.RuleID
	if rule == "" {
		rule = "no rule (hook failed closed)"
	}
	summary := clean(rec.Reason)
	if r := []rune(summary); len(r) > 72 {
		summary = string(r[:71]) + "…"
	}
	if summary == "" {
		summary = rec.Decision + " of " + clean(rec.Tool)
	}

	var b strings.Builder
	fmt.Fprintf(&b, "Title: [bug] %s: %s\n\n", clean(rule), summary)
	b.WriteString("## What happened\n\n")
	fmt.Fprintf(&b, "guardrail returned **%s** under rule %s.\n\n", clean(rec.Decision), codeSpan(clean(rule)))
	item := func(label, value string) {
		if value != "" {
			fmt.Fprintf(&b, "- **%s:** %s\n", label, value)
		}
	}
	item("guardrail version", codeSpan(version))
	item("OS", runtime.GOOS+"/"+runtime.GOARCH)
	item("plane", clean(rec.Plane)+" (event "+clean(rec.Event)+")")
	item("when", clean(rec.TS))
	tool := clean(rec.Tool)
	if rec.NativeTool != "" && rec.NativeTool != rec.Tool {
		tool += " (native " + clean(rec.NativeTool) + ")"
	}
	if rec.Capability != "" {
		tool += ", capability " + clean(rec.Capability)
	}
	item("tool", tool)
	var paths []string
	for _, p := range rec.Paths {
		paths = append(paths, codeSpan(clean(p)))
	}
	item("paths", strings.Join(paths, ", "))
	if rec.RepoRoot != "" {
		item("repository", codeSpan(clean(rec.RepoRoot)))
	}
	item("reason given", clean(rec.Reason))
	if rec.Command != "" {
		cmd := scrub.clean(rec.Command)
		fence := strings.Repeat("`", max(3, longestBacktickRun(cmd)+1))
		fmt.Fprintf(&b, "\nCommand:\n\n%s\n%s\n%s\n", fence, cmd, fence)
	}
	b.WriteString("\n## What were you trying to do?\n\n<!-- the action the agent was attempting, and why -->\n")
	b.WriteString("\n## Why does this verdict look wrong?\n\n<!-- a false positive, a deny with no useful next step, a missing check… -->\n")
	b.WriteString("\n## What did you do instead?\n\n<!-- -->\n")
	fmt.Fprintf(&b, "\n---\nGenerated by `guardrail report` from the audit record at %s. Secrets the audit redaction recognises show as «redacted» and the home directory as ~.\n", clean(rec.TS))
	return b.String()
}

// codeSpan wraps v in a Markdown code span whose delimiter is longer than
// any backtick run inside it, so a value cannot close the span early.
func codeSpan(v string) string {
	if v == "" {
		return ""
	}
	tick := strings.Repeat("`", longestBacktickRun(v)+1)
	if strings.HasPrefix(v, "`") || strings.HasSuffix(v, "`") {
		return tick + " " + v + " " + tick
	}
	return tick + v + tick
}

func longestBacktickRun(s string) int {
	best, run := 0, 0
	for _, r := range s {
		if r == '`' {
			run++
			best = max(best, run)
		} else {
			run = 0
		}
	}
	return best
}
