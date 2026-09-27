package main

import (
	"fmt"
	"io"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/CtrlCarlitos/agent-guardrails/internal/adapter"
	"github.com/CtrlCarlitos/agent-guardrails/internal/audit"
	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
	"github.com/CtrlCarlitos/agent-guardrails/internal/safetext"
)

const explainUsage = "guardrail: explain accepts [last | <timestamp> | <request-id> | <session-id>] [--last N] [--all] [--path <file>]"

// cmdExplain answers "why was this blocked, and what do I do about it" from
// one audit record (#106). It replaces the four-step investigation of grep the
// log, read rule_id and reason, find the guidance text, find the fix: the
// record, the verdict, the reason and the next step are printed together, and
// the next step is the adapter's own text (adapter.NextStep), so the operator
// reads exactly the continuation the agent was given.
//
// It reads the audit log and nothing else. It never re-evaluates a call: the
// policy may have changed since, and a verdict computed now would answer a
// different question from the one the record answers.
func cmdExplain(args []string, cwd string, stdout, stderr io.Writer) int {
	var path, selector string
	all := false
	count := 1
	for i := 0; i < len(args); i++ {
		switch arg := args[i]; arg {
		case "--path", "--last":
			if i+1 >= len(args) {
				fmt.Fprintln(stderr, explainUsage)
				return 2
			}
			i++
			if arg == "--path" {
				path = args[i]
				continue
			}
			n, err := strconv.Atoi(args[i])
			if err != nil || n < 1 {
				fmt.Fprintln(stderr, "guardrail: --last needs a positive number")
				return 2
			}
			count = n
		case "--all":
			all = true
		default:
			if strings.HasPrefix(arg, "-") || selector != "" {
				fmt.Fprintln(stderr, explainUsage)
				return 2
			}
			selector = arg
		}
	}
	if selector == "last" {
		selector = ""
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
		fmt.Fprintf(stderr, "guardrail: no audit log at %s; nothing has been decided here yet\n", safetext.SingleLine(path))
		return 1
	}
	records, malformed, err := audit.ReadRecords(segments)
	if err != nil {
		fmt.Fprintf(stderr, "guardrail: audit log unreadable: %s\n", safetext.SingleLine(err.Error()))
		return 2
	}

	matches, scope := selectExplainRecords(records, selector, repo, all)
	if len(matches) == 0 {
		fmt.Fprintf(stderr, "guardrail: no ask or deny record %s in %s (selftest probes excluded)\n", scope, safetext.SingleLine(path))
		if selector == "" && !all {
			fmt.Fprintln(stderr, "guardrail: `guardrail explain --all` searches every repository")
		}
		return 1
	}
	shown := matches[:min(count, len(matches))]
	for i, rec := range shown {
		if i > 0 {
			fmt.Fprintln(stdout)
		}
		printExplanation(rec, records, stdout)
	}
	if rest := len(matches) - len(shown); rest > 0 {
		fmt.Fprintf(stdout, "\n%d older matching record(s) not shown; --last N shows more\n", rest)
	}
	if malformed > 0 {
		fmt.Fprintf(stdout, "note: %d malformed audit line(s) skipped\n", malformed)
	}
	return 0
}

// selectExplainRecords returns the matching verdict records, newest first,
// and a phrase naming what was searched. With no selector the scope is this
// repository, plus records that name no repository (written before records
// carried one, or by a hook that failed closed before it could tell); an
// explicit timestamp, request ID or session ID is already specific, so it
// searches every repository.
func selectExplainRecords(records []audit.Record, selector, repo string, all bool) ([]audit.Record, string) {
	match := func(rec audit.Record) bool {
		return all || rec.RepoRoot == "" || sameRepoRoot(rec.RepoRoot, repo)
	}
	scope := "for " + safetext.SingleLine(repo)
	if all {
		scope = "in any repository"
	}
	if selector != "" {
		if at, err := time.Parse(time.RFC3339Nano, selector); err == nil {
			scope = "at " + selector
			match = func(rec audit.Record) bool {
				ts, err := time.Parse(time.RFC3339Nano, rec.TS)
				return err == nil && ts.Equal(at)
			}
		} else if hasRequest(records, selector) {
			scope = "for request " + safetext.SingleLine(selector)
			match = func(rec audit.Record) bool { return rec.RequestID == selector }
		} else {
			scope = "for session " + safetext.SingleLine(selector)
			match = func(rec audit.Record) bool { return rec.SessionID == selector }
		}
	}
	var out []audit.Record
	for i := len(records) - 1; i >= 0; i-- {
		if isExplainableVerdict(records[i]) && match(records[i]) {
			out = append(out, records[i])
		}
	}
	return out, scope
}

func hasRequest(records []audit.Record, id string) bool {
	for _, rec := range records {
		if rec.RequestID == id && isExplainableVerdict(rec) {
			return true
		}
	}
	return false
}

// isExplainableVerdict keeps the hook's ask, deny and brokered-action records.
// Operator-action bookkeeping (requested/completed) and grant issuance are the
// operator's own acts, not verdicts, and selftest probes deny on purpose on
// every update; without excluding them `explain` would mostly explain the last
// selftest (the runbook's `grep -v selftest`).
func isExplainableVerdict(rec audit.Record) bool {
	switch rec.Decision {
	case string(policy.Ask), string(policy.Deny), string(policy.Complete):
	default:
		return false
	}
	return rec.Plane != "operator" && rec.Event != "operator-action" && !strings.HasPrefix(rec.SessionID, "selftest-")
}

func printExplanation(rec audit.Record, records []audit.Record, stdout io.Writer) {
	line := func(label, value string) {
		if value != "" {
			fmt.Fprintf(stdout, "%-10s %s\n", label, safetext.SingleLine(value))
		}
	}
	session := rec.SessionID
	if session == "" {
		session = "(none)"
	}
	fmt.Fprintf(stdout, "record     %s  plane %s  session %s\n",
		safetext.SingleLine(rec.TS), safetext.SingleLine(rec.Plane), safetext.SingleLine(session))
	repo := rec.RepoRoot
	if repo == "" {
		repo = "(not recorded)"
	}
	line("repo", repo)
	tool := rec.Tool
	if rec.NativeTool != "" && rec.NativeTool != rec.Tool {
		tool += " (native " + rec.NativeTool + ")"
	}
	if rec.Capability != "" {
		tool += ", capability " + rec.Capability
	}
	line("tool", tool)
	line("command", rec.Command)
	line("paths", strings.Join(rec.Paths, ", "))
	rule := rec.RuleID
	if rule == "" {
		rule = "(none)"
	}
	fmt.Fprintf(stdout, "verdict    %s  rule %s\n", safetext.SingleLine(rec.Decision), safetext.SingleLine(rule))
	line("why", rec.Reason)

	v := policy.Verdict{
		Decision: policy.Decision(rec.Decision), RuleID: rec.RuleID, Reason: rec.Reason,
		OperatorAction: rec.OperatorAction, RequestID: rec.RequestID,
	}
	if rec.RuleID == "" && v.Decision == policy.Deny {
		// Guidance would render this as "the rule ID ()", which reads as a
		// rule with an empty name. There is no rule: say what happened.
		line("next step", noRuleNextStep(rec))
		line("agent saw", rec.Reason)
		return
	}
	line("next step", adapter.NextStep(v))
	line("operator", operatorNextStep(rec, records))
	if v.Decision == policy.Complete {
		return // NextStep already is the text the model was given.
	}
	fmt.Fprintln(stdout, "guidance the agent was given (re-rendered from this record; the exact tool arguments and the plane's wrapper may differ):")
	fmt.Fprintf(stdout, "  %s\n", safetext.SingleLine(adapter.Guidance(v, explainAction(rec))))
}

func noRuleNextStep(rec audit.Record) string {
	if rec.AuditKind == "hook-fail-closed" || strings.Contains(rec.Reason, "failing closed") {
		return "This deny has no rule ID because no policy rule decided it: the hook failed closed before it could evaluate the call, for the reason above (an unparseable payload, or a policy or Overlay that would not load or merge). The call itself was never judged. Run `guardrail doctor` in this repository and fix what it reports, then retry the call."
	}
	return "This deny carries no rule ID, so the record does not say which rule decided it. Run `guardrail doctor` in this repository; if it is clean, report the record to the operator."
}

// operatorNextStep is what only the operator can do about this record, derived
// from the record and from the same predicates that gate the operator's
// commands, so it never offers something the command would refuse.
func operatorNextStep(rec audit.Record, records []audit.Record) string {
	switch policy.Decision(rec.Decision) {
	case policy.Complete:
		status := "no operator record for it yet"
		for i := len(records) - 1; i >= 0; i-- {
			if records[i].RequestID == rec.RequestID && records[i].Event == "operator-action" {
				status = records[i].Decision
				break
			}
		}
		return fmt.Sprintf("`guardrail approvals approve %s` re-opens the passkey ceremony while the request is pending (`guardrail approvals list` shows pending requests); latest status in the audit log: %s", rec.RequestID, status)
	case policy.Ask:
		switch {
		case policy.NeverRelaxable(rec.RuleID):
			return rec.RuleID + " can never be granted: it stays a per-call operator decision (ADR-0018)"
		case policy.NeverGrantable(rec.RuleID):
			return rec.RuleID + " can never be granted: it is a fail-closed backstop"
		case rec.Command == "" || rec.RepoRoot == "":
			return ""
		case strings.Contains(rec.Command, "«redacted»"):
			return "the audit log redacted part of this command, so a grant built from the record could never match it; a grant needs the exact command, which the agent can quote"
		}
		return fmt.Sprintf("to authorize exactly this command once instead of approving it in chat, from the operator's own terminal: guardrail approvals grant --repo %s --rule %s --command %s",
			shellQuote(rec.RepoRoot), rec.RuleID, shellQuote(rec.Command))
	}
	return ""
}

// explainAction stands in for the native action the adapter quoted in the
// guidance. The record keeps the normalized command and paths, not the raw
// tool arguments, so this is a faithful summary rather than the wire bytes.
func explainAction(rec audit.Record) string {
	tool := rec.NativeTool
	if tool == "" {
		tool = rec.Tool
	}
	switch {
	case rec.Command != "":
		return tool + " " + rec.Command
	case len(rec.Paths) > 0:
		return tool + " " + strings.Join(rec.Paths, " ")
	}
	return tool
}

// shellQuote quotes s for the operator's shell: PowerShell on Windows, a POSIX
// shell elsewhere. Single quotes in both, so nothing inside is expanded.
func shellQuote(s string) string {
	if runtime.GOOS == "windows" {
		return "'" + strings.ReplaceAll(s, "'", "''") + "'"
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

func explainRepoRoot(cwd string) string {
	if root, ok := policy.FindRepoRoot(cwd); ok {
		return root
	}
	return cwd
}

// explainAuditPath resolves the audit log the hook writes for this directory:
// the default, or an Overlay redirect the Operator config authorized. Any
// failure to resolve policy falls back to the default path, which is also
// where a fail-closed deny is recorded.
func explainAuditPath(cwd, repo string) string {
	base, err := policy.LoadBase()
	if err != nil {
		return audit.DefaultPath("")
	}
	var ov *policy.Overlay
	if p, ok, _ := policy.FindOverlayPath(cwd); ok {
		if ov, err = policy.LoadOverlay(p); err != nil {
			return audit.DefaultPath("")
		}
	}
	op, _ := policy.LoadOperatorConfig()
	merged, _, err := policy.Merge(base, ov, version, op, repo)
	if err != nil {
		return audit.DefaultPath("")
	}
	return audit.DefaultPath(merged.Slots.AuditLog)
}

// sameRepoRoot compares repository roots the way the platform does: git on
// Windows may spell a root with forward slashes and any letter case, and on
// macOS a temp root is reachable through the /var -> /private/var symlink.
func sameRepoRoot(a, b string) bool {
	a, b = filepath.Clean(a), filepath.Clean(b)
	if a == b || runtime.GOOS == "windows" && strings.EqualFold(a, b) {
		return true
	}
	ra, errA := filepath.EvalSymlinks(a)
	rb, errB := filepath.EvalSymlinks(b)
	return errA == nil && errB == nil && ra == rb
}
