package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/CtrlCarlitos/agent-guardrails/internal/audit"
	"github.com/CtrlCarlitos/agent-guardrails/internal/safetext"
)

const tailUsage = `usage:
  guardrail tail [--format compact|json] [--plane <name>] [--verdict allow|ask|deny|complete] [--lines N] [--path <file>]
  guardrail audit --follow [same flags]

Streams new Guardrail decision records in real time as they are appended to the
audit log, following 20MB segment rotations.

Flags:
  --format compact|json   output format (default: compact)
  --plane <name>          filter by plane (claude, opencode, antigravity, codex, operator)
  --verdict <decision>    filter by verdict (allow, ask, deny, complete)
  --lines N, -n N         emit up to N recent matching records before following (default: 0)
  --path <file>           audit log path override
`

// tailContext supplies the cancellation context for `guardrail tail`.
// Overridden in tests so CLI streaming tests stop cleanly without OS signals.
var tailContext = func() (context.Context, context.CancelFunc) {
	return signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
}

func cmdTail(args []string, stdout, stderr io.Writer) int {
	for _, a := range args {
		if a == "-h" || a == "--help" || a == "help" {
			fmt.Fprint(stdout, tailUsage)
			return 0
		}
	}

	fs := flag.NewFlagSet("tail", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {}
	var (
		format  string
		plane   string
		verdict string
		path    string
		lines   int
	)
	fs.StringVar(&format, "format", "compact", "output format: compact or json")
	fs.StringVar(&plane, "plane", "", "filter by plane")
	fs.StringVar(&verdict, "verdict", "", "filter by verdict")
	fs.StringVar(&path, "path", "", "audit log path override")
	fs.IntVar(&lines, "lines", 0, "initial matching records to emit before following")
	fs.IntVar(&lines, "n", 0, "shorthand for --lines")

	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		fmt.Fprintln(stderr, "guardrail: tail takes no positional arguments (see `guardrail tail --help`)")
		return 2
	}
	format = strings.ToLower(strings.TrimSpace(format))
	if format != "compact" && format != "json" {
		fmt.Fprintf(stderr, "guardrail: tail --format must be compact or json (got %q)\n", safetext.SingleLine(format))
		return 2
	}
	plane = strings.ToLower(strings.TrimSpace(plane))
	if plane != "" && !validTailPlane(plane) {
		fmt.Fprintf(stderr, "guardrail: tail --plane must be claude, opencode, antigravity, codex, or operator (got %q)\n", safetext.SingleLine(plane))
		return 2
	}
	verdict = strings.ToLower(strings.TrimSpace(verdict))
	if verdict != "" && !validTailVerdict(verdict) {
		fmt.Fprintf(stderr, "guardrail: tail --verdict must be allow, ask, deny, or complete (got %q)\n", safetext.SingleLine(verdict))
		return 2
	}
	if lines < 0 {
		fmt.Fprintln(stderr, "guardrail: tail --lines must be >= 0")
		return 2
	}

	ctx, cancel := tailContext()
	defer cancel()

	err := audit.Tail(ctx, audit.TailOptions{
		Path:         path,
		InitialLines: lines,
		Filter: audit.TailFilter{
			Plane:   plane,
			Verdict: verdict,
		},
		Emit: func(rec audit.Record) error {
			var line string
			if format == "json" {
				var err error
				line, err = formatTailJSON(rec)
				if err != nil {
					return err
				}
			} else {
				line = formatTailCompact(rec)
			}
			_, err := fmt.Fprintln(stdout, line)
			return err
		},
	})
	if err != nil {
		fmt.Fprintf(stderr, "guardrail: tail failed: %s\n", safetext.SingleLine(err.Error()))
		return 1
	}
	return 0
}

func validTailPlane(p string) bool {
	switch p {
	case "claude", "opencode", "antigravity", "codex", "operator":
		return true
	default:
		return false
	}
}

func validTailVerdict(v string) bool {
	switch v {
	case "allow", "ask", "deny", "complete":
		return true
	default:
		return false
	}
}

func formatTailJSON(rec audit.Record) (string, error) {
	if rec.Command != "" {
		rec.Command = audit.Redact(rec.Command)
	}
	if rec.Reason != "" {
		rec.Reason = audit.Redact(rec.Reason)
	}
	b, err := json.Marshal(rec)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func formatTailCompact(rec audit.Record) string {
	ts := formatTailTimestamp(rec.TS)
	plane := safetext.SingleLine(rec.Plane)
	if plane == "" {
		plane = "-"
	}
	tool := rec.NativeTool
	if tool == "" {
		tool = rec.Tool
	}
	tool = safetext.SingleLine(tool)
	if tool == "" {
		tool = "-"
	}
	target := tailTargetSummary(rec)
	decision := strings.ToUpper(safetext.SingleLine(rec.Decision))
	if decision == "" {
		decision = "-"
	}

	var b strings.Builder
	fmt.Fprintf(&b, "%-12s  %-11s  %-14s  %-32s  %-5s", ts, plane, tool, target, decision)
	if rec.RuleID != "" {
		fmt.Fprintf(&b, "  [%s]", safetext.SingleLine(rec.RuleID))
	}
	if rec.HookMS > 0 {
		fmt.Fprintf(&b, " (%.1fms)", rec.HookMS)
	}
	return b.String()
}

func formatTailTimestamp(raw string) string {
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339} {
		if t, err := time.Parse(layout, raw); err == nil {
			return t.UTC().Format("15:04:05.000")
		}
	}
	s := safetext.SingleLine(raw)
	if s == "" {
		return "--:--:--.---"
	}
	return s
}

func tailTargetSummary(rec audit.Record) string {
	var raw string
	switch {
	case len(rec.Paths) > 0 && rec.Paths[0] != "":
		raw = rec.Paths[0]
	case rec.Command != "":
		raw = audit.Redact(rec.Command)
	case rec.OperatorAction != "":
		raw = rec.OperatorAction
	default:
		return "-"
	}
	clean := safetext.SingleLine(raw)
	const maxRunes = 48
	runes := []rune(clean)
	if len(runes) > maxRunes {
		return string(runes[:maxRunes-1]) + "…"
	}
	return clean
}
