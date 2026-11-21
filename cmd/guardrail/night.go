package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/CtrlCarlitos/agent-guardrails/internal/approval"
	"github.com/CtrlCarlitos/agent-guardrails/internal/night"
	"github.com/CtrlCarlitos/agent-guardrails/internal/pathutil"
	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
	"github.com/CtrlCarlitos/agent-guardrails/internal/safetext"
)

const defaultNightDuration = 8 * time.Hour

func init() {
	approval.RegisterAction("night-on", executeNightApproval)
	approval.RegisterAction("night-off", executeNightApproval)
}

func executeNightApproval(r approval.Request) error {
	alreadyCompleted, err := startActionAudit(r)
	if err != nil {
		return err
	}
	if alreadyCompleted {
		return nil
	}
	path, err := night.DefaultPath()
	if err != nil {
		return err
	}
	if r.Action == "night-off" {
		if err := night.Remove(path); err != nil {
			return err
		}
		// The mutation is durable; leave completion audit recovery pending on failure.
		_ = completeActionAudit(r)
		return nil
	}
	until, err := time.Parse(time.RFC3339Nano, r.Parameters["expires_at"])
	if err != nil || until.UTC().Format(time.RFC3339Nano) != r.Parameters["expires_at"] {
		return fmt.Errorf("invalid approved night expiry")
	}
	hostname, err := os.Hostname()
	if err != nil {
		return fmt.Errorf("resolving hostname: %w", err)
	}
	if err := night.Write(path, night.Marker{Until: until, SetBy: fmt.Sprintf("%s:%d", hostname, os.Getpid())}); err != nil {
		return err
	}
	_ = completeActionAudit(r)
	return nil
}

const nightUsage = `usage:
  guardrail night on [--scope global|repo|session] [--repo <path>] [--session <id>] [--until HH:MM | --for 8h]
  guardrail night off
  guardrail night status
`

func cmdNight(args []string, operatorTerminal bool, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "guardrail: night requires on, off, or status")
		return 2
	}
	if args[0] == "help" || args[0] == "-h" || args[0] == "--help" {
		fmt.Fprint(stdout, nightUsage)
		return 0
	}
	if (args[0] == "on" || args[0] == "off") && !operatorTerminal {
		if code, handled := nightViaHostApproval(args, stdout, stderr); handled {
			return code
		}
		fmt.Fprintln(stderr, "night mode is an operator action; run it from a terminal")
		return 2
	}
	path, err := night.DefaultPath()
	if err != nil {
		return nightError(err, stderr)
	}

	switch args[0] {
	case "on":
		return cmdNightOn(path, args[1:], stdout, stderr)
	case "off":
		if len(args) != 1 {
			fmt.Fprintln(stderr, "guardrail: night off takes no arguments")
			return 2
		}
		if err := night.Remove(path); err != nil {
			return nightError(err, stderr)
		}
		fmt.Fprintln(stdout, "night mode off")
		return 0
	case "status":
		if len(args) != 1 {
			fmt.Fprintln(stderr, "guardrail: night status takes no arguments")
			return 2
		}
		state, err := night.Load(path, time.Now())
		if err != nil {
			return nightError(err, stderr)
		}
		if !state.Active {
			fmt.Fprintln(stdout, "night mode inactive")
			return 1
		}
		fmt.Fprintln(stdout, state.Banner())
		return 0
	default:
		fmt.Fprintf(stderr, "guardrail: unknown night action %q\n", args[0])
		return 2
	}
}

func cmdNightOn(path string, args []string, stdout, stderr io.Writer) int {
	for _, flagName := range []string{"for", "until", "scope", "repo", "session"} {
		if repeatedNightFlag(args, flagName) {
			fmt.Fprintf(stderr, "guardrail: night on accepts --%s at most once\n", flagName)
			return 2
		}
	}
	fs := flag.NewFlagSet("night on", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {}
	var durationText, untilText, scopeText, repoText, sessionText string
	fs.StringVar(&durationText, "for", "", "night mode duration")
	fs.StringVar(&untilText, "until", "", "next local clock time")
	fs.StringVar(&scopeText, "scope", night.ScopeGlobal, "lease scope: global, repo, or session")
	fs.StringVar(&repoText, "repo", "", "target repository path (only with --scope repo)")
	fs.StringVar(&sessionText, "session", "", "target session ID (only with --scope session)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	set := make(map[string]bool)
	fs.Visit(func(f *flag.Flag) { set[f.Name] = true })
	if fs.NArg() != 0 {
		fmt.Fprintln(stderr, "guardrail: night on takes no positional arguments")
		return 2
	}
	if set["for"] && set["until"] {
		fmt.Fprintln(stderr, "guardrail: night on accepts only one of --for and --until")
		return 2
	}
	if set["for"] && durationText == "" || set["until"] && untilText == "" {
		fmt.Fprintln(stderr, "guardrail: night expiry flag cannot be empty")
		return 2
	}

	scope := strings.ToLower(strings.TrimSpace(scopeText))
	if scope == "" {
		scope = night.ScopeGlobal
	}
	var targetRepo, targetSession string
	switch scope {
	case night.ScopeGlobal:
		if set["repo"] || set["session"] {
			fmt.Fprintln(stderr, "guardrail: --repo and --session require --scope repo or --scope session")
			return 2
		}
	case night.ScopeRepo:
		if set["session"] {
			fmt.Fprintln(stderr, "guardrail: --session cannot be combined with --scope repo")
			return 2
		}
		dir := repoText
		if dir == "" {
			cwd, err := os.Getwd()
			if err != nil {
				return nightError(err, stderr)
			}
			dir = cwd
		} else {
			abs, err := filepath.Abs(dir)
			if err != nil {
				return nightError(err, stderr)
			}
			dir = abs
		}
		root, ok := policy.FindRepoRoot(dir)
		if !ok {
			fmt.Fprintln(stderr, "guardrail: --scope repo needs a git repository; run from inside one or pass --repo <path>")
			return 2
		}
		canon, err := pathutil.Canonical(root)
		if err != nil {
			return nightError(err, stderr)
		}
		targetRepo = canon
	case night.ScopeSession:
		if set["repo"] {
			fmt.Fprintln(stderr, "guardrail: --repo cannot be combined with --scope session")
			return 2
		}
		targetSession = strings.TrimSpace(sessionText)
		if targetSession == "" {
			targetSession = strings.TrimSpace(os.Getenv("GUARDRAIL_SESSION_ID"))
		}
		if targetSession == "" {
			fmt.Fprintln(stderr, "guardrail: --scope session requires --session <id> (or GUARDRAIL_SESSION_ID)")
			return 2
		}
	default:
		fmt.Fprintf(stderr, "guardrail: --scope must be global, repo, or session (got %q)\n", safetext.SingleLine(scope))
		return 2
	}

	now := time.Now()
	until := now.Add(defaultNightDuration)
	if set["for"] {
		duration, err := time.ParseDuration(durationText)
		if err != nil || duration <= 0 {
			fmt.Fprintln(stderr, "guardrail: --for must be a positive duration")
			return 2
		}
		until = now.Add(duration)
	}
	if set["until"] {
		clock, err := time.ParseInLocation("15:04", untilText, now.Location())
		if err != nil {
			fmt.Fprintln(stderr, "guardrail: --until must be a local time in HH:MM format")
			return 2
		}
		until = time.Date(now.Year(), now.Month(), now.Day(), clock.Hour(), clock.Minute(), 0, 0, now.Location())
		if !until.After(now) {
			until = until.AddDate(0, 0, 1)
		}
	}

	hostname, err := os.Hostname()
	if err != nil {
		return nightError(fmt.Errorf("resolving hostname: %w", err), stderr)
	}
	marker := night.Marker{
		Until:   until,
		SetBy:   fmt.Sprintf("%s:%d", hostname, os.Getpid()),
		Scope:   scope,
		Repo:    targetRepo,
		Session: targetSession,
	}
	if err := night.Write(path, marker); err != nil {
		return nightError(err, stderr)
	}
	fmt.Fprintln(stdout, (night.State{Marker: marker, Active: true}).Banner())
	return 0
}

// nightViaHostApproval applies a canonical night command that the agent host
// asked the operator about and they approved (ADR-0033, prompt mode). Only
// the canonical forms ever carry a ticket: `night off` and
// `night on --until HH:MM`. It reports handled=false when there is nothing to
// apply, and the caller keeps today's terminal refusal.
func nightViaHostApproval(args []string, stdout, stderr io.Writer) (int, bool) {
	var request approval.Request
	switch {
	case len(args) == 1 && args[0] == "off":
		request.Action = "night-off"
	case len(args) == 3 && args[0] == "on" && args[1] == "--until":
		request.Action = "night-on"
		request.Parameters = map[string]string{"until": args[2]}
	default:
		return 0, false
	}
	if !promptApprovalMode() || !claimInvocationTicket() {
		return 0, false
	}
	cwd, err := os.Getwd()
	if err != nil {
		return nightError(err, stderr), true
	}
	request.Plane, request.SessionID, request.RepoRoot = "operator", "host-ask", cwd
	request.Scope, request.Reason = approval.Allow, "canonical operator action"
	if _, err := approval.ApplyLocal(request, transportHostAsk); err != nil {
		return nightError(err, stderr), true
	}
	if request.Action == "night-off" {
		fmt.Fprintln(stdout, "night mode off")
		return 0, true
	}
	path, err := night.DefaultPath()
	if err != nil {
		return nightError(err, stderr), true
	}
	state, err := night.Load(path, time.Now())
	if err != nil || !state.Active {
		fmt.Fprintln(stderr, "guardrail: approved night mode did not take effect")
		return 1, true
	}
	fmt.Fprintln(stdout, state.Banner())
	return 0, true
}

func repeatedNightFlag(args []string, name string) bool {
	count := 0
	for _, arg := range args {
		for _, prefix := range []string{"--" + name, "-" + name} {
			if arg == prefix || len(arg) > len(prefix) && arg[:len(prefix)+1] == prefix+"=" {
				count++
				break
			}
		}
	}
	return count > 1
}

func nightError(err error, stderr io.Writer) int {
	fmt.Fprintf(stderr, "guardrail: night: %s\n", safetext.SingleLine(err.Error()))
	return 2
}
