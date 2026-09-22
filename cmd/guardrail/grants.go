package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/CtrlCarlitos/agent-guardrails/internal/audit"
	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
)

// Operator-issued command grants: issuance, revocation, and the ceremony that
// stands between them and the config file.
//
// The deadlock this exists to break has a worse endgame than an extra prompt:
// the operator runs the action outside guardrail, so the single most
// consequential command in the session is the only one with no audit record.
// A grant turns that into an in-policy, attributed allow.

type grantRequest struct {
	repo    string
	ruleID  string
	command string
	uses    int
	window  time.Duration
}

func parseGrantFlags(name string, args []string, stderr io.Writer) (grantRequest, bool) {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {}
	var req grantRequest
	var windowText string
	fs.StringVar(&req.repo, "repo", "", "absolute repository path the grant applies to")
	fs.StringVar(&req.ruleID, "rule", "", "rule ID from the verdict being authorized")
	fs.StringVar(&req.command, "command", "", "the exact command text to authorize")
	fs.IntVar(&req.uses, "uses", 0, "number of executions to authorize (default 1)")
	fs.StringVar(&windowText, "for", "", "how long the grant stays live (default 30m)")
	if err := fs.Parse(args); err != nil {
		return req, false
	}
	if fs.NArg() != 0 {
		fmt.Fprintf(stderr, "guardrail: approvals %s takes only flags\n", name)
		return req, false
	}
	if req.repo == "" || req.ruleID == "" || req.command == "" {
		fmt.Fprintf(stderr, "guardrail: approvals %s needs --repo, --rule and --command\n", name)
		return req, false
	}
	if !filepath.IsAbs(req.repo) {
		fmt.Fprintf(stderr, "guardrail: --repo must be an absolute path; grants never transfer between repositories\n")
		return req, false
	}
	req.repo = filepath.Clean(req.repo)
	if windowText != "" {
		window, err := time.ParseDuration(windowText)
		if err != nil || window <= 0 {
			fmt.Fprintln(stderr, "guardrail: --for must be a positive duration")
			return req, false
		}
		req.window = window
	}
	return req, true
}

// cmdApprovalsGrant runs the issuance ceremony and records the grant.
//
// The ceremony's whole job is that the operator can verify what they are
// authorizing by reading it. So the command is shown twice: once as written,
// and once quoted, which makes leading and trailing whitespace, tabs and any
// other control character visible instead of invisible. Nothing is truncated
// and no summary stands in for the string that will actually be matched.
func cmdApprovalsGrant(args []string, operatorTerminal bool, input io.Reader, stdout, stderr io.Writer) int {
	if !operatorTerminal {
		fmt.Fprintln(stderr, "guardrail: approvals grant requires an interactive local terminal")
		return 2
	}
	req, ok := parseGrantFlags("grant", args, stderr)
	if !ok {
		return 2
	}
	if policy.NeverGrantable(req.ruleID) {
		if policy.NeverRelaxable(req.ruleID) {
			fmt.Fprintf(stderr, "guardrail: %s can never be granted (ADR-0018: the External tier is a per-call operator decision)\n", req.ruleID)
		} else {
			fmt.Fprintf(stderr, "guardrail: %s can never be granted (fail-closed backstop; granting it would make the engine fail open)\n", req.ruleID)
		}
		return 2
	}

	now := time.Now()
	grant := policy.CommandGrant{
		RuleID:    req.ruleID,
		Command:   req.command,
		Uses:      policy.IssuedUses(req.uses),
		ExpiresAt: policy.BoundedGrantExpiry(now, req.window),
	}
	printGrantCeremony(stdout, req.repo, grant, now)
	if !confirmGrant(input, stdout) {
		fmt.Fprintln(stderr, "guardrail: not authorized; nothing was recorded")
		return 1
	}

	if err := mutateCommandGrants(req.repo, func(existing []policy.CommandGrant) []policy.CommandGrant {
		return append(withoutGrant(existing, grant.RuleID, grant.Command), grant)
	}); err != nil {
		fmt.Fprintf(stderr, "guardrail: recording the grant failed (%v)\n", err)
		return 1
	}
	writeGrantAudit("grant-issued", req.repo, grant, "operator issued a single-command grant")
	fmt.Fprintf(stdout, "authorized. %d use, expires %s\n", grant.Uses, grant.ExpiresAt.Local().Format(time.RFC3339))
	return 0
}

func cmdApprovalsRevoke(args []string, stdout, stderr io.Writer) int {
	req, ok := parseGrantFlags("revoke", args, stderr)
	if !ok {
		return 2
	}
	removed := false
	if err := mutateCommandGrants(req.repo, func(existing []policy.CommandGrant) []policy.CommandGrant {
		trimmed := withoutGrant(existing, req.ruleID, req.command)
		removed = len(trimmed) != len(existing)
		return trimmed
	}); err != nil {
		fmt.Fprintf(stderr, "guardrail: revoking the grant failed (%v)\n", err)
		return 1
	}
	if !removed {
		fmt.Fprintln(stderr, "guardrail: no grant matches that repository, rule and exact command")
		return 1
	}
	writeGrantAudit("grant-revoked", req.repo,
		policy.CommandGrant{RuleID: req.ruleID, Command: req.command}, "operator revoked a grant")
	fmt.Fprintln(stdout, "revoked")
	return 0
}

// cmdApprovalsListGrants prints every recorded grant in full. An operator who
// cannot read what is authorized cannot decide whether to revoke it, so this
// shares issuance's no-truncation obligation.
func cmdApprovalsListGrants(stdout, stderr io.Writer) int {
	op, err := policy.LoadOperatorConfig()
	if err != nil {
		fmt.Fprintf(stderr, "guardrail: reading operator config failed (%v)\n", err)
		return 1
	}
	repos := make([]string, 0, len(op.Repos))
	for repo := range op.Repos {
		if len(op.Repos[repo].Commands) > 0 {
			repos = append(repos, repo)
		}
	}
	sort.Strings(repos)
	if len(repos) == 0 {
		fmt.Fprintln(stdout, "no command grants are recorded")
		return 0
	}
	now := time.Now()
	for _, repo := range repos {
		fmt.Fprintf(stdout, "%s\n", repo)
		for _, g := range op.Repos[repo].Commands {
			state := "spent"
			if g.Live(now) {
				state = fmt.Sprintf("%d use(s) left, expires %s", g.RemainingUses(), g.ExpiresAt.Local().Format(time.RFC3339))
			} else if !g.ExpiresAt.IsZero() && !now.Before(g.ExpiresAt) {
				state = "expired"
			}
			fmt.Fprintf(stdout, "  rule     %s\n", g.RuleID)
			fmt.Fprintf(stdout, "  command  %s\n", g.Command)
			fmt.Fprintf(stdout, "  exact    %q\n", g.Command)
			fmt.Fprintf(stdout, "  state    %s\n\n", state)
		}
	}
	fmt.Fprintln(stdout, "revoke with: guardrail approvals revoke --repo <path> --rule <id> --command <exact text>")
	return 0
}

func printGrantCeremony(stdout io.Writer, repo string, g policy.CommandGrant, now time.Time) {
	fmt.Fprintln(stdout, "guardrail: authorize ONE command, in ONE repository, under ONE rule.")
	fmt.Fprintln(stdout)
	fmt.Fprintf(stdout, "  repository  %s\n", repo)
	fmt.Fprintf(stdout, "  rule        %s\n", g.RuleID)
	fmt.Fprintf(stdout, "  command     %s\n", g.Command)
	fmt.Fprintf(stdout, "  exact       %q  (%d bytes)\n", g.Command, len(g.Command))
	fmt.Fprintf(stdout, "  uses        %d\n", g.Uses)
	fmt.Fprintf(stdout, "  expires     %s (in %s)\n", g.ExpiresAt.Local().Format(time.RFC3339), g.ExpiresAt.Sub(now).Round(time.Second))
	fmt.Fprintln(stdout)
	fmt.Fprintln(stdout, "The command is matched literally. A longer command containing this one is")
	fmt.Fprintln(stdout, "NOT authorized, and neither is the same command in any other repository.")
	fmt.Fprintln(stdout, "Read the exact line above before answering.")
	fmt.Fprintln(stdout)
	fmt.Fprint(stdout, "Type yes to authorize: ")
}

func confirmGrant(input io.Reader, stdout io.Writer) bool {
	if input == nil {
		return false
	}
	line, err := bufio.NewReader(input).ReadString('\n')
	if err != nil && line == "" {
		return false
	}
	fmt.Fprintln(stdout)
	return strings.EqualFold(strings.TrimSpace(line), "yes")
}

// withoutGrant removes the entry for one exact triple. It is shared by
// issuance (which replaces rather than duplicates) and revocation.
func withoutGrant(existing []policy.CommandGrant, ruleID, command string) []policy.CommandGrant {
	kept := make([]policy.CommandGrant, 0, len(existing))
	for _, g := range existing {
		if g.RuleID == ruleID && g.Command == command {
			continue
		}
		kept = append(kept, g)
	}
	return kept
}

func writeGrantAudit(action, repo string, g policy.CommandGrant, reason string) {
	rec := audit.Record{
		TS:             time.Now().UTC().Format(time.RFC3339Nano),
		Plane:          "operator",
		Tool:           "guardrail approvals",
		Event:          "operator",
		Command:        g.Command,
		Paths:          []string{repo},
		Decision:       "allow",
		RuleID:         g.RuleID,
		OperatorAction: action,
		Reason:         reason,
	}
	// A failed audit write must not leave the operator believing nothing
	// happened when the grant was recorded, so it is reported rather than
	// returned: the grant itself has already been committed.
	if err := audit.Write(rec, audit.DefaultPath("")); err != nil {
		fmt.Fprintf(os.Stderr, "guardrail: grant audit write failed (%v)\n", err)
	}
}
