package main

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/CtrlCarlitos/agent-guardrails/internal/audit"
	"github.com/CtrlCarlitos/agent-guardrails/internal/delivery"
	"github.com/CtrlCarlitos/agent-guardrails/internal/engine"
	"github.com/CtrlCarlitos/agent-guardrails/internal/pathutil"
	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
	"mvdan.cc/sh/v3/syntax"
)

// ADR-0039 (#630): a session may remove the exact worktree it created. The
// creation evidence is the session's own allowed-or-asked `git worktree add`
// audit record; the match is the exact path, canonicalized against the
// effective working directory. Everything else — no record, another session, a
// different path, forced removal, a denied creation, expired evidence, compound commands,
// redirections, env overrides, or dynamic expansions — keeps today's ask.
func applyWorktreeProvenance(tc engine.ToolCall, v policy.Verdict, now time.Time) policy.Verdict {
	if v.RuleID != "P2.git-worktree-remove" && v.OriginRuleID != "P2.git-worktree-remove" {
		return v
	}
	if v.Decision != policy.Ask && v.RuleID != "host-auto-ask-escalated" {
		return v
	}
	target, ok := worktreeTarget(tc.Command, "remove", tc.CWD)
	if !ok {
		return v
	}
	evidence, found := audit.SessionCreation(audit.DefaultPath(""), tc.SessionID, now, 24*time.Hour, func(command string) bool {
		created, ok := worktreeTarget(command, "add", tc.CWD)
		return ok && sameWorktreePath(created, target, tc.CWD)
	})
	if !found {
		return v
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := delivery.VerifyPublishedWorktree(ctx, target); err != nil {
		v.Reason += "; " + err.Error()
		return v
	}
	return policy.Verdict{Decision: policy.Allow, RuleID: "P2.git-worktree-remove",
		Reason: fmt.Sprintf("removes a worktree created by this session (%s: %s) with clean files and a remote-tracked HEAD; ADR-0039", evidence.TS, evidence.Command)}
}

// worktreeTarget parses a single, simple, un-redirected, assignment-free,
// static-literal `git [-C dir] worktree add|remove … <path>` invocation and
// returns the worktree path resolved against the effective base directory
// (defaultCWD adjusted by any `-C` flags). Compound commands, pipes,
// redirections, env overrides, `--git-dir`/`--work-tree`, and shell expansions
// fail closed so provenance cannot be piggybacked onto another action (#151).
func worktreeTarget(command, sub, defaultCWD string) (string, bool) {
	argv, ok := simpleCommandArgv(command)
	if !ok || len(argv) < 3 || argv[0] != "git" {
		return "", false
	}
	baseDir := defaultCWD
	applyC := func(dir string) bool {
		if dir == "" {
			return false
		}
		if filepath.IsAbs(dir) {
			baseDir = filepath.Clean(dir)
			return true
		}
		if baseDir == "" {
			return false
		}
		baseDir = filepath.Join(baseDir, dir)
		return true
	}

	i := 1
	for i < len(argv) && strings.HasPrefix(argv[i], "-") && argv[i] != "-" {
		flag := argv[i]
		switch {
		case flag == "-C":
			if i+1 >= len(argv) || !applyC(argv[i+1]) {
				return "", false
			}
			i += 2
		case strings.HasPrefix(flag, "-C") && len(flag) > 2:
			if !applyC(flag[2:]) {
				return "", false
			}
			i++
		case flag == "--no-pager":
			i++
		default:
			// Unknown global git flags (including --git-dir, --work-tree, -c)
			// change repository targeting or take arguments; fail closed.
			return "", false
		}
	}
	if i+1 >= len(argv) || argv[i] != "worktree" || argv[i+1] != sub {
		return "", false
	}

	var operand string
	afterDashDash := false
	for j := i + 2; j < len(argv); j++ {
		arg := argv[j]
		if !afterDashDash && arg == "--" {
			afterDashDash = true
			continue
		}
		if !afterDashDash && strings.HasPrefix(arg, "-") && arg != "-" {
			switch sub {
			case "remove":
				// Git's non-forced removal is the final check for dirty files.
				return "", false
			case "add":
				if (arg == "-b" || arg == "-B" || arg == "--reason") && j+1 < len(argv) {
					j++
					continue
				}
			default:
				return "", false
			}
			continue
		}
		if operand == "" {
			operand = arg
			continue
		}
		// `git worktree remove` takes exactly one path operand; extra operands
		// fail closed. `git worktree add <path> [<commit-ish>]` may carry a
		// trailing commit-ish after the path.
		if sub == "remove" {
			return "", false
		}
	}
	if operand == "" {
		return "", false
	}
	if filepath.IsAbs(operand) {
		return filepath.Clean(operand), true
	}
	if baseDir == "" {
		return "", false
	}
	return filepath.Join(baseDir, operand), true
}

// simpleCommandArgv parses a shell command only when it consists of a single
// simple call with no chaining, pipelines, redirections, negation, background
// execution, environment assignments, or dynamic expansions.
func simpleCommandArgv(command string) ([]string, bool) {
	prog, err := syntax.NewParser().Parse(strings.NewReader(command), "")
	if err != nil || len(prog.Stmts) != 1 {
		return nil, false
	}
	stmt := prog.Stmts[0]
	if stmt.Negated || stmt.Background || stmt.Coprocess || len(stmt.Redirs) > 0 {
		return nil, false
	}
	call, ok := stmt.Cmd.(*syntax.CallExpr)
	if !ok || len(call.Assigns) > 0 || len(call.Args) == 0 {
		return nil, false
	}
	argv := make([]string, 0, len(call.Args))
	for _, word := range call.Args {
		val, ok := staticWordText(word)
		if !ok || val == "" {
			return nil, false
		}
		argv = append(argv, val)
	}
	return argv, true
}

// staticWordText returns the literal string value of a shell word only when
// every part is static (unquoted literal, single-quoted literal, or
// double-quoted literal without expansions). Any variable, command
// substitution, arithmetic expansion, or globbing extension fails closed.
func staticWordText(word *syntax.Word) (string, bool) {
	if word == nil || len(word.Parts) == 0 {
		return "", false
	}
	var b strings.Builder
	for _, part := range word.Parts {
		switch p := part.(type) {
		case *syntax.Lit:
			b.WriteString(p.Value)
		case *syntax.SglQuoted:
			b.WriteString(p.Value)
		case *syntax.DblQuoted:
			for _, inner := range p.Parts {
				lit, ok := inner.(*syntax.Lit)
				if !ok {
					return "", false
				}
				b.WriteString(lit.Value)
			}
		default:
			return "", false
		}
	}
	return b.String(), true
}

// sameWorktreePath compares two worktree paths after resolving relatives
// against cwd using canonical path identity (symlinks, Windows 8.3 short
// names, separators, and case folding on Windows/macOS).
func sameWorktreePath(a, b, cwd string) bool {
	if a == "" || b == "" {
		return false
	}
	resolve := func(p string) string {
		if !filepath.IsAbs(p) {
			p = filepath.Join(cwd, p)
		}
		return p
	}
	ra, rb := resolve(a), resolve(b)
	if pathutil.Same(ra, rb) {
		return true
	}
	return pathutil.NormalizeLexical(ra) == pathutil.NormalizeLexical(rb)
}
