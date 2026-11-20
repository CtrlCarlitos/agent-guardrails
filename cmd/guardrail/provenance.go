package main

import (
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/CtrlCarlitos/agent-guardrails/internal/audit"
	"github.com/CtrlCarlitos/agent-guardrails/internal/engine"
	"github.com/CtrlCarlitos/agent-guardrails/internal/pathutil"
	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
	"mvdan.cc/sh/v3/syntax"
)

// ADR-0039 (#630): a session may remove the exact worktree it created. The
// creation evidence is the session's own allowed-or-asked `git worktree add`
// audit record; the match is the exact path, canonicalized against the
// current working directory. Everything else — no record, another session, a
// different path, a denied creation, expired evidence — keeps today's ask.
func applyWorktreeProvenance(tc engine.ToolCall, v policy.Verdict, now time.Time) policy.Verdict {
	if v.RuleID != "P2.git-worktree-remove" && v.OriginRuleID != "P2.git-worktree-remove" {
		return v
	}
	if v.Decision != policy.Ask && v.RuleID != "host-auto-ask-escalated" {
		return v
	}
	target, ok := worktreeOperand(tc.Command, "remove")
	if !ok {
		return v
	}
	evidence, found := audit.SessionCreation(audit.DefaultPath(""), tc.SessionID, now, 24*time.Hour, func(command string) bool {
		created, ok := worktreeOperand(command, "add")
		return ok && sameWorktreePath(created, target, tc.CWD)
	})
	if !found {
		return v
	}
	return policy.Verdict{Decision: policy.Allow, RuleID: "P2.git-worktree-remove",
		Reason: fmt.Sprintf("removes a worktree created by this session (%s: %s); ADR-0039", evidence.TS, evidence.Command)}
}

// worktreeOperand extracts the path operand of `git worktree add|remove …`,
// skipping `git`'s and `worktree`'s own flags (and the values of the flags
// that take one). The path is the first non-flag operand.
func worktreeOperand(command, sub string) (string, bool) {
	argv := commandArgv(command)
	if len(argv) < 3 || argv[0] != "git" {
		return "", false
	}
	i := 1
	for i < len(argv) && strings.HasPrefix(argv[i], "-") && argv[i] != "-" {
		if argv[i] == "-C" || argv[i] == "--git-dir" || argv[i] == "--work-tree" {
			i += 2
			continue
		}
		i++
	}
	if i >= len(argv) || argv[i] != "worktree" || i+1 >= len(argv) || argv[i+1] != sub {
		return "", false
	}
	for j := i + 2; j < len(argv); j++ {
		arg := argv[j]
		if strings.HasPrefix(arg, "-") && arg != "-" {
			if (arg == "-b" || arg == "-B") && j+1 < len(argv) {
				j++
			}
			continue
		}
		return arg, true
	}
	return "", false
}

// commandArgv parses a shell command and returns the first call's argv,
// with quoted words kept whole. Unparsable input yields nil.
func commandArgv(command string) []string {
	prog, err := syntax.NewParser().Parse(strings.NewReader(command), "")
	if err != nil {
		return nil
	}
	var argv []string
	syntax.Walk(prog, func(node syntax.Node) bool {
		if call, ok := node.(*syntax.CallExpr); ok {
			for _, word := range call.Args {
				var b strings.Builder
				for _, part := range word.Parts {
					if lit, ok := part.(*syntax.Lit); ok {
						b.WriteString(lit.Value)
					}
				}
				if b.Len() > 0 {
					argv = append(argv, b.String())
				}
			}
			return false
		}
		return true
	})
	return argv
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
