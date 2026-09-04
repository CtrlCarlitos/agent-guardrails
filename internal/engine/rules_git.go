package engine

import (
	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
)

func checkGitSafety(s Simple) *policy.Verdict {
	if head(s.Argv) != "git" || len(s.Argv) < 2 {
		return nil
	}
	sub := gitSubcommand(s.Argv)
	switch sub {
	case "reset":
		if hasAnyFlag(s.Argv, "", "--hard", "--keep") {
			return &policy.Verdict{Decision: policy.Deny, RuleID: "P2.git-reset-hard",
				Reason: "git reset --hard/--keep discards the working tree and index irrecoverably"}
		}
	case "config":
		writeFlag := hasAnyFlag(s.Argv, "", "--global", "--system", "--local", "--add", "--replace-all", "--unset", "--unset-all")
		if writeFlag || len(nonFlagArgs(s.Argv[1:])) >= 2 {
			return &policy.Verdict{Decision: policy.Deny, RuleID: "P2.git-config-write",
				Reason: "git config write can redirect core.hooksPath/fsmonitor into arbitrary code execution"}
		}
	case "checkout", "restore":
		for _, a := range nonFlagArgs(s.Argv) {
			if a == "." {
				return &policy.Verdict{Decision: policy.Ask, RuleID: "P2.git-checkout-restore",
					Reason: "git " + sub + " . silently reverts uncommitted changes"}
			}
		}
	case "branch":
		if hasAnyFlag(s.Argv, "D") || (hasAnyFlag(s.Argv, "", "--delete") && hasAnyFlag(s.Argv, "", "--force")) {
			return &policy.Verdict{Decision: policy.Ask, RuleID: "P2.git-branch-delete",
				Reason: "git branch -D force-deletes an unmerged branch"}
		}
	case "commit":
		if hasAnyFlag(s.Argv, "", "--amend") {
			return &policy.Verdict{Decision: policy.Ask, RuleID: "P2.git-history-rewrite",
				Reason: "git commit --amend rewrites the last commit"}
		}
	case "filter-branch", "filter-repo":
		return &policy.Verdict{Decision: policy.Ask, RuleID: "P2.git-history-rewrite",
			Reason: "git " + sub + " rewrites history"}
	case "reflog":
		if gitSubcommandArg(s.Argv) == "expire" {
			return &policy.Verdict{Decision: policy.Ask, RuleID: "P2.git-history-rewrite",
				Reason: "git reflog expire removes the safety net for history rewrites"}
		}
	case "gc":
		if hasAnyFlag(s.Argv, "", "--prune=now") {
			return &policy.Verdict{Decision: policy.Ask, RuleID: "P2.git-history-rewrite",
				Reason: "git gc --prune=now permanently drops unreachable objects"}
		}
	case "remote":
		if n := gitSubcommandArg(s.Argv); n == "add" || n == "set-url" {
			return &policy.Verdict{Decision: policy.Ask, RuleID: "P2.git-remote-add",
				Reason: "adding/changing a remote adds a reachable exfil destination"}
		}
	case "stash":
		if n := gitSubcommandArg(s.Argv); n == "clear" || n == "drop" {
			return &policy.Verdict{Decision: policy.Ask, RuleID: "P2.git-stash-clear",
				Reason: "discards stashed work with no reflog for the stash contents"}
		}
	case "push":
		if hasAnyFlag(s.Argv, "f", "--force", "--force-with-lease") {
			return nil // P1.git-push-force (checkGit) already denies this; don't duplicate
		}
		for _, a := range nonFlagArgs(s.Argv) {
			if a == "main" || a == "master" {
				return &policy.Verdict{Decision: policy.Ask, RuleID: "P2.git-push-protected",
					Reason: "push to a protected branch"}
			}
		}
		if hasAnyFlag(s.Argv, "", "--tags") {
			return &policy.Verdict{Decision: policy.Ask, RuleID: "P2.git-push-protected",
				Reason: "pushing tags can overwrite released versions"}
		}
	}
	return nil
}

var gitProtectedGlobs = []string{"**/.git/config", "**/.git/hooks/**"}
