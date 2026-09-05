package engine

import (
	"strings"

	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
)

func checkGitSafety(s Simple) *policy.Verdict {
	if head(s.Argv) != "git" || len(s.Argv) < 2 {
		return nil
	}
	unknown := gitSubcommandUnknownFlag(s.Argv)
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
		args := parseGitPushArgs(s.Argv)
		if args.force {
			return nil // P1.git-push-force (checkGit) already denies this; don't duplicate
		}
		var forceRefspec, deleteRefspec string
		protected := false
		for _, a := range args.refspecs {
			if strings.HasPrefix(a, "+") {
				if forceRefspec == "" {
					forceRefspec = a
				}
			}
			if strings.HasPrefix(a, ":") {
				if deleteRefspec == "" {
					deleteRefspec = a
				}
			}
			dst := a
			if i := strings.LastIndex(a, ":"); i >= 0 {
				dst = a[i+1:]
			}
			dst = strings.TrimPrefix(dst, "refs/heads/")
			if dst == "main" || dst == "master" {
				protected = true
			}
		}
		if forceRefspec != "" {
			return &policy.Verdict{Decision: policy.Deny, RuleID: "P2.git-push-force",
				Reason: "a leading + in a refspec is a force push: " + forceRefspec}
		}
		if args.delete || deleteRefspec != "" {
			reason := "git push --delete deletes remote refs"
			if deleteRefspec != "" {
				reason = "an empty source in a refspec deletes the remote ref: " + deleteRefspec
			}
			return &policy.Verdict{Decision: policy.Ask, RuleID: "P2.git-push-delete", Reason: reason}
		}
		if protected {
			return &policy.Verdict{Decision: policy.Ask, RuleID: "P2.git-push-protected",
				Reason: "push to a protected branch"}
		}
		if args.tags {
			return &policy.Verdict{Decision: policy.Ask, RuleID: "P2.git-push-protected",
				Reason: "pushing tags can overwrite released versions"}
		}
	}
	if unknown != "" {
		return &policy.Verdict{Decision: policy.Ask, RuleID: "P2.git-unknown-global",
			Reason: "unrecognized git global option " + unknown + " before the subcommand; cannot verify what this runs"}
	}
	return nil
}

var gitPushValueFlags = map[string]bool{
	"-o": true, "--push-option": true, "--receive-pack": true, "--exec": true,
	"--repo": true, "--server-option": true, "--recurse-submodules": true,
	"--negotiation-tip": true,
}

type gitPushArgs struct {
	force    bool
	delete   bool
	tags     bool
	refspecs []string
}

func parseGitPushArgs(argv []string) gitPushArgs {
	var args gitPushArgs
	i := gitSubcommandIndex(argv)
	if i < 0 || argv[i] != "push" {
		return args
	}

	i++
	repositorySeen := false
	optionsEnded := false
	for i < len(argv) {
		a := argv[i]
		if !optionsEnded && a == "--" {
			optionsEnded = true
			i++
			continue
		}
		if !optionsEnded && strings.HasPrefix(a, "--") {
			base := a
			if eq := strings.IndexByte(a, '='); eq >= 0 {
				base = a[:eq]
			}
			switch base {
			case "--force-with-lease":
				args.force = true
			case "--force":
				if base == a {
					args.force = true
				}
			case "--delete":
				if base == a {
					args.delete = true
				}
			case "--tags":
				if base == a {
					args.tags = true
				}
			}
			if gitPushValueFlags[base] && base == a {
				i += 2
			} else {
				i++
			}
			continue
		}
		if !optionsEnded && strings.HasPrefix(a, "-") && len(a) > 1 {
			consumeNext := false
			for j := 1; j < len(a); j++ {
				switch a[j] {
				case 'f':
					args.force = true
				case 'd':
					args.delete = true
				case 'o':
					consumeNext = j == len(a)-1
					j = len(a)
				}
			}
			if consumeNext {
				i += 2
			} else {
				i++
			}
			continue
		}
		if !repositorySeen {
			repositorySeen = true
			i++
			continue
		}
		args.refspecs = append(args.refspecs, a)
		i++
	}
	return args
}

var gitProtectedGlobs = []string{"**/.git/config", "**/.git/hooks/**"}
