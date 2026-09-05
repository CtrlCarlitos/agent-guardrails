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
	case "update-ref":
		if gitOptionPresent(s.Argv, "d", "--delete", map[string]bool{"-m": true}) {
			return ask("P2.git-ref-delete", "git update-ref -d deletes a ref")
		}
	case "worktree":
		if gitSubcommandArg(s.Argv) == "remove" {
			return ask("P2.git-worktree-remove", "git worktree remove discards a working tree")
		}
	case "switch":
		if gitOptionPresent(s.Argv, "", "--discard-changes", map[string]bool{
			"-c": true, "-C": true, "--create": true, "--force-create": true,
			"--conflict": true, "--orphan": true,
		}) {
			return ask("P2.git-discard", "git switch --discard-changes throws away uncommitted work")
		}
	case "rm":
		if gitOptionPresent(s.Argv, "rf", "--force", map[string]bool{"--pathspec-from-file": true}) {
			return ask("P2.git-rm", "git rm -r/-f removes tracked files")
		}
	case "push":
		args := parseGitPushArgs(s.Argv)
		if args.force || args.forceWithLease {
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

func gitOptionPresent(argv []string, shortFlags, longFlag string, valueOptions map[string]bool) bool {
	i := gitSubcommandIndex(argv)
	if i < 0 {
		return false
	}
	for i++; i < len(argv); i++ {
		arg := argv[i]
		if arg == "--" {
			return false
		}
		if strings.HasPrefix(arg, "--") {
			name, _, attached := strings.Cut(arg, "=")
			if name == longFlag {
				return !attached
			}
			if valueOptions[name] && !attached {
				i++
			}
			continue
		}
		if strings.HasPrefix(arg, "-") && len(arg) > 1 {
			for j := 1; j < len(arg); j++ {
				name := "-" + arg[j:j+1]
				if strings.ContainsRune(shortFlags, rune(arg[j])) {
					return true
				}
				if valueOptions[name] {
					if j+1 == len(arg) {
						i++
					}
					break
				}
			}
		}
	}
	return false
}

type gitPushValueMode uint8

const (
	gitPushNoValue gitPushValueMode = iota
	gitPushRequiredValue
	gitPushOptionalValue
)

type gitPushLongOption struct {
	name      string
	valueMode gitPushValueMode
	negatable bool
}

var gitPushLongOptions = []gitPushLongOption{
	{name: "verbose", negatable: true},
	{name: "quiet", negatable: true},
	{name: "repo", valueMode: gitPushRequiredValue, negatable: true},
	{name: "all", negatable: true},
	{name: "branches", negatable: true},
	{name: "mirror", negatable: true},
	{name: "delete", negatable: true},
	{name: "tags", negatable: true},
	{name: "dry-run", negatable: true},
	{name: "porcelain", negatable: true},
	{name: "force", negatable: true},
	{name: "force-with-lease", valueMode: gitPushOptionalValue, negatable: true},
	{name: "force-if-includes", negatable: true},
	{name: "recurse-submodules", valueMode: gitPushRequiredValue, negatable: true},
	{name: "thin", negatable: true},
	{name: "receive-pack", valueMode: gitPushRequiredValue, negatable: true},
	{name: "exec", valueMode: gitPushRequiredValue, negatable: true},
	{name: "set-upstream", negatable: true},
	{name: "progress", negatable: true},
	{name: "prune", negatable: true},
	{name: "verify", negatable: true},
	{name: "follow-tags", negatable: true},
	{name: "signed", valueMode: gitPushOptionalValue, negatable: true},
	{name: "atomic", negatable: true},
	{name: "push-option", valueMode: gitPushRequiredValue, negatable: true},
	{name: "ipv4"},
	{name: "ipv6"},
}

type gitPushArgs struct {
	force          bool
	forceWithLease bool
	delete         bool
	tags           bool
	refspecs       []string
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
			eq := strings.IndexByte(a, '=')
			if eq >= 0 {
				base = a[:eq]
			}
			option, negated, ok := resolveGitPushLongOption(strings.TrimPrefix(base, "--"))
			if !ok || (negated && eq >= 0) || (!negated && eq >= 0 && option.valueMode == gitPushNoValue) {
				i++
				continue
			}
			switch option.name {
			case "force":
				args.force = !negated
			case "force-with-lease":
				args.forceWithLease = !negated
			case "delete":
				args.delete = !negated
			case "tags":
				args.tags = !negated
			}
			if !negated && eq < 0 && option.valueMode == gitPushRequiredValue && i+1 < len(argv) {
				i += 2
				continue
			}
			i++
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

func resolveGitPushLongOption(name string) (gitPushLongOption, bool, bool) {
	negated := strings.HasPrefix(name, "no-")
	if negated {
		name = strings.TrimPrefix(name, "no-")
	}
	for _, option := range gitPushLongOptions {
		if option.name == name && (!negated || option.negatable) {
			return option, negated, true
		}
	}
	var match gitPushLongOption
	found := false
	for _, option := range gitPushLongOptions {
		if (!negated || option.negatable) && strings.HasPrefix(option.name, name) {
			if found {
				return gitPushLongOption{}, false, false
			}
			match = option
			found = true
		}
	}
	return match, negated, found
}

var gitProtectedGlobs = []string{"**/.git/config", "**/.git/hooks/**"}
