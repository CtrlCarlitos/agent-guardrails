package engine

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
)

func checkGitSafety(s Simple, tc ToolCall) *policy.Verdict {
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
		verdict := checkGitConfig(parseGitConfig(s, tc))
		if verdict != nil && verdict.Decision == policy.Deny {
			return verdict
		}
		if unknown == "" {
			return verdict
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
		if gitOptionPresent(s.Argv, "d", "", gitUpdateRefLongOptions, "m") {
			return ask("P2.git-ref-delete", "git update-ref -d deletes a ref")
		}
	case "worktree":
		if gitSubcommandArg(s.Argv) == "remove" {
			return ask("P2.git-worktree-remove", "git worktree remove discards a working tree")
		}
	case "switch":
		if gitOptionPresent(s.Argv, "", "discard-changes", gitSwitchLongOptions, "cC") {
			return ask("P2.git-discard", "git switch --discard-changes throws away uncommitted work")
		}
	case "rm":
		if gitOptionPresent(s.Argv, "rf", "force", gitRmLongOptions, "") {
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

type parsedGitConfig struct {
	operation string
	scope     string
	subjects  []string
	localRepo bool
	uncertain bool
}

func parseGitConfig(s Simple, tc ToolCall) parsedGitConfig {
	argv := s.Argv
	parsed := parsedGitConfig{operation: "read", scope: "local", localRepo: gitConfigTargetsToolCallRepo(s, tc)}
	subcommand := gitSubcommandIndex(argv)
	if subcommand < 0 || argv[subcommand] != "config" {
		parsed.uncertain = true
		return parsed
	}

	operation := ""
	var operands []string
	setOperation := func(next string) {
		if operation != "" && operation != next {
			parsed.uncertain = true
		}
		operation = next
	}
	setScope := func(next string) {
		if parsed.scope != "local" && parsed.scope != next {
			parsed.uncertain = true
		}
		parsed.scope = next
	}

	optionsEnded := false
	for i := subcommand + 1; i < len(argv); i++ {
		arg := argv[i]
		if optionsEnded || len(operands) > 0 {
			operands = append(operands, arg)
			continue
		}
		if arg == "--" {
			optionsEnded = true
			continue
		}
		if !strings.HasPrefix(arg, "-") || arg == "-" {
			operands = append(operands, arg)
			continue
		}

		if strings.HasPrefix(arg, "--") {
			name, attached, hasAttached := strings.Cut(strings.TrimPrefix(arg, "--"), "=")
			switch name {
			case "local", "global", "system", "worktree":
				if hasAttached {
					parsed.uncertain = true
				}
				setScope(name)
			case "file", "blob", "type":
				value := attached
				if !hasAttached {
					if i+1 >= len(argv) {
						parsed.uncertain = true
						continue
					}
					i++
					value = argv[i]
				}
				if value == "" {
					parsed.uncertain = true
				}
				if name == "file" || name == "blob" {
					setScope(name)
				}
			case "add", "replace-all", "unset", "unset-all", "rename-section", "remove-section", "edit":
				if hasAttached {
					parsed.uncertain = true
				}
				setOperation(name)
			case "get", "get-all", "get-regexp", "get-urlmatch", "get-color", "get-colorbool", "list":
				if hasAttached {
					parsed.uncertain = true
				}
				setOperation(name)
			case "fixed-value", "show-origin", "show-scope", "name-only", "includes", "no-includes", "null", "bool", "int", "bool-or-int", "bool-or-str", "path", "expiry-date":
				if hasAttached {
					parsed.uncertain = true
				}
			default:
				parsed.uncertain = true
			}
			continue
		}

		for j := 1; j < len(arg); j++ {
			switch arg[j] {
			case 'e':
				setOperation("edit")
			case 'l':
				setOperation("list")
			case 'z', 'n', 't':
			case 'f':
				value := arg[j+1:]
				if value == "" {
					if i+1 >= len(argv) {
						parsed.uncertain = true
						j = len(arg)
						continue
					}
					i++
					value = argv[i]
				}
				if value == "" {
					parsed.uncertain = true
				}
				setScope("file")
				j = len(arg)
			default:
				parsed.uncertain = true
			}
		}
	}

	if operation == "" {
		operation = "positional"
	}
	parsed.operation = operation
	valid := false
	switch operation {
	case "positional":
		valid = len(operands) <= 3
		if len(operands) >= 2 {
			parsed.operation = "write"
			parsed.subjects = []string{strings.ToLower(operands[0])}
		}
	case "add":
		valid = len(operands) == 2
	case "replace-all":
		valid = len(operands) == 2 || len(operands) == 3
	case "unset", "unset-all":
		valid = len(operands) == 1 || len(operands) == 2
	case "rename-section":
		valid = len(operands) == 2
	case "remove-section":
		valid = len(operands) == 1
	case "edit", "list":
		valid = len(operands) == 0
	case "get", "get-all", "get-regexp", "get-color", "get-colorbool":
		valid = len(operands) == 1 || len(operands) == 2
	case "get-urlmatch":
		valid = len(operands) == 2
	}
	if !valid {
		parsed.uncertain = true
		return parsed
	}
	if operation == "add" || operation == "replace-all" || operation == "unset" || operation == "unset-all" {
		parsed.operation = "write"
		parsed.subjects = []string{strings.ToLower(operands[0])}
	}
	if operation == "rename-section" || operation == "remove-section" {
		parsed.subjects = make([]string, len(operands))
		for i, subject := range operands {
			parsed.subjects[i] = strings.ToLower(subject)
		}
	}
	if parsed.scope == "blob" && parsed.operation != "read" && parsed.operation != "list" && parsed.operation != "get" && parsed.operation != "get-all" && parsed.operation != "get-regexp" && parsed.operation != "get-urlmatch" {
		parsed.uncertain = true
	}
	return parsed
}

func checkGitConfig(parsed parsedGitConfig) *policy.Verdict {
	if parsed.uncertain {
		return ask("P2.git-config-write", "git config arguments could not be classified safely")
	}
	switch parsed.operation {
	case "read", "positional", "list", "get", "get-all", "get-regexp", "get-urlmatch", "get-color", "get-colorbool":
		return nil
	}
	for _, subject := range parsed.subjects {
		if dangerousGitConfigSubject(subject, parsed.operation) {
			return &policy.Verdict{Decision: policy.Deny, RuleID: "P2.git-config-write",
				Reason: "git config writes a protected key or section: " + subject}
		}
	}
	if parsed.scope == "global" || parsed.scope == "system" || parsed.scope == "file" {
		return &policy.Verdict{Decision: policy.Deny, RuleID: "P2.git-config-write",
			Reason: "git config writes outside repository-local configuration"}
	}
	if parsed.scope == "worktree" {
		return ask("P2.git-config-write", "git config writes worktree-specific configuration")
	}
	if !parsed.localRepo {
		return ask("P2.git-config-write", "git config targets a repository other than the ToolCall repository")
	}
	if parsed.operation == "edit" {
		return ask("P2.git-config-write", "git config opens repository configuration for unrestricted editing")
	}
	for _, subject := range parsed.subjects {
		if !approvedGitConfigSubject(subject, parsed.operation) {
			return ask("P2.git-config-write", "git config writes an unclassified key or section: "+subject)
		}
	}
	return nil
}

func dangerousGitConfigSubject(subject, operation string) bool {
	if operation == "rename-section" || operation == "remove-section" {
		switch subject {
		case "core", "credential", "include", "includeif", "alias":
			return true
		}
		return false
	}
	switch subject {
	case "core.hookspath", "core.fsmonitor", "core.sshcommand", "core.pager", "core.editor", "include.path":
		return true
	}
	return strings.HasPrefix(subject, "credential.") || strings.HasPrefix(subject, "includeif.") || strings.HasPrefix(subject, "alias.")
}

func approvedGitConfigSubject(subject, operation string) bool {
	if operation == "rename-section" || operation == "remove-section" {
		return subject == "user" || subject == "advice" || subject == "color"
	}
	if subject == "init.defaultbranch" || subject == "commit.gpgsign" {
		return true
	}
	return strings.HasPrefix(subject, "user.") || strings.HasPrefix(subject, "advice.") || strings.HasPrefix(subject, "color.")
}

func gitConfigTargetsToolCallRepo(s Simple, tc ToolCall) bool {
	argv := s.Argv
	subcommand := gitSubcommandIndex(argv)
	if subcommand < 0 || s.cwdUnknown || s.gitEnvironmentUnknown || s.Cwd == "" || tc.RepoRoot == "" {
		return false
	}
	target, ok := gitCommonDirectory(argv[0], normalizeGitIdentityArgs(argv[1:subcommand]), s.Cwd, s.gitEnvironment, false)
	if !ok {
		return false
	}
	trusted, ok := gitCommonDirectory(argv[0], []string{"-C", tc.RepoRoot}, s.Cwd, nil, true)
	if !ok {
		return false
	}
	return sameGitConfigPath(target, trusted)
}

func gitCommonDirectory(binary string, globalArgs []string, cwd string, variables map[string]string, cleanEnvironment bool) (string, bool) {
	args := append(append([]string{}, globalArgs...), "rev-parse", "--path-format=absolute", "--git-common-dir")
	command := exec.Command(binary, args...)
	command.Dir = cwd
	environment := os.Environ()
	if cleanEnvironment {
		environment = withoutGitRepositoryEnvironment(environment)
	}
	for name, value := range variables {
		environment = withoutEnvironmentVariable(environment, name)
		environment = append(environment, name+"="+value)
	}
	command.Env = environment
	output, err := command.Output()
	if err != nil {
		return "", false
	}
	path := strings.TrimSpace(string(output))
	return path, path != ""
}

func normalizeGitIdentityArgs(args []string) []string {
	normalized := make([]string, 0, len(args)+1)
	for _, arg := range args {
		if strings.HasPrefix(arg, "-C") && len(arg) > 2 {
			normalized = append(normalized, "-C", arg[2:])
			continue
		}
		normalized = append(normalized, arg)
	}
	return normalized
}

func withoutGitRepositoryEnvironment(environment []string) []string {
	cleaned := make([]string, 0, len(environment))
	for _, entry := range environment {
		name, _, _ := strings.Cut(entry, "=")
		switch name {
		case "GIT_DIR", "GIT_COMMON_DIR", "GIT_WORK_TREE", "GIT_CEILING_DIRECTORIES", "GIT_DISCOVERY_ACROSS_FILESYSTEM":
			continue
		}
		cleaned = append(cleaned, entry)
	}
	return cleaned
}

func withoutEnvironmentVariable(environment []string, excluded string) []string {
	cleaned := make([]string, 0, len(environment))
	for _, entry := range environment {
		name, _, _ := strings.Cut(entry, "=")
		if name != excluded {
			cleaned = append(cleaned, entry)
		}
	}
	return cleaned
}

func sameGitConfigPath(left, right string) bool {
	leftAbs, leftErr := filepath.Abs(left)
	rightAbs, rightErr := filepath.Abs(right)
	if leftErr != nil || rightErr != nil {
		return false
	}
	if filepath.Clean(leftAbs) == filepath.Clean(rightAbs) {
		return true
	}
	leftPhysical, leftOK := resolveExistingPath(leftAbs, "")
	rightPhysical, rightOK := resolveExistingPath(rightAbs, "")
	return leftOK && rightOK && filepath.Clean(leftPhysical) == filepath.Clean(rightPhysical)
}

var gitUpdateRefLongOptions = []gitPushLongOption{
	{name: "no-deref"}, {name: "stdin"}, {name: "create-reflog"}, {name: "batch-updates"},
}

var gitSwitchLongOptions = []gitPushLongOption{
	{name: "create", valueMode: gitPushRequiredValue},
	{name: "force-create", valueMode: gitPushRequiredValue},
	{name: "detach"}, {name: "guess"}, {name: "no-guess"}, {name: "discard-changes"},
	{name: "force"}, {name: "merge"},
	{name: "conflict", valueMode: gitPushRequiredValue},
	{name: "quiet"}, {name: "progress"}, {name: "no-progress"},
	{name: "recurse-submodules", valueMode: gitPushOptionalValue}, {name: "no-recurse-submodules"},
	{name: "orphan", valueMode: gitPushRequiredValue}, {name: "ignore-other-worktrees"},
	{name: "track", valueMode: gitPushOptionalValue}, {name: "no-track"},
}

var gitRmLongOptions = []gitPushLongOption{
	{name: "force"}, {name: "dry-run"}, {name: "cached"}, {name: "ignore-unmatch"},
	{name: "quiet"}, {name: "sparse"},
	{name: "pathspec-from-file", valueMode: gitPushRequiredValue}, {name: "pathspec-file-nul"},
}

func gitOptionPresent(argv []string, shortFlags, longFlag string, longOptions []gitPushLongOption, shortValues string) bool {
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
			name, _, attached := strings.Cut(strings.TrimPrefix(arg, "--"), "=")
			option, ok := resolveGitLongOption(name, longOptions)
			if !ok || attached && option.valueMode == gitPushNoValue {
				continue
			}
			if option.name == longFlag {
				return true
			}
			if option.valueMode == gitPushRequiredValue && !attached {
				i++
			}
			continue
		}
		if strings.HasPrefix(arg, "-") && len(arg) > 1 {
			for j := 1; j < len(arg); j++ {
				if strings.ContainsRune(shortFlags, rune(arg[j])) {
					return true
				}
				if strings.ContainsRune(shortValues, rune(arg[j])) {
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

func resolveGitLongOption(name string, options []gitPushLongOption) (gitPushLongOption, bool) {
	for _, option := range options {
		if option.name == name {
			return option, true
		}
	}
	var match gitPushLongOption
	found := false
	for _, option := range options {
		if !strings.HasPrefix(option.name, name) {
			continue
		}
		if found {
			return gitPushLongOption{}, false
		}
		match, found = option, true
	}
	return match, found
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
	optionsEnded := false
	var operands []string
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
		operands = append(operands, a)
		i++
	}
	if len(operands) > 0 {
		operands = operands[1:]
	}
	args.refspecs = append(args.refspecs, operands...)
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
