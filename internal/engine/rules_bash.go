package engine

import (
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
)

func head(argv []string) string {
	if len(argv) == 0 {
		return ""
	}
	return path.Base(argv[0])
}

func checkBash(tc ToolCall, pol *policy.Policy) *policy.Verdict {
	if !tc.IsBash() {
		return nil
	}
	simples, err := Normalize(tc.Command)
	if err != nil {
		return &policy.Verdict{Decision: policy.Ask, RuleID: "tokenize-failed",
			Reason: "could not parse shell command; failing closed to ask"}
	}
	var worst *policy.Verdict
	take := func(v *policy.Verdict) {
		if v == nil {
			return
		}
		if pol.Waived[v.RuleID] {
			return
		}
		if worst == nil || v.Decision.Severity() > worst.Decision.Severity() {
			worst = v
		}
	}
	take(checkDownloadPipeShell(simples))
	for _, s := range simples {
		if len(s.Argv) == 0 {
			continue
		}
		if s.Unresolved {
			take(&policy.Verdict{Decision: policy.Ask, RuleID: "P3.unresolved",
				Reason: "command contains an unexpanded variable or substitution; its real target cannot be verified"})
		}
		take(checkRmRf(s, tc, pol))
		take(checkDiskDestroyers(s))
		take(checkGit(s))
		take(checkGitSafety(s))
		take(checkDocker(s, tc.Command))
		take(checkAskTier(s, tc, pol))
		take(checkEgress(s, pol))
		take(checkPackageInstall(s))
	}
	return worst
}

func hasAnyFlag(argv []string, short string, long ...string) bool {
	for _, a := range argv[1:] {
		if strings.HasPrefix(a, "--") {
			for _, l := range long {
				if a == l || strings.HasPrefix(a, l+"=") {
					return true
				}
			}
			continue
		}
		if strings.HasPrefix(a, "-") && len(a) > 1 {
			if strings.ContainsAny(a[1:], short) {
				return true
			}
		}
	}
	return false
}

func nonFlagArgs(argv []string) []string {
	var out []string
	for _, a := range argv[1:] {
		if !strings.HasPrefix(a, "-") {
			out = append(out, a)
		}
	}
	return out
}

func checkRmRf(s Simple, tc ToolCall, pol *policy.Policy) *policy.Verdict {
	if head(s.Argv) != "rm" {
		return nil
	}
	if !hasAnyFlag(s.Argv, "rfR", "--recursive", "--force") {
		// need at least one of recursive OR force to be dangerous
		return nil
	}
	recursive := hasAnyFlag(s.Argv, "rR", "--recursive")
	force := hasAnyFlag(s.Argv, "f", "--force")
	if !recursive && !force {
		return nil
	}
	for _, raw := range nonFlagArgs(s.Argv) {
		if !withinSafe(resolvePath(raw, tc.CWD), tc.RepoRoot, pol.Slots.SafeRoots) {
			return &policy.Verdict{Decision: policy.Deny, RuleID: "P1.rm-rf",
				Reason: "recursive/forced rm of a path outside the repo and configured safe roots: " + raw}
		}
	}
	return nil
}

func checkGit(s Simple) *policy.Verdict {
	if head(s.Argv) != "git" || len(s.Argv) < 2 {
		return nil
	}
	sub := gitSubcommand(s.Argv)
	switch sub {
	case "push":
		args := parseGitPushArgs(s.Argv)
		if args.force {
			return &policy.Verdict{Decision: policy.Deny, RuleID: "P1.git-push-force",
				Reason: "git push --force overwrites remote history"}
		}
	case "clean":
		if hasAnyFlag(s.Argv, "fxd", "--force") {
			return &policy.Verdict{Decision: policy.Deny, RuleID: "P1.git-clean",
				Reason: "git clean -f/-x/-d deletes untracked files irrecoverably"}
		}
	}
	return nil
}

// gitValueFlags are git global options that consume a following token.
// Missing one shifts subcommand parsing and silently disables every git rule
// — exactly the class the v0.4.1 hotfix closed for -C/-c and the 2026-09-04
// review reopened through --git-dir. Keep this list complete.
var gitValueFlags = map[string]bool{
	"-C": true, "-c": true, "--namespace": true,
	"--git-dir": true, "--work-tree": true, "--exec-path": true,
	"--attr-source": true, "--super-prefix": true, "--config-env": true,
}

// gitValuelessGlobals are global options that take no following token.
var gitValuelessGlobals = map[string]bool{
	"-p": true, "-P": true, "--no-pager": true, "--paginate": true, "--bare": true,
	"--literal-pathspecs": true, "--no-replace-objects": true,
	"--help": true, "--version": true, "--no-optional-locks": true,
}

// gitSubcommand returns the git subcommand (e.g. "push", "config"), correctly
// skipping global options that take a separate value token before it.
func gitSubcommand(argv []string) string {
	i := gitSubcommandIndex(argv)
	if i < 0 {
		return ""
	}
	return argv[i]
}

func gitSubcommandIndex(argv []string) int {
	for i := 1; i < len(argv); {
		a := argv[i]
		if !strings.HasPrefix(a, "-") {
			return i
		}
		if gitValueFlags[a] {
			i += 2
			continue
		}
		i++
	}
	return -1
}

// gitSubcommandArg returns the token immediately after the git subcommand
// ("clear" in "git stash clear"), or "" when absent. Sub-subcommands must be
// read relative to the subcommand, not at the fixed position s.Argv[2]:
// global options like "-C <path>"/"-c k=v" before the subcommand shift every
// later token, which bypassed the reflog/remote/stash rules exactly the way
// the subcommand misparse did.
func gitSubcommandArg(argv []string) string {
	i := gitSubcommandIndex(argv)
	if i >= 0 && i+1 < len(argv) {
		return argv[i+1]
	}
	return ""
}

// gitSubcommandUnknownFlag returns the first --flag preceding the subcommand
// that this code does not recognise. A new git global option must fail closed
// rather than silently shift the subcommand.
func gitSubcommandUnknownFlag(argv []string) string {
	for i := 1; i < len(argv); {
		a := argv[i]
		if !strings.HasPrefix(a, "-") {
			return ""
		}
		base := a
		if eq := strings.Index(a, "="); eq >= 0 {
			base = a[:eq]
		}
		if gitValueFlags[base] {
			if strings.Contains(a, "=") {
				i++
			} else {
				i += 2
			}
			continue
		}
		if gitValuelessGlobals[base] {
			i++
			continue
		}
		if !strings.HasPrefix(a, "--") {
			i++
			continue
		}
		return a
	}
	return ""
}

func checkDocker(s Simple, rawCmd string) *policy.Verdict {
	if head(s.Argv) != "docker" || len(s.Argv) < 2 {
		return nil
	}
	joined := strings.Join(s.Argv[1:], " ")
	switch {
	case strings.HasPrefix(joined, "compose down"):
		return &policy.Verdict{Decision: policy.Deny, RuleID: "P1.docker-down",
			Reason: "docker compose down tears down a whole stack"}
	case strings.HasPrefix(joined, "system prune"),
		strings.HasPrefix(joined, "network prune"),
		strings.HasPrefix(joined, "volume prune"):
		return &policy.Verdict{Decision: policy.Deny, RuleID: "P1.docker-prune",
			Reason: "docker prune removes resources with unverifiable scope"}
	}
	first := s.Argv[1]
	target := strings.HasPrefix(joined, "rm ") || strings.HasPrefix(joined, "kill ") ||
		strings.HasPrefix(joined, "volume rm") || strings.HasPrefix(joined, "network rm")
	if (first == "rm" || first == "kill" || first == "volume" || first == "network") && target &&
		commandHasSubstitution(rawCmd) {
		return &policy.Verdict{Decision: policy.Deny, RuleID: "P1.docker-substituted",
			Reason: "docker rm/kill with a command-substituted target list"}
	}
	return nil
}

func commandHasSubstitution(cmd string) bool {
	return strings.Contains(cmd, "$(") || strings.Contains(cmd, "`")
}

func checkDiskDestroyers(s Simple) *policy.Verdict {
	command := head(s.Argv)
	switch {
	case command == "dd":
		for _, a := range s.Argv[1:] {
			if strings.HasPrefix(a, "of=/dev/") {
				return &policy.Verdict{Decision: policy.Deny, RuleID: "P1.dd",
					Reason: "dd writing to a raw device: " + a}
			}
		}
	case command == "mkfs" || strings.HasPrefix(command, "mkfs.") || command == "mke2fs" || command == "wipefs":
		return &policy.Verdict{Decision: policy.Deny, RuleID: "P1.mkfs",
			Reason: "filesystem-destroying command: " + command}
	case command == "shred" || command == "srm":
		return &policy.Verdict{Decision: policy.Deny, RuleID: "P1.shred",
			Reason: "irreversible secure-delete command: " + command}
	}
	return nil
}

func checkAskTier(s Simple, tc ToolCall, pol *policy.Policy) *policy.Verdict {
	switch head(s.Argv) {
	case "sudo", "su", "doas":
		return &policy.Verdict{Decision: policy.Deny, RuleID: "P1.privesc",
			Reason: "privilege escalation removes every other guardrail's ground truth"}
	case "chmod":
		if hasAnyFlag(s.Argv, "R", "--recursive") {
			return ask("P1.chmod", "recursive chmod")
		}
		for _, a := range nonFlagArgs(s.Argv) {
			if a == "777" || a == "0777" {
				return ask("P1.chmod", "chmod 777 widens permissions dangerously")
			}
		}
	case "chown":
		if hasAnyFlag(s.Argv, "R", "--recursive") {
			return ask("P1.chown", "recursive chown")
		}
	case "find":
		for i, a := range s.Argv {
			if a == "-delete" {
				return ask("P1.find-delete", "find -delete is a bulk deletion primitive")
			}
			if a == "-exec" && i+1 < len(s.Argv) && s.Argv[i+1] == "rm" {
				return ask("P1.find-delete", "find -exec rm is a bulk deletion primitive")
			}
		}
	case "truncate":
		return ask("P1.truncate", "truncate destroys file contents with no diff")
	case "kill":
		if hasAnyFlag(s.Argv, "9") {
			return ask("P1.kill", "kill -9 can corrupt the target process's state")
		}
	case "killall", "pkill":
		return ask("P1.kill", "killall/pkill can terminate unrelated work")
	}
	for _, r := range s.Redirects {
		if !withinSafe(resolvePath(r, tc.CWD), tc.RepoRoot, pol.Slots.SafeRoots) {
			return ask("P1.redirect", "output redirection onto a path outside the repo/safe roots: "+r)
		}
	}
	return nil
}

func ask(id, reason string) *policy.Verdict {
	return &policy.Verdict{Decision: policy.Ask, RuleID: id, Reason: reason}
}

func resolvePath(p, cwd string) string {
	if strings.HasPrefix(p, "~") {
		return p // treat "~" as outside any safe root; do not expand
	}
	if filepath.IsAbs(p) || cwd == "" {
		return p
	}
	if os.IsPathSeparator(cwd[len(cwd)-1]) {
		return cwd + p
	}
	return cwd + string(filepath.Separator) + p
}

func withinSafe(target, repoRoot string, safeRoots []string) bool {
	if target == "~" || strings.HasPrefix(target, "~/") {
		return false
	}
	target = filepath.Clean(target)
	if target == "/" {
		return false
	}
	roots := append([]string{repoRoot}, safeRoots...)
	for _, r := range roots {
		if r == "" {
			continue
		}
		rr := filepath.Clean(r)
		if target == rr || strings.HasPrefix(target, rr+string(filepath.Separator)) {
			return true
		}
	}
	return false
}
