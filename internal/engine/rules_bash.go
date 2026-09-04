package engine

import (
	"path/filepath"
	"strings"

	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
)

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
	if s.Argv[0] != "rm" {
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
	if s.Argv[0] != "git" || len(s.Argv) < 2 {
		return nil
	}
	sub := gitSubcommand(s.Argv)
	switch sub {
	case "push":
		if hasAnyFlag(s.Argv, "f", "--force", "--force-with-lease") {
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

func gitSubcommand(argv []string) string {
	for _, a := range argv[1:] {
		if strings.HasPrefix(a, "-") {
			continue
		}
		if a == "-C" { // handled as flag above only if prefixed; -C takes a value
			continue
		}
		return a
	}
	return ""
}

func checkDocker(s Simple, rawCmd string) *policy.Verdict {
	if s.Argv[0] != "docker" || len(s.Argv) < 2 {
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
	head := s.Argv[0]
	switch {
	case head == "dd":
		for _, a := range s.Argv[1:] {
			if strings.HasPrefix(a, "of=/dev/") {
				return &policy.Verdict{Decision: policy.Deny, RuleID: "P1.dd",
					Reason: "dd writing to a raw device: " + a}
			}
		}
	case head == "mkfs" || strings.HasPrefix(head, "mkfs.") || head == "mke2fs" || head == "wipefs":
		return &policy.Verdict{Decision: policy.Deny, RuleID: "P1.mkfs",
			Reason: "filesystem-destroying command: " + head}
	case head == "shred" || head == "srm":
		return &policy.Verdict{Decision: policy.Deny, RuleID: "P1.shred",
			Reason: "irreversible secure-delete command: " + head}
	}
	return nil
}

func checkAskTier(s Simple, tc ToolCall, pol *policy.Policy) *policy.Verdict {
	head := s.Argv[0]
	switch head {
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
	if filepath.IsAbs(p) {
		return filepath.Clean(p)
	}
	return filepath.Clean(filepath.Join(cwd, p))
}

func withinSafe(target, repoRoot string, safeRoots []string) bool {
	if target == "~" || strings.HasPrefix(target, "~/") || target == "/" {
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
