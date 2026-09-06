package engine

import (
	"os"
	"path"
	"path/filepath"
	"strconv"
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
	simples, err := Normalize(tc.Command, tc.CWD)
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
		if s.Unresolved {
			take(&policy.Verdict{Decision: policy.Ask, RuleID: "P3.unresolved",
				Reason: "command contains an unexpanded variable or substitution; its real target cannot be verified"})
		}
		if len(s.Argv) == 0 {
			take(checkAskTier(s, tc, pol)) // redirect targets only
			continue
		}
		take(checkRmRf(s, tc, pol))
		take(checkDiskDestroyers(s))
		take(checkDestinationWrites(s, tc, pol))
		take(checkGit(s))
		take(checkGitSafety(s))
		take(checkDocker(s, tc.Command))
		take(checkAskTier(s, tc, pol))
		take(checkEgress(s, pol))
		take(checkPackageInstall(s))
	}
	return worst
}

func checkDestinationWrites(s Simple, tc ToolCall, pol *policy.Policy) *policy.Verdict {
	cwd := simpleCwd(s, tc)
	command := head(s.Argv)
	switch command {
	case "mv", "cp", "ln", "tee", "install":
	case "rsync":
		deletes, err := rsyncDeletionMode(s.Argv)
		if err != nil {
			return ask("P3.unresolved", "rsync option parsing could not establish deletion scope")
		}
		if !deletes {
			return nil
		}
	default:
		return nil
	}
	if spec, ok := mutatingDestinationCommands[command]; ok && parseDestinationArgs(s.Argv, spec).ambiguous {
		return ask("P3.unresolved", command+" option parsing could not establish destination scope")
	}
	if command == "mv" {
		for _, source := range moveSourceTargets(s.Argv) {
			candidate := pathCandidate{path: source, cwd: cwd, cwdUnknown: s.cwdUnknown}
			authorized, lexical := authorizedPath(candidate, tc.RepoRoot, pol.Slots.SafeRoots, true)
			if authorized {
				continue
			}
			if lexical || candidate.cwdUnknown && !filepath.IsAbs(source) {
				return ask("P1.out-of-repo-write", "moves a source that resolves outside the repo and configured safe roots: "+source)
			}
			resolved := resolvePath(source, cwd)
			if _, err := os.Lstat(resolved); !os.IsNotExist(err) {
				return ask("P1.out-of-repo-write", "moves a source outside the repo and configured safe roots: "+source)
			}
		}
	}
	for _, target := range writeTargets(s) {
		if command == "rsync" && rsyncRemoteTarget(target) {
			return ask("P1.out-of-repo-write", "writes to a remote destination outside configured safe roots: "+target)
		}
		candidate := pathCandidate{path: target, cwd: cwd, cwdUnknown: s.cwdUnknown}
		if authorized, _ := authorizedPath(candidate, tc.RepoRoot, pol.Slots.SafeRoots, true); !authorized {
			return ask("P1.out-of-repo-write", "writes to a path outside the repo and configured safe roots: "+target)
		}
	}
	return nil
}

type authorizedRoot struct {
	lexical  string
	physical string
}

func authorizedPath(candidate pathCandidate, repoRoot string, safeRoots []string, allowTemp bool) (authorized, lexical bool) {
	if candidate.path == "~" || strings.HasPrefix(candidate.path, "~/") || candidate.cwdUnknown && !filepath.IsAbs(candidate.path) {
		return false, false
	}
	target, err := filepath.Abs(resolvePath(candidate.path, candidate.cwd))
	if err != nil {
		return false, false
	}
	physicalTarget, ok := resolveExistingPath(target, "")
	if !ok {
		return false, false
	}
	var roots []authorizedRoot
	addRoot := func(root string, rejectSymlink bool) {
		if root == "" {
			return
		}
		if candidate.cwdUnknown && !filepath.IsAbs(root) {
			return
		}
		root, err = filepath.Abs(resolvePath(root, candidate.cwd))
		if err != nil || filepath.Clean(root) == string(filepath.Separator) {
			return
		}
		physical, ok := resolveExistingPath(root, "")
		if !ok || rejectSymlink && filepath.Clean(physical) != filepath.Clean(root) {
			return
		}
		roots = append(roots, authorizedRoot{lexical: root, physical: physical})
	}
	addRoot(repoRoot, false)
	for _, root := range safeRoots {
		addRoot(root, true)
	}
	if allowTemp {
		addRoot(os.TempDir(), false)
	}
	for _, root := range roots {
		if withinSafe(target, root.lexical, nil) {
			lexical = true
			if withinSafe(physicalTarget, root.physical, nil) {
				return true, true
			}
		}
	}
	return false, lexical
}

func rsyncRemoteTarget(target string) bool {
	if strings.HasPrefix(target, "rsync://") {
		return true
	}
	hostPath := target
	if at := strings.LastIndexByte(hostPath, '@'); at >= 0 {
		hostPath = hostPath[at+1:]
	}
	if strings.HasPrefix(hostPath, "[") {
		return strings.Contains(hostPath, "]:")
	}
	colon := strings.IndexByte(hostPath, ':')
	return colon > 0 && !strings.Contains(hostPath[:colon], "/")
}

func rsyncDeletionMode(argv []string) (bool, error) {
	spec := mutatingDestinationCommands["rsync"]
	deletionOptions := map[string]bool{
		"del": true, "delete": true, "delete-before": true, "delete-during": true,
		"delete-delay": true, "delete-after": true, "delete-excluded": true,
		"delete-missing-args": true,
	}
	for i := 1; i < len(argv); i++ {
		arg := argv[i]
		if arg == "--" {
			return false, nil
		}
		if !strings.HasPrefix(arg, "-") || arg == "-" {
			continue
		}
		if strings.HasPrefix(arg, "--") {
			name, _, attached := strings.Cut(strings.TrimPrefix(arg, "--"), "=")
			resolved, kind, ok := resolveDestinationLongOption(name, spec)
			if !ok {
				return false, unknownOpt("rsync", arg)
			}
			if deletionOptions[resolved] {
				if attached {
					return false, unknownOpt("rsync", arg)
				}
				return true, nil
			}
			if kind == destinationValue || kind == destinationWritePath {
				if !attached {
					if i+1 >= len(argv) {
						return false, needsValue("rsync", arg)
					}
					i++
				}
				continue
			}
			if kind == destinationFlag && attached {
				return false, unknownOpt("rsync", arg)
			}
			continue
		}
		short := strings.TrimPrefix(arg, "-")
		for j := 0; j < len(short); j++ {
			option := short[j]
			if strings.ContainsRune(spec.shortValues, rune(option)) {
				if j+1 == len(short) {
					if i+1 >= len(argv) {
						return false, needsValue("rsync", "-"+string(option))
					}
					i++
				}
				break
			}
			if !strings.ContainsRune(spec.shortFlags, rune(option)) {
				return false, unknownOpt("rsync", "-"+string(option))
			}
		}
	}
	return false, nil
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
		candidate := pathCandidate{path: raw, cwd: simpleCwd(s, tc), cwdUnknown: s.cwdUnknown}
		if candidate.cwdUnknown && !filepath.IsAbs(raw) {
			continue // P3 owns runtime-relative targets whose cwd is unknowable.
		}
		if authorized, _ := authorizedPath(candidate, tc.RepoRoot, pol.Slots.SafeRoots, false); !authorized {
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
		if args.force || args.forceWithLease {
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

type dockerOptionSpec struct {
	flags  map[string]bool
	values map[string]bool
}

func dockerOptionNames(names ...string) map[string]bool {
	out := make(map[string]bool, len(names))
	for _, name := range names {
		out[name] = true
	}
	return out
}

var dockerGlobalOptionSpecs = map[string]dockerOptionSpec{
	"docker": {
		flags: dockerOptionNames("-D", "--debug", "--help", "--tls", "--tlsverify", "-v", "--version"),
		values: dockerOptionNames(
			"--config", "-c", "--context", "-H", "--host", "-l", "--log-level",
			"--tlscacert", "--tlscert", "--tlskey",
		),
	},
	"podman": {
		flags: dockerOptionNames("--help", "--remote", "--syslog", "--transient-store", "-v", "--version"),
		values: dockerOptionNames(
			"--cgroup-manager", "-c", "--connection", "--conmon", "--events-backend",
			"--hooks-dir", "--identity", "--log-level", "--module", "--network-cmd-path",
			"--out", "--root", "--runroot", "--runtime", "--runtime-flag", "--ssh",
			"--storage-driver", "--storage-opt", "--tmpdir", "--url",
		),
	},
	"nerdctl": {
		flags: dockerOptionNames(
			"--bridge-nftables", "--debug", "--debug-full", "--experimental", "--help",
			"--insecure-registry", "-v", "--version",
		),
		values: dockerOptionNames(
			"-a", "--address", "--cgroup-manager", "--cni-netconfpath", "--data-root",
			"--host-gateway-ip", "--hosts-dir", "--log-level", "-n", "--namespace", "--snapshotter",
		),
	},
}

var dockerComposeOptionSpec = dockerOptionSpec{
	flags: dockerOptionNames(
		"--all-resources", "--compatibility", "--dry-run", "--help", "--no-ansi",
		"--skip-hostname-check", "--tls", "--tlsverify", "--verbose", "-v", "--version",
	),
	values: dockerOptionNames(
		"--ansi", "--env-file", "-f", "--file", "-H", "--host", "--log-level",
		"--parallel", "--profile", "--progress", "--project-directory", "-p", "--project-name",
		"--tlscacert", "--tlscert", "--tlskey",
	),
}

var dockerGroupOptionSpec = dockerOptionSpec{
	flags: dockerOptionNames("--help"),
}

var dockerRunOptionSpec = dockerOptionSpec{
	flags: dockerOptionNames(
		"-d", "--detach", "--disable-content-trust", "--help", "--init", "-i", "--interactive",
		"--oom-kill-disable", "-P", "--privileged", "--publish-all", "--read-only", "--rm",
		"--sig-proxy", "-t", "--tty", "--use-api-socket",
	),
	values: dockerOptionNames(
		"--add-host", "--annotation", "-a", "--attach", "--blkio-weight", "--blkio-weight-device",
		"--cap-add", "--cap-drop", "--cgroup-parent", "--cgroupns", "--cidfile", "-c", "--cpu-period",
		"--cpu-quota", "--cpu-rt-period", "--cpu-rt-runtime", "--cpu-shares", "--cpus", "--cpuset-cpus",
		"--cpuset-mems", "--device", "--device-cgroup-rule", "--device-read-bps", "--device-read-iops",
		"--detach-keys", "--device-write-bps", "--device-write-iops", "--dns", "--dns-option", "--dns-search", "--domainname",
		"--entrypoint", "-e", "--env", "--env-file", "--expose", "--gpus", "--group-add", "--health-cmd",
		"--health-interval", "--health-retries", "--health-start-interval", "--health-start-period", "--health-timeout",
		"-h", "--hostname", "--ip", "--ip6", "--ipc", "--isolation", "--kernel-memory", "-l", "--label",
		"--label-file", "--link", "--link-local-ip", "--log-driver", "--log-opt", "--mac-address", "-m", "--memory",
		"--memory-reservation", "--memory-swap", "--memory-swappiness", "--mount", "--name", "--network",
		"--network-alias", "--oom-score-adj", "--pid", "--pids-limit", "--platform", "-p", "--publish", "--pull",
		"--restart", "--runtime", "--security-opt", "--shm-size", "--stop-signal", "--stop-timeout", "--storage-opt",
		"--sysctl", "--tmpfs", "--ulimit", "-u", "--user", "--uts", "-v", "--volume", "--volume-driver",
		"--volumes-from", "-w", "--workdir",
	),
}

var dockerExecOptionSpec = dockerOptionSpec{
	flags: dockerOptionNames("-d", "--detach", "--help", "-i", "--interactive", "--privileged", "-t", "--tty"),
	values: dockerOptionNames(
		"--detach-keys", "-e", "--env", "--env-file", "--preserve-fd", "--preserve-fds",
		"-u", "--user", "-w", "--workdir",
	),
}

var dockerSubcommandGroups = map[string]bool{
	"builder": true, "container": true, "image": true,
	"network": true, "system": true, "volume": true,
}

func skipDockerOptions(scope string, argv []string, start int, spec dockerOptionSpec) (int, error) {
	for start < len(argv) {
		arg := argv[start]
		if arg == "--" {
			return start + 1, nil
		}
		if arg == "-" || !strings.HasPrefix(arg, "-") {
			return start, nil
		}
		if strings.HasPrefix(arg, "--") {
			base := arg
			value := ""
			attached := false
			if eq := strings.IndexByte(arg, '='); eq >= 0 {
				base, value, attached = arg[:eq], arg[eq+1:], true
			}
			switch {
			case spec.values[base]:
				if attached {
					start++
				} else {
					if start+1 >= len(argv) {
						return start, needsValue(scope, arg)
					}
					start += 2
				}
			case spec.flags[base]:
				if attached {
					if _, err := strconv.ParseBool(value); err != nil {
						return start, unknownOpt(scope, arg)
					}
				}
				start++
			default:
				return start, unknownOpt(scope, arg)
			}
			continue
		}

		consumed := false
		for i := 1; i < len(arg); i++ {
			option := "-" + arg[i:i+1]
			switch {
			case spec.values[option]:
				if i+1 < len(arg) {
					start++
				} else {
					if start+1 >= len(argv) {
						return start, needsValue(scope, option)
					}
					start += 2
				}
				consumed = true
			case spec.flags[option]:
				if i+1 < len(arg) && arg[i+1] == '=' {
					if _, err := strconv.ParseBool(arg[i+2:]); err != nil {
						return start, unknownOpt(scope, arg)
					}
					start++
					consumed = true
				}
			default:
				return start, unknownOpt(scope, arg)
			}
			if consumed {
				break
			}
		}
		if !consumed {
			start++
		}
	}
	return start, nil
}

func dockerSubcommandIndex(argv []string) (int, error) {
	spec, ok := dockerGlobalOptionSpecs[head(argv)]
	if !ok {
		return -1, nil
	}
	i, err := skipDockerOptions(head(argv)+" global", argv, 1, spec)
	if err != nil || i >= len(argv) {
		return -1, err
	}
	return i, nil
}

func parseDockerSubcommandChain(argv []string) ([]string, error) {
	if len(argv) < 2 {
		return nil, nil
	}
	if head(argv) == "docker-compose" {
		i, err := skipDockerOptions("docker-compose", argv, 1, dockerComposeOptionSpec)
		if err != nil || i >= len(argv) {
			return nil, err
		}
		return []string{argv[i]}, nil
	}

	i, err := dockerSubcommandIndex(argv)
	if err != nil {
		return nil, err
	}
	if i < 0 {
		return nil, nil
	}
	chain := []string{argv[i]}
	if chain[0] == "run" || chain[0] == "exec" {
		spec := dockerRunOptionSpec
		if chain[0] == "exec" {
			spec = dockerExecOptionSpec
		}
		_, err := skipDockerOptions(head(argv)+" "+chain[0], argv, i+1, spec)
		return chain, err
	}
	if chain[0] != "compose" && !dockerSubcommandGroups[chain[0]] {
		return chain, nil
	}
	spec := dockerGroupOptionSpec
	if chain[0] == "compose" {
		spec = dockerComposeOptionSpec
	}
	i, err = skipDockerOptions(head(argv)+" "+chain[0], argv, i+1, spec)
	if err != nil {
		return nil, err
	}
	if i < len(argv) {
		chain = append(chain, argv[i])
	}
	return chain, nil
}

// dockerSubcommandChain preserves the simple interface used by matching and
// returns no chain when strict option parsing cannot establish one safely.
func dockerSubcommandChain(argv []string) []string {
	chain, _ := parseDockerSubcommandChain(argv)
	return chain
}

func chainHasPrefix(chain []string, want ...string) bool {
	if len(chain) < len(want) {
		return false
	}
	for i := range want {
		if chain[i] != want[i] {
			return false
		}
	}
	return true
}

func checkDocker(s Simple, rawCmd string) *policy.Verdict {
	command := head(s.Argv)
	switch command {
	case "docker", "docker-compose", "podman", "nerdctl":
	default:
		return nil
	}
	chain, err := parseDockerSubcommandChain(s.Argv)
	if err != nil {
		return &policy.Verdict{Decision: policy.Ask, RuleID: "P3.unresolved",
			Reason: "docker option parsing could not establish the command boundary"}
	}
	if command == "docker-compose" {
		chain = append([]string{"compose"}, chain...)
	}
	if chainHasPrefix(chain, "compose", "down") {
		return &policy.Verdict{Decision: policy.Deny, RuleID: "P1.docker-down",
			Reason: "docker compose down tears down a whole stack"}
	}
	if (len(chain) >= 2 && dockerSubcommandGroups[chain[0]] && chain[1] == "prune") ||
		chainHasPrefix(chain, "prune") {
		return &policy.Verdict{Decision: policy.Deny, RuleID: "P1.docker-prune",
			Reason: "docker prune removes resources with unverifiable scope"}
	}
	destructive := chainHasPrefix(chain, "rm") || chainHasPrefix(chain, "kill") ||
		chainHasPrefix(chain, "volume", "rm") || chainHasPrefix(chain, "network", "rm")
	if destructive && commandHasSubstitution(rawCmd) {
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
	case "sudo", "su", "doas", "pkexec", "run0", "systemd-run", "flatpak-spawn", "toolbox", "distrobox-host-exec", "parallel":
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
		destructive := map[string]bool{"rm": true, "shred": true, "truncate": true, "dd": true}
		for i, a := range s.Argv {
			if a == "-delete" {
				return ask("P1.find-delete", "find -delete is a bulk deletion primitive")
			}
			if (a == "-exec" || a == "-execdir" || a == "-ok" || a == "-okdir") &&
				i+1 < len(s.Argv) && destructive[path.Base(s.Argv[i+1])] {
				return ask("P1.find-delete", "find "+a+" invokes a destructive command")
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
		candidate := pathCandidate{path: r, cwd: simpleCwd(s, tc), cwdUnknown: s.cwdUnknown}
		if candidate.cwdUnknown && !filepath.IsAbs(r) {
			continue // Preserve P3 without resolving against the guardrail process cwd.
		}
		if authorized, _ := authorizedPath(candidate, tc.RepoRoot, pol.Slots.SafeRoots, false); !authorized {
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

func simpleCwd(s Simple, tc ToolCall) string {
	if s.cwdUnknown {
		return ""
	}
	if s.Cwd != "" {
		return s.Cwd
	}
	return tc.CWD
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
