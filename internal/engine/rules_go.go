package engine

import (
	"bufio"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
)

var goSensitiveEnvironment = map[string]bool{
	"GOPROXY":      true,
	"GOINSECURE":   true,
	"GONOSUMDB":    true,
	"GONOSUMCHECK": true,
}

type goInvocation struct {
	subcommand string
	args       []string
	cwd        string
	cwdKnown   bool
}

func checkGoToolchain(s Simple) *policy.Verdict {
	invocation, ok := parseGoInvocation(s)
	if !ok {
		return nil
	}

	if goRegistryRedirect(s, invocation) {
		return &policy.Verdict{
			Decision: policy.Deny,
			RuleID:   "P6.registry-redirect",
			Reason:   "Go command redirects module verification or dependency resolution",
		}
	}
	if goToolExecOverride(s, invocation) {
		return &policy.Verdict{
			Decision: policy.Ask,
			RuleID:   "P1.toolexec",
			Reason:   "Go command delegates compilation or analysis to an execution override",
		}
	}

	switch invocation.subcommand {
	case "get", "install":
		return &policy.Verdict{
			Decision: policy.Ask,
			RuleID:   "P6.package-install",
			Reason:   "new Go module fetched and built",
		}
	case "run":
		if goRunFetchesExternalPackage(invocation) {
			return &policy.Verdict{
				Decision: policy.Ask,
				RuleID:   "P6.package-install",
				Reason:   "Go run fetches and executes an external module package",
			}
		}
	case "mod":
		if len(invocation.args) > 0 && invocation.args[0] == "edit" {
			return &policy.Verdict{
				Decision: policy.Ask,
				RuleID:   "P5.ci-infra-lockfile",
				Reason:   "go mod edit changes dependency metadata",
			}
		}
	}
	return nil
}

func parseGoInvocation(s Simple) (goInvocation, bool) {
	if head(s.Argv) != "go" || len(s.Argv) < 2 {
		return goInvocation{}, false
	}
	invocation := goInvocation{cwd: s.Cwd, cwdKnown: !s.cwdUnknown}
	args := s.Argv[1:]
	for len(args) > 0 {
		switch {
		case args[0] == "-C":
			if len(args) < 2 {
				return invocation, true
			}
			invocation.cwd, invocation.cwdKnown = goWorkingDirectory(invocation.cwd, args[1], invocation.cwdKnown)
			args = args[2:]
		case strings.HasPrefix(args[0], "-C="):
			invocation.cwd, invocation.cwdKnown = goWorkingDirectory(invocation.cwd, strings.TrimPrefix(args[0], "-C="), invocation.cwdKnown)
			args = args[1:]
		case strings.HasPrefix(args[0], "-"):
			// The go command currently exposes only -C before the subcommand. An
			// unknown global option leaves the execution shape unclassified.
			return invocation, true
		default:
			invocation.subcommand = args[0]
			invocation.args = args[1:]
			return invocation, true
		}
	}
	return invocation, true
}

func goWorkingDirectory(current, target string, currentKnown bool) (string, bool) {
	if !currentKnown {
		return "", false
	}
	if absolute, ok := hostProbePath(target); ok && filepath.IsAbs(absolute) {
		return absolute, true
	}
	if path.IsAbs(filepath.ToSlash(target)) {
		return "", false
	}
	base, ok := hostProbePath(current)
	if !ok {
		return "", false
	}
	return filepath.Clean(filepath.Join(base, filepath.FromSlash(target))), true
}

func goRegistryRedirect(s Simple, invocation goInvocation) bool {
	for name := range goSensitiveEnvironment {
		if _, ok := s.goEnvironment[name]; ok {
			return true
		}
	}
	if goFlagsContain(s.goEnvironment["GOFLAGS"], "-insecure") {
		return true
	}
	if invocation.subcommand != "env" || !containsArg(invocation.args, "-w") {
		return false
	}
	for _, arg := range invocation.args {
		name, value, assignment := strings.Cut(arg, "=")
		if !assignment {
			continue
		}
		if goSensitiveEnvironment[name] || name == "GOFLAGS" && goFlagsContain(value, "-insecure") {
			return true
		}
	}
	return false
}

func goToolExecOverride(s Simple, invocation goInvocation) bool {
	if goFlagsContain(s.goEnvironment["GOFLAGS"], "-toolexec") {
		return true
	}
	if invocation.subcommand == "env" && containsArg(invocation.args, "-w") {
		for _, arg := range invocation.args {
			name, value, assignment := strings.Cut(arg, "=")
			if assignment && name == "GOFLAGS" && goFlagsContain(value, "-toolexec") {
				return true
			}
		}
	}
	switch invocation.subcommand {
	case "build", "test", "vet":
		return goArgsContainToolExec(invocation.args, invocation.subcommand == "test")
	case "run":
		flags, _, _ := splitGoRunArgs(invocation.args)
		return goArgsContainToolExec(flags, false)
	default:
		return false
	}
}

func goArgsContainToolExec(args []string, stopAtArgs bool) bool {
	for index := 0; index < len(args); index++ {
		arg := args[index]
		if arg == "--" || stopAtArgs && arg == "-args" {
			return false
		}
		if arg == "-toolexec" || strings.HasPrefix(arg, "-toolexec=") {
			return true
		}
	}
	return false
}

func goFlagsContain(value, wanted string) bool {
	for _, flag := range strings.Fields(value) {
		if flag == wanted || strings.HasPrefix(flag, wanted+"=") {
			return true
		}
	}
	return false
}

func containsArg(args []string, wanted string) bool {
	for _, arg := range args {
		if arg == wanted {
			return true
		}
	}
	return false
}

func goRunFetchesExternalPackage(invocation goInvocation) bool {
	_, target, known := splitGoRunArgs(invocation.args)
	if !known {
		return true
	}
	if target == "" || goRunTargetIsLocal(target) {
		return false
	}
	path, _, versioned := strings.Cut(target, "@")
	if versioned {
		return goImportPathIsRemote(path)
	}
	if !goImportPathIsRemote(path) {
		return false
	}
	if !invocation.cwdKnown {
		return true
	}
	module, ok := nearestGoModule(invocation.cwd)
	return !ok || path != module && !strings.HasPrefix(path, module+"/")
}

var goRunValuedFlags = map[string]bool{
	"-asmflags":      true,
	"-buildmode":     true,
	"-compiler":      true,
	"-covermode":     true,
	"-coverpkg":      true,
	"-exec":          true,
	"-gccgoflags":    true,
	"-gcflags":       true,
	"-installsuffix": true,
	"-ldflags":       true,
	"-mod":           true,
	"-modfile":       true,
	"-overlay":       true,
	"-p":             true,
	"-pgo":           true,
	"-pkgdir":        true,
	"-tags":          true,
	"-toolexec":      true,
}

func splitGoRunArgs(args []string) (flags []string, target string, known bool) {
	for index := 0; index < len(args); index++ {
		arg := args[index]
		if arg == "--" {
			if index+1 >= len(args) {
				return flags, "", true
			}
			return flags, args[index+1], true
		}
		if !strings.HasPrefix(arg, "-") || arg == "-" {
			return flags, arg, true
		}
		flags = append(flags, arg)
		name, _, hasValue := strings.Cut(arg, "=")
		if goRunValuedFlags[name] && !hasValue {
			if index+1 >= len(args) {
				return flags, "", false
			}
			index++
			flags = append(flags, args[index])
			continue
		}
		if !goRunFlagKnown(name) {
			return flags, "", false
		}
	}
	return flags, "", true
}

func goRunFlagKnown(name string) bool {
	if goRunValuedFlags[name] {
		return true
	}
	switch name {
	case "-a", "-asan", "-buildvcs", "-cover", "-json", "-linkshared", "-modcacherw", "-msan", "-n", "-race", "-trimpath", "-v", "-work", "-x":
		return true
	default:
		return false
	}
}

func goRunTargetIsLocal(target string) bool {
	normalized := filepath.ToSlash(target)
	if normalized == "." || normalized == ".." || strings.HasPrefix(normalized, "./") || strings.HasPrefix(normalized, "../") {
		return true
	}
	return strings.HasSuffix(normalized, ".go")
}

func goImportPathIsRemote(target string) bool {
	first, _, _ := strings.Cut(filepath.ToSlash(target), "/")
	return strings.Contains(first, ".")
}

func nearestGoModule(cwd string) (string, bool) {
	directory, ok := hostProbePath(cwd)
	if !ok {
		return "", false
	}
	for {
		if module, ok := readGoModule(filepath.Join(directory, "go.mod")); ok {
			return module, true
		}
		parent := filepath.Dir(directory)
		if parent == directory {
			return "", false
		}
		directory = parent
	}
}

func readGoModule(path string) (string, bool) {
	file, err := os.Open(path)
	if err != nil {
		return "", false
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 2 || fields[0] != "module" {
			continue
		}
		module := fields[1]
		if unquoted, err := strconv.Unquote(module); err == nil {
			module = unquoted
		}
		return strings.TrimSpace(module), module != ""
	}
	return "", false
}
