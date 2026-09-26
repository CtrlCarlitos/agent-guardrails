package engine

import (
	"regexp"
	"strings"

	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
)

// #381: the install and remote-launch verbs of every mainstream manager get
// the same P6.package-install ask that `pip install` and `npm install` always
// had, under every spelling. checkPackageInstall owns the original spellings
// and falls through to checkInstallSpellings for the rest.

var pythonLauncherName = regexp.MustCompile(`^(python[0-9.]*|py)$`)

// pipModuleArgv rewrites `python -m pip <args>` to `pip <args>` so the pip
// rules (install ask, registry-redirect deny) see one spelling.
func pipModuleArgv(argv []string) []string {
	if len(argv) >= 3 && pythonLauncherName.MatchString(head(argv)) && argv[1] == "-m" &&
		(argv[2] == "pip" || argv[2] == "pip3") {
		return append([]string{"pip"}, argv[3:]...)
	}
	return argv
}

func installAsk(reason string) *policy.Verdict {
	return &policy.Verdict{Decision: policy.Ask, RuleID: "P6.package-install", Reason: reason}
}

func checkInstallSpellings(s Simple) *policy.Verdict {
	command := head(s.Argv)
	operands := nonFlagArgs(s.Argv)
	verb, next := "", ""
	if len(operands) > 0 {
		verb = operands[0]
	}
	if len(operands) > 1 {
		next = operands[1]
	}

	switch command {
	case "pipx":
		switch verb {
		case "install", "inject", "upgrade", "upgrade-all", "reinstall", "reinstall-all", "install-all":
			return installAsk("new Python tool — runs install scripts with your privileges")
		case "run":
			return installAsk("pipx run downloads and executes remote code")
		}
	case "uv":
		switch verb {
		case "sync", "add":
			return installAsk("uv " + verb + " installs Python dependencies — runs install scripts with your privileges")
		case "pip":
			if next == "install" || next == "sync" {
				return installAsk("uv pip " + next + " installs Python dependencies — runs install scripts with your privileges")
			}
		case "tool":
			if next == "install" || next == "upgrade" || next == "run" {
				return installAsk("uv tool " + next + " installs or runs a remote Python tool")
			}
		}
	case "poetry":
		switch verb {
		case "install", "add", "update", "sync":
			return installAsk("poetry " + verb + " installs Python dependencies — runs install scripts with your privileges")
		}
	case "yarn":
		if len(operands) == 0 && !hasAnyFlag(s.Argv, "vh", "--version", "--help") {
			return installAsk("bare yarn installs the JS dependencies — runs postinstall scripts with your privileges")
		}
		if verb == "dlx" {
			return launcherVerdict(s.Argv, "yarn dlx", operands[1:])
		}
	case "pnpm":
		if verb == "dlx" {
			return launcherVerdict(s.Argv, "pnpm dlx", operands[1:])
		}
	case "npm":
		if verb == "exec" || verb == "x" {
			return launcherVerdict(s.Argv, "npm "+verb, operands[1:])
		}
	case "bun":
		if verb == "x" {
			return launcherVerdict(s.Argv, "bun x", operands[1:])
		}
	case "npx", "bunx", "uvx":
		return launcherVerdict(s.Argv, command, operands)
	case "graft":
		switch verb {
		case "init":
			return installAsk("graft init writes agent instruction files, MCP config and hooks into the repo")
		case "uninstall":
			return installAsk("graft uninstall removes agent configuration and hooks from the repo")
		case "upgrade":
			return installAsk("graft upgrade installs a new graft release from a registry")
		case "build":
			if hasBareFlag(s.Argv, "--deep") {
				return installAsk("graft build --deep sends code to an LLM provider using an API key")
			}
		}
	}
	return nil
}

// launcherFlagsAreInert are the only flags allowed next to a local package
// spec: anything else may redirect the package (`--package`, `--from`,
// `--with`, `--registry`) and the local-looking operand is then not the code
// that runs.
var launcherFlagsAreInert = map[string]bool{
	"-y": true, "--yes": true, "-q": true, "--quiet": true, "--silent": true,
}

// launcherVerdict asks for a fetch-and-run launcher unless nothing is
// fetched: `--no-install` (`--no` for npm) resolves only local binaries, a
// missing package spec runs nothing, and a bare local path is not fetched.
func launcherVerdict(argv []string, name string, operands []string) *policy.Verdict {
	for _, a := range argv[1:] {
		if a == "--no-install" || a == "--no" {
			return nil
		}
	}
	remote := installAsk(name + " downloads and runs a package from a registry unless it is already local; use --no-install or a local path")
	if len(operands) == 0 {
		if hasAnyFlag(argv, "p", "--package", "--from", "--with") {
			return remote
		}
		return nil
	}
	if isLocalPackageSpec(operands[0]) {
		for _, a := range argv[1:] {
			if strings.HasPrefix(a, "-") && !launcherFlagsAreInert[a] {
				return remote
			}
		}
		return nil
	}
	return remote
}

var windowsDriveSpec = regexp.MustCompile(`^[A-Za-z]:[\\/]`)

func isLocalPackageSpec(spec string) bool {
	return spec == "." || spec == ".." ||
		strings.HasPrefix(spec, "./") || strings.HasPrefix(spec, "../") ||
		strings.HasPrefix(spec, `.\`) || strings.HasPrefix(spec, `..\`) ||
		strings.HasPrefix(spec, "/") || strings.HasPrefix(spec, "~/") ||
		strings.HasPrefix(spec, "file:") || windowsDriveSpec.MatchString(spec)
}
