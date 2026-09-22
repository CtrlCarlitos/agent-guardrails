package engine

import (
	"strings"

	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
)

// The go toolchain reached the analyzer as unknown words, so every subcommand
// was judged alike: not at all (#251).
//
// The cut is *whose code*, not whether code executes. `go test` runs module
// code exactly the way `go run` does — init(), TestMain, every test body — so
// an execution/no-execution line between them does not describe the risk.
// What does: running the repository's own packages is not something a static
// tool-call guard can contain, because the agent authored them and can reach
// them through Bash in a hundred other ways (ADR-0012), and those commands are
// the most frequent thing a Go developer types. Gating them would be friction
// with no containment gain, and the ask-pressure profile (`guardrail audit
// --verdicts`) is where that cost would show up.
//
// Gateable, and gated here:
//   - one-step fetch-and-execute (`go run <remote>`), the same class as the
//     `go get`/`go install` ask that checkPackageInstall already issues
//   - the module fetcher's own redirect levers, persistent and inline, which
//     are the direct analogue of `npm --registry` and `pip --index-url`
//   - `-toolexec`/`-vettool`, an arbitrary program run for every compile step
//   - writes to go.mod, matching the lockfile posture the Edit tool already has

// goRedirectEnvironment are the variables that repoint or weaken the module
// fetcher. Writing any of them is the supply-chain lever; reading them is not.
var goRedirectEnvironment = map[string]bool{
	"GOPROXY":      true,
	"GOFLAGS":      true,
	"GONOSUMDB":    true,
	"GONOSUMCHECK": true,
	"GOSUMDB":      true,
	"GOINSECURE":   true,
	"GOPRIVATE":    true,
}

// goRedirectEnvironmentVariable reports whether an inline assignment repoints
// the fetcher. Exported to the tokenizer's capture loop, which mirrors the way
// GIT_DIR and friends are already captured.
func goRedirectEnvironmentVariable(name string) bool { return goRedirectEnvironment[name] }

func checkGoToolchain(s Simple) *policy.Verdict {
	if head(s.Argv) != "go" && head(s.Argv) != "gofmt" {
		return nil
	}
	// An inline assignment is the same lever as `go env -w`, and it leaves no
	// persistent trace, so it is the likelier shape. The tokenizer strips the
	// prefix from Argv, so this reads the captured environment instead.
	for name := range s.goEnvironment {
		return &policy.Verdict{Decision: policy.Deny, RuleID: "P6.registry-redirect",
			Reason: "inline " + name + " repoints or weakens the Go module fetcher"}
	}
	if head(s.Argv) == "gofmt" || len(s.Argv) < 2 {
		return nil
	}

	subcommand := s.Argv[1]
	rest := s.Argv[2:]

	// -toolexec/-vettool run an arbitrary program for every compile step.
	// Checked before the subcommand switch because it applies across
	// build/run/test/vet and is out-of-band wherever it appears.
	for _, arg := range rest {
		name, _, _ := strings.Cut(arg, "=")
		if name == "-toolexec" || name == "--toolexec" || name == "-vettool" || name == "--vettool" {
			return ask("P1.toolexec",
				"go "+subcommand+" "+name+" runs an arbitrary program for every compile step")
		}
	}

	switch subcommand {
	case "env":
		if assignment, ok := goEnvWriteAssignment(rest); ok {
			return &policy.Verdict{Decision: policy.Deny, RuleID: "P6.registry-redirect",
				Reason: "go env -w " + assignment + " repoints or weakens the Go module fetcher"}
		}
	case "run":
		if target, remote := goRemotePackage(rest); remote {
			return &policy.Verdict{Decision: policy.Ask, RuleID: "P6.package-install",
				Reason: "go run " + target + " fetches and executes a module in one step"}
		}
	case "mod":
		return checkGoMod(rest)
	}
	return nil
}

// goEnvWriteAssignment returns the first `-w NAME=value` assignment that
// touches a redirect variable. `go env` without -w only reads.
func goEnvWriteAssignment(rest []string) (string, bool) {
	write := false
	for _, arg := range rest {
		if arg == "-w" || arg == "--w" {
			write = true
			continue
		}
		if !write {
			continue
		}
		name, _, found := strings.Cut(arg, "=")
		if found && goRedirectEnvironment[strings.ToUpper(name)] {
			return arg, true
		}
	}
	return "", false
}

func checkGoMod(rest []string) *policy.Verdict {
	if len(rest) == 0 {
		return nil
	}
	switch rest[0] {
	case "download":
		return &policy.Verdict{Decision: policy.Ask, RuleID: "P6.package-install",
			Reason: "go mod download fetches modules from the network"}
	case "edit":
		for _, arg := range rest[1:] {
			name, _, _ := strings.Cut(arg, "=")
			if name == "-replace" || name == "--replace" {
				return &policy.Verdict{Decision: policy.Deny, RuleID: "P6.registry-redirect",
					Reason: "go mod edit -replace points a module at an arbitrary path"}
			}
		}
		// Any other go.mod write is the lockfile posture the Edit tool already
		// asks for; asking here closes the gap between editing go.mod with a
		// tool and editing it with a command.
		return ask("P5.ci-infra-lockfile", "go mod edit writes go.mod")
	}
	return nil
}

// goRemotePackage reports whether a `go run` target is fetched rather than
// local. Local is the common case and must stay silent, so the test is
// deliberately narrow: a target is remote only if it carries an explicit
// @version or its first path segment looks like a domain.
func goRemotePackage(rest []string) (string, bool) {
	for _, arg := range rest {
		if strings.HasPrefix(arg, "-") {
			continue
		}
		if goRemotePackagePath(arg) {
			return arg, true
		}
		// The first non-flag operand is the package target; anything after it
		// belongs to the program being run.
		return "", false
	}
	return "", false
}

func goRemotePackagePath(target string) bool {
	if target == "" {
		return false
	}
	// `./x`, `.`, `..`, `../x`, and absolute paths are local by construction.
	if strings.HasPrefix(target, ".") || strings.HasPrefix(target, "/") || strings.HasPrefix(target, `\`) {
		return false
	}
	if strings.Contains(target, "@") {
		// An explicit version can only refer to a module to be fetched.
		return true
	}
	first, _, _ := strings.Cut(target, "/")
	// A domain component is what separates `github.com/x/y` from a standard
	// library package like `net/http` or a module-relative `cmd/x`.
	return strings.Contains(first, ".")
}
