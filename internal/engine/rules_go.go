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
//   - `go generate`, whose directives are command lines the hook never sees
//   - `go tool <module tool>`, `go install`, `go get` (see each check below)

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
	if head(s.Argv) == "gofmt" {
		return nil
	}
	subcommand, rest, ok := goSubcommand(s.Argv)
	if !ok {
		return nil
	}

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
	case "generate":
		return checkGoGenerate(rest)
	case "tool":
		return checkGoTool(rest)
	case "install":
		return checkGoInstall(rest)
	case "get":
		// In module mode `go get` exists only to change go.mod requirements
		// and download them: a local pattern still resolves missing imports
		// from the network, and `go get go@X` / `toolchain@X` downloads a
		// toolchain that later runs. No form is free of remote effect.
		return &policy.Verdict{Decision: policy.Ask, RuleID: "P6.package-install",
			Reason: "go get changes go.mod requirements and downloads modules from the network"}
	}
	return nil
}

// goSubcommand returns the subcommand and its arguments, skipping the one
// global flag the go command accepts before it, `-C dir` (Go 1.20). Reading
// argv[1] let `go -C sub run example.com/x@latest` past every rule here.
func goSubcommand(argv []string) (string, []string, bool) {
	rest := argv[1:]
	for len(rest) > 0 {
		arg := rest[0]
		switch {
		case arg == "-C" || arg == "--C":
			if len(rest) < 2 {
				return "", nil, false
			}
			rest = rest[2:]
		case strings.HasPrefix(arg, "-C=") || strings.HasPrefix(arg, "--C="):
			rest = rest[1:]
		default:
			return arg, rest[1:], true
		}
	}
	return "", nil, false
}

// checkGoGenerate asks for `go generate`. It is not `go test`: it runs the
// program named in every //go:generate directive, a command line the hook
// never sees, so a directive written into a file launders a command the
// Engine would judge if it were typed. `-n` prints the commands and runs
// nothing.
func checkGoGenerate(rest []string) *policy.Verdict {
	for _, arg := range rest {
		if arg == "-n" || arg == "--n" {
			return nil
		}
		if arg == "--" {
			break
		}
	}
	return ask("P1.go-generate",
		"go generate runs the command in every //go:generate directive, which this hook never sees; run go generate -n to list them first")
}

// goBuiltinTools are the tools shipped with the Go distribution under
// $GOROOT/pkg/tool. They can do nothing the shell cannot, and a go.mod tool
// directive cannot shadow them.
var goBuiltinTools = map[string]bool{
	"addr2line": true, "asm": true, "buildid": true, "cgo": true, "compile": true,
	"covdata": true, "cover": true, "dist": true, "distpack": true, "doc": true,
	"fix": true, "link": true, "nm": true, "objdump": true, "pack": true,
	"pprof": true, "preprofile": true, "test2json": true, "trace": true, "vet": true,
}

// checkGoTool allows the distribution's tools and asks for a tool declared by
// a go.mod `tool` directive (Go 1.24): third-party module code built and run
// in one step, fetched first when it is not cached — the `go run <remote>`
// shape.
func checkGoTool(rest []string) *policy.Verdict {
	for i := 0; i < len(rest); i++ {
		arg := rest[i]
		switch {
		case arg == "-n" || arg == "--n":
			return nil // prints the tool's path, runs nothing
		case arg == "-modfile" || arg == "--modfile":
			i++
			continue
		case strings.HasPrefix(arg, "-"):
			continue
		}
		name := strings.TrimSuffix(strings.ToLower(arg), ".exe")
		if goBuiltinTools[name] {
			return nil
		}
		return &policy.Verdict{Decision: policy.Ask, RuleID: "P6.package-install",
			Reason: "go tool " + arg + " runs a tool declared in go.mod: third-party module code fetched, built and executed in one step"}
	}
	return nil // `go tool` alone lists the tools
}

// checkGoInstall separates the two things `go install` does. With a module
// path or a version it fetches, builds and installs third-party code: the
// package-install ask. With the repository's own packages it fetches nothing
// `go build` would not, but it still writes an executable into GOBIN, which is
// on PATH and outside the repository — a binary named `git` there shadows the
// real one — so it is the out-of-repo write ask, with the in-repo alternative.
func checkGoInstall(rest []string) *policy.Verdict {
	for _, arg := range rest {
		if strings.HasPrefix(arg, "-") {
			continue
		}
		if goRemotePackagePath(arg) {
			return &policy.Verdict{Decision: policy.Ask, RuleID: "P6.package-install",
				Reason: "go install " + arg + " fetches, builds and installs a module"}
		}
	}
	return ask("P1.out-of-repo-write",
		"go install writes an executable into GOBIN, on PATH and outside the repository; use go build -o <path in the repo> to build in place")
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
