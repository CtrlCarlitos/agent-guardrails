package engine

import (
	"path"
	"path/filepath"
	"strings"

	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
	"github.com/bmatcuk/doublestar/v4"
)

var pathReaders = map[string]bool{
	"cat": true, "head": true, "tail": true, "grep": true, "egrep": true, "fgrep": true,
	"sed": true, "awk": true, "less": true, "more": true, "bat": true, "xxd": true,
	"od": true, "strings": true,
}

func isFileTool(tool string) bool {
	switch strings.ToLower(tool) {
	case "read", "edit", "write", "multiedit":
		return true
	}
	return false
}

// isWriteToolCall reports whether tc is a file-tool call that mutates.
// Bash calls are excluded here on purpose: their write intent is carried by
// redirect targets (and, after the writeCandidates work, by argv), not by the
// tool name.
func isWriteToolCall(tool string) bool {
	switch strings.ToLower(tool) {
	case "edit", "write", "multiedit":
		return true
	}
	return false
}

func checkPaths(tc ToolCall, pol *policy.Policy) *policy.Verdict {
	var candidates []string
	if isFileTool(tc.Tool) {
		candidates = append(candidates, tc.Paths...)
	}
	if tc.IsBash() {
		simples, err := Normalize(tc.Command)
		if err == nil {
			for _, s := range simples {
				if len(s.Argv) > 0 && pathReaders[s.Argv[0]] {
					candidates = append(candidates, nonFlagArgs(s.Argv)...)
				}
			}
		}
	}
	for _, c := range candidates {
		c = strings.TrimPrefix(c, "~/")
		c = strings.TrimPrefix(c, "~")
		if matchesAnyGlob(c, pol.Slots.SecretAllow) {
			continue
		}
		if matchesAnyGlob(c, pol.Slots.SecretGlobs) {
			if !pol.Waived["P4.secret-path"] {
				return &policy.Verdict{Decision: policy.Deny, RuleID: "P4.secret-path",
					Reason: "access to a credential/secret path: " + c}
			}
			// waived here: skip the secret-path verdict but still check this
			// candidate (and the rest) for symlink escape; Evaluate re-filters
			// waived rules as the single semantic waiver point.
		}
		if v := checkSymlinkEscape(c, tc); v != nil {
			return v
		}
	}
	if v := checkGitProtectedPaths(tc); v != nil {
		return v
	}
	if v := checkSelfConfig(tc); v != nil {
		return v
	}
	if v := checkCIInfraLockfile(tc); v != nil {
		return v
	}
	if v := checkOutOfRepoWrite(tc); v != nil {
		return v
	}
	return nil
}

var mutatingDestinationCommands = map[string]bool{
	"cp": true, "mv": true, "install": true, "ln": true, "rsync": true,
}

// rsync is intentionally absent: its -t flag means --times.
var targetDirectoryCommands = map[string]bool{
	"cp": true, "mv": true, "install": true, "ln": true,
}

var mutatingAllArgs = map[string]bool{
	"rm": true, "truncate": true, "chmod": true, "chown": true,
	"mkdir": true, "tee": true, "touch": true, "shred": true,
}

func destinationTargets(argv []string, supportsTargetDirectory bool) []string {
	var operands []string
	var targetDirectory string
	targetDirectorySet := false
	options := true
	for i := 1; i < len(argv); i++ {
		a := argv[i]
		if options && a == "--" {
			options = false
			continue
		}
		if options && supportsTargetDirectory {
			switch {
			case a == "-t" || a == "--target-directory":
				targetDirectorySet = true
				if i+1 < len(argv) {
					i++
					targetDirectory = argv[i]
				}
				continue
			case strings.HasPrefix(a, "--target-directory="):
				targetDirectorySet = true
				targetDirectory = strings.TrimPrefix(a, "--target-directory=")
				continue
			case strings.HasPrefix(a, "-t") && len(a) > 2:
				targetDirectorySet = true
				targetDirectory = strings.TrimPrefix(a, "-t")
				continue
			}
		}
		if options && strings.HasPrefix(a, "-") {
			continue
		}
		operands = append(operands, a)
	}

	if targetDirectorySet {
		if targetDirectory == "" {
			return nil
		}
		out := []string{targetDirectory}
		for _, source := range operands {
			out = append(out, path.Join(targetDirectory, path.Base(source)))
		}
		return out
	}
	if len(operands) == 0 {
		return nil
	}
	return operands[len(operands)-1:]
}

func writeTargets(s Simple) []string {
	if len(s.Argv) == 0 {
		return nil
	}
	head := path.Base(s.Argv[0])
	args := nonFlagArgs(s.Argv)

	if head == "dd" {
		var out []string
		for _, a := range s.Argv[1:] {
			if strings.HasPrefix(a, "of=") {
				out = append(out, strings.TrimPrefix(a, "of="))
			}
		}
		return out
	}
	// sed -i edits in place; without -i it is a reader.
	if head == "sed" {
		if !hasAnyFlag(s.Argv, "i", "--in-place") {
			return nil
		}
		if len(args) > 1 {
			return args[1:] // args[0] is the script
		}
		return nil
	}
	if mutatingDestinationCommands[head] {
		return destinationTargets(s.Argv, targetDirectoryCommands[head])
	}
	if mutatingAllArgs[head] {
		return args
	}
	return nil
}

func writeCandidates(tc ToolCall) []string {
	var out []string
	if isFileTool(tc.Tool) {
		out = append(out, tc.Paths...)
	}
	if tc.IsBash() {
		if simples, err := Normalize(tc.Command); err == nil {
			for _, s := range simples {
				out = append(out, s.Redirects...)
				out = append(out, writeTargets(s)...)
			}
		}
	}
	return out
}

func checkGitProtectedPaths(tc ToolCall) *policy.Verdict {
	if isFileTool(tc.Tool) && !isWriteToolCall(tc.Tool) {
		return nil
	}
	for _, c := range writeCandidates(tc) {
		if matchesAnyGlob(strings.TrimPrefix(c, "./"), gitProtectedGlobs) {
			return &policy.Verdict{Decision: policy.Deny, RuleID: "P2.git-protected-path",
				Reason: "write to a protected git-internal path: " + c}
		}
	}
	return nil
}

var selfConfigGlobs = []string{
	"**/.claude/**", "CLAUDE.md", "AGENTS.md", ".mcp.json", ".envrc",
	"**/.bashrc", "**/.zshrc", "**/.profile", "**/.bash_profile",
	// Guardrail's own machinery: the agent must not configure, disable, or
	// replace the thing supervising it (CR-14).
	"guardrail.toml", "**/guardrail.toml",
	"**/.guardrail/**",
	"opencode.json", "**/opencode.json",
	"**/.agents/hooks.json",
	"**/.gemini/config/hooks.json",
	"**/.local/bin/guardrail", "**/bin/guardrail",
}

func checkSelfConfig(tc ToolCall) *policy.Verdict {
	if isFileTool(tc.Tool) && !isWriteToolCall(tc.Tool) {
		return nil
	}
	for _, c := range writeCandidates(tc) {
		if matchesAnyGlob(strings.TrimPrefix(c, "./"), selfConfigGlobs) {
			return &policy.Verdict{Decision: policy.Deny, RuleID: "P5.self-config",
				Reason: "write to the agent's own guardrail/shell config: " + c}
		}
	}
	return nil
}

var ciInfraLockGlobs = []string{
	"**/.github/workflows/**", ".gitlab-ci.yml", "**/.circleci/**", "Jenkinsfile",
	"**/.buildkite/**", ".pre-commit-config.yaml", "azure-pipelines.yml",
	"Dockerfile", "docker-compose*.yml", "*.tf", "Makefile", "justfile", "Taskfile.yml",
	"setup.py", "conftest.py", "noxfile.py",
	"package-lock.json", "yarn.lock", "pnpm-lock.yaml", "Cargo.lock",
	"poetry.lock", "uv.lock", "go.sum", "Gemfile.lock", "mix.lock", "composer.lock",
}

func checkCIInfraLockfile(tc ToolCall) *policy.Verdict {
	if !isFileTool(tc.Tool) && !tc.IsBash() {
		return nil
	}
	// only Write/Edit — reading these is fine
	if isFileTool(tc.Tool) && !isWriteToolCall(tc.Tool) {
		return nil
	}
	for _, c := range writeCandidates(tc) {
		if matchesAnyGlob(strings.TrimPrefix(c, "./"), ciInfraLockGlobs) {
			return &policy.Verdict{Decision: policy.Ask, RuleID: "P5.ci-infra-lockfile",
				Reason: "edit of a CI/infra/lockfile — this code runs later with more privilege: " + c}
		}
	}
	return nil
}

func checkOutOfRepoWrite(tc ToolCall) *policy.Verdict {
	if tc.RepoRoot == "" {
		return nil
	}
	if !strings.EqualFold(tc.Tool, "edit") && !strings.EqualFold(tc.Tool, "write") && !strings.EqualFold(tc.Tool, "multiedit") {
		return nil
	}
	for _, p := range tc.Paths {
		abs := resolvePath(p, tc.CWD)
		if !withinSafe(abs, tc.RepoRoot, nil) {
			return &policy.Verdict{Decision: policy.Ask, RuleID: "P5.out-of-repo",
				Reason: "write target is outside the repo/worktree root: " + p}
		}
	}
	return nil
}

func matchesAnyGlob(p string, globs []string) bool {
	p = path.Clean(filepath.ToSlash(strings.TrimPrefix(p, "./")))
	base := path.Base(p)
	for _, g := range globs {
		if ok, _ := doublestar.Match(g, p); ok {
			return true
		}
		if ok, _ := doublestar.Match(g, base); ok {
			return true
		}
	}
	return false
}

func checkSymlinkEscape(cand string, tc ToolCall) *policy.Verdict {
	if tc.RepoRoot == "" || filepath.IsAbs(cand) && !strings.HasPrefix(filepath.Clean(cand), filepath.Clean(tc.RepoRoot)) {
		// only guard paths that claim to be inside the repo
		if !strings.HasPrefix(filepath.Clean(cand), filepath.Clean(tc.RepoRoot)) {
			return nil
		}
	}
	abs := cand
	if !filepath.IsAbs(abs) {
		abs = filepath.Join(tc.CWD, cand)
	}
	if !strings.HasPrefix(filepath.Clean(abs), filepath.Clean(tc.RepoRoot)+string(filepath.Separator)) {
		return nil
	}
	resolved, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return nil // nonexistent target: nothing to resolve yet
	}
	root := filepath.Clean(tc.RepoRoot) + string(filepath.Separator)
	if !strings.HasPrefix(filepath.Clean(resolved)+string(filepath.Separator), root) {
		return &policy.Verdict{Decision: policy.Deny, RuleID: "P4.symlink-escape",
			Reason: "a path inside the repo resolves outside it via symlink: " + cand}
	}
	return nil
}
