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
			}
		}
	}
	return out
}

func checkGitProtectedPaths(tc ToolCall) *policy.Verdict {
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
}

func checkSelfConfig(tc ToolCall) *policy.Verdict {
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
	if isFileTool(tc.Tool) && !strings.EqualFold(tc.Tool, "edit") && !strings.EqualFold(tc.Tool, "write") && !strings.EqualFold(tc.Tool, "multiedit") {
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

func matchesAnyGlob(p string, globs []string) bool {
	p = strings.TrimPrefix(p, "./")
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
