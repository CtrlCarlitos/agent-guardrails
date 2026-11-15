package engine

import (
	"os"
	"path/filepath"
	"strings"
)

var codexSelfConfigGlobs = []string{"**/.codex", "**/.codex/**"}

// The active Codex home holds configuration and managed source worktrees.
// Only the ancestor's Codex match may be removed: configuration inside the
// working tree and every other protection continue to apply (#564).
func matchesCodexSelfConfig(candidate pathCandidate) bool {
	if !matchesScoped(candidate, codexSelfConfigGlobs, nil) {
		return false
	}
	relative, ok := managedCodexSourceRelative(candidate)
	if !ok {
		return true
	}
	return relative == ".git" || strings.HasPrefix(relative, ".git/") ||
		matchesAnyGlob(relative, codexSelfConfigGlobs) || matchesAnyGlob(relative, selfConfigRootOnly)
}

func managedCodexSourceRelative(candidate pathCandidate) (string, bool) {
	home := os.Getenv("CODEX_HOME")
	if home == "" {
		userHome, err := os.UserHomeDir()
		if err != nil {
			return "", false
		}
		home = filepath.Join(userHome, ".codex")
	}
	if !filepath.IsAbs(home) {
		return "", false
	}
	home, ok := resolveExistingPath(home, "")
	if !ok {
		return "", false
	}
	target, ok := resolvePathCandidate(candidate)
	if !ok {
		return "", false
	}
	base := filepath.Join(home, "worktrees")
	rel, err := filepath.Rel(base, target)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", false
	}
	parts := strings.Split(rel, string(filepath.Separator))
	// Layout: worktrees/<slot>/<repository>/<working file>. The working
	// tree root, slot directory and home itself never receive this exemption.
	if len(parts) < 3 {
		return "", false
	}
	root := filepath.Join(base, parts[0], parts[1])
	pointer := filepath.Join(root, ".git")
	info, err := os.Lstat(pointer)
	if err != nil || !info.Mode().IsRegular() {
		return "", false
	}
	gitDir, ok := discoverGitDirectory(root)
	if !ok {
		return "", false
	}
	if common, ok := readSmallFile(filepath.Join(gitDir, "commondir")); !ok || strings.TrimSpace(common) == "" {
		return "", false
	}
	// Git's reverse pointer must identify this exact .git file. Pointing a
	// fake worktree at another checkout's valid bookkeeping is not enough.
	backref, ok := readSmallFile(filepath.Join(gitDir, "gitdir"))
	if !ok {
		return "", false
	}
	backrefInfo, err := os.Stat(resolvePath(strings.TrimSpace(backref), gitDir))
	if err != nil || !os.SameFile(info, backrefInfo) {
		return "", false
	}
	if !sameRepository(target, candidate.repoRoot) {
		return "", false
	}
	return filepath.ToSlash(filepath.Join(parts[2:]...)), true
}
