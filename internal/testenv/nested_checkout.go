package testenv

import (
	"os"
	"path/filepath"
	"strings"
)

// IsNestedCheckout reports whether dir, found while walking the repository
// rooted at root, is a separate git checkout: a linked worktree (its .git is a
// file), a clone (its .git is a directory), or a directory under `.worktrees/`
// or `.claude/worktrees/` — including partial-removal remnants whose `.git`
// file was already deleted by a failed Windows `git worktree remove` (#406, #84).
// The root itself is never nested.
func IsNestedCheckout(root, dir string) bool {
	cleanRoot := filepath.Clean(root)
	cleanDir := filepath.Clean(dir)
	if cleanRoot == cleanDir {
		return false
	}
	if rel, err := filepath.Rel(cleanRoot, cleanDir); err == nil {
		slash := filepath.ToSlash(rel)
		if slash == ".worktrees" || strings.HasPrefix(slash, ".worktrees/") ||
			slash == ".claude/worktrees" || strings.HasPrefix(slash, ".claude/worktrees/") {
			return true
		}
	}
	_, err := os.Lstat(filepath.Join(cleanDir, ".git"))
	return err == nil
}
