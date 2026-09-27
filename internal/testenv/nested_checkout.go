package testenv

import (
	"os"
	"path/filepath"
)

// IsNestedCheckout reports whether dir, found while walking the repository
// rooted at root, is a separate git checkout: a linked worktree (its .git is a
// file) or a clone (its .git is a directory). Repo-walking guard tests skip
// such a directory, since its files are another checkout's source, not this
// repository's (#406). The root itself is never nested.
func IsNestedCheckout(root, dir string) bool {
	if filepath.Clean(root) == filepath.Clean(dir) {
		return false
	}
	_, err := os.Lstat(filepath.Join(dir, ".git"))
	return err == nil
}
