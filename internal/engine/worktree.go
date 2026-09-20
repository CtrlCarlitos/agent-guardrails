package engine

import (
	"os"
	"path/filepath"
)

// sameRepository reports whether an absolute target path belongs to a git
// worktree of the same repository as repoRoot: both resolve, through git's
// own bookkeeping (.git directory, linked-worktree pointer, commondir), to
// the same common git directory. The one-branch-per-PR worktree discipline
// writes through such siblings — the same repository under the same policy,
// not out-of-repo targets.
//
// Forgery fails closed: a hand-written .git pointer without git's worktree
// bookkeeping (commondir and HEAD inside the pointed git directory) does
// not resolve, and the target stays out-of-repo.
func sameRepository(target, repoRoot string) bool {
	if target == "" || repoRoot == "" {
		return false
	}
	targetCommon, ok := gitCommonDirectory(nil, filepath.Dir(target), nil, true)
	if !ok {
		return false
	}
	rootCommon, ok := gitCommonDirectory(nil, repoRoot, nil, true)
	if !ok {
		return false
	}
	if targetCommon == rootCommon {
		return true
	}
	targetInfo, targetErr := os.Stat(targetCommon)
	rootInfo, rootErr := os.Stat(rootCommon)
	return targetErr == nil && rootErr == nil && os.SameFile(targetInfo, rootInfo)
}
