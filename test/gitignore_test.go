package test

import (
	"os/exec"
	"path/filepath"
	"testing"
)

// Plane sessions drop screenshots and scratch state in repo-root
// directories (2026-11-24: 176 PNGs under tmp/). The ignore list is what
// keeps a session's `git add .` from sweeping them into a commit (#724).
func TestGitignoreCoversSessionScratchDirectories(t *testing.T) {
	isolateGitConfig(t)
	repoRoot, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}
	// A trailing slash makes check-ignore read the path as a directory, so
	// directory-only patterns (`/tmp/`) match whether or not it exists yet.
	for _, dir := range []string{"tmp", "graft", ".worktrees", "dist", ".probe-tmp"} {
		cmd := exec.Command("git", "check-ignore", "-q", dir+"/")
		cmd.Dir = repoRoot
		if err := cmd.Run(); err != nil {
			t.Errorf("repo-root %s/ is not ignored; a session scratch sweep (git add .) would commit it", dir)
		}
	}
}
