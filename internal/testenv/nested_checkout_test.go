package testenv

import (
	"os"
	"path/filepath"
	"testing"
)

// A repo-walking guard must not read another checkout's files as this repo's
// source: an agent's worktree under .claude/worktrees tripped two guards on
// every Stop hook for as long as the agent ran (#406).
func TestIsNestedCheckoutSkipsWorktreesAndClonesButNotTheRoot(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, ".git"), []byte("gitdir: x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	worktree := filepath.Join(root, ".claude", "worktrees", "agent-1")
	clone := filepath.Join(root, "vendor-src", "other")
	plain := filepath.Join(root, "internal", "engine")
	for _, d := range []string{worktree, clone, plain} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(worktree, ".git"), []byte("gitdir: y\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(clone, ".git"), 0o700); err != nil {
		t.Fatal(err)
	}
	for path, want := range map[string]bool{
		root:     false,
		worktree: true,
		clone:    true,
		plain:    false,
	} {
		if got := IsNestedCheckout(root, path); got != want {
			t.Errorf("IsNestedCheckout(root, %s) = %v, want %v", path, got, want)
		}
	}
}

// Concrete Windows failure mode (#84, 2026-09-28): a locked file during
// `git worktree remove` leaves a directory under `.claude/worktrees/` or
// `.worktrees/` whose `.git` file has already been deleted. Repo-walking
// guards must still treat those remnants as nested checkouts so they are not
// scanned as this repository's source.
func TestWindowsAndPOSIXIsNestedCheckoutSkipsPartialWorktreesWithoutGit(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, ".git"), 0o700); err != nil {
		t.Fatal(err)
	}
	partialDotWorktrees := filepath.Join(root, ".worktrees", "partial-leftover")
	partialClaude := filepath.Join(root, ".claude", "worktrees", "agent-a17073e7")
	partialNested := filepath.Join(partialClaude, "test")
	claudeDir := filepath.Join(root, ".claude")
	plain := filepath.Join(root, "internal", "engine")
	for _, d := range []string{partialDotWorktrees, partialNested, plain} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}

	cases := []struct {
		name string
		dir  string
		want bool
	}{
		{"root", root, false},
		{"plain source dir", plain, false},
		{"dot-claude parent", claudeDir, false},
		{"dot-worktrees container", filepath.Join(root, ".worktrees"), true},
		{"partial worktree under .worktrees without .git", partialDotWorktrees, true},
		{"dot-claude worktrees container", filepath.Join(root, ".claude", "worktrees"), true},
		{"partial worktree under .claude/worktrees without .git", partialClaude, true},
		{"nested dir inside partial worktree", partialNested, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsNestedCheckout(root, tc.dir); got != tc.want {
				t.Errorf("IsNestedCheckout(%q, %q) = %v, want %v", root, tc.dir, got, tc.want)
			}
		})
	}
}
