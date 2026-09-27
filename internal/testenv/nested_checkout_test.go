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
