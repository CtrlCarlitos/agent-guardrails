package engine

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
)

func codexManagedWorktreeFixture(t *testing.T) (string, string, string) {
	base := testRepoBase(t)
	repo := filepath.Join(base, "main")
	if err := os.MkdirAll(repo, 0700); err != nil {
		t.Fatal(err)
	}
	initGitRepository(t, repo, false)
	if err := commitInitial(repo); err != nil {
		t.Fatal(err)
	}
	home := filepath.Join(base, ".codex")
	t.Setenv("CODEX_HOME", home)
	linked := filepath.Join(home, "worktrees", "7a7e", "takumi-dream")
	if err := os.MkdirAll(filepath.Dir(linked), 0700); err != nil {
		t.Fatal(err)
	}
	if err := addDetachedWorktree(repo, linked); err != nil {
		t.Fatal(err)
	}
	return repo, home, linked
}

func TestWindowsCodexManagedWorktreeSourceIsNotSelfConfig(t *testing.T) {
	repo, _, linked := codexManagedWorktreeFixture(t)
	target := filepath.Join(linked, "takumi-project-tracker", "SPEC.md")
	for _, root := range []string{linked, repo} {
		tc := ToolCall{Plane: "opencode", Tool: "Write", Paths: []string{target}, CWD: root, RepoRoot: root}
		if v := Evaluate(tc, pathPol()); v.Decision != policy.Allow {
			t.Fatalf("ordinary managed-worktree source from %q = %+v, want allow", root, v)
		}
	}
}
