package engine

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
)

func TestWindowsCodexManagedWorktreeExcludesUnrelatedAndRepoConfig(t *testing.T) {
	repo, home, linked := codexManagedWorktreeFixture(t)
	t.Run("unrelated repository", func(t *testing.T) {
		other := filepath.Join(filepath.Dir(repo), "other-main")
		if err := os.MkdirAll(other, 0700); err != nil {
			t.Fatal(err)
		}
		initGitRepository(t, other, false)
		if err := commitInitial(other); err != nil {
			t.Fatal(err)
		}
		root := filepath.Join(home, "worktrees", "other", "other-repo")
		if err := os.MkdirAll(filepath.Dir(root), 0700); err != nil {
			t.Fatal(err)
		}
		if err := addDetachedWorktree(other, root); err != nil {
			t.Fatal(err)
		}
		tc := ToolCall{Tool: "Write", Paths: []string{filepath.Join(root, "source.go")}, CWD: linked, RepoRoot: linked}
		if v := Evaluate(tc, pathPol()); v.Decision != policy.Deny || v.RuleID != "P5.self-config" {
			t.Fatalf("unrelated source=%+v", v)
		}
	})
	t.Run("real linked worktree inside repository config", func(t *testing.T) {
		root := filepath.Join(repo, ".codex", "worktrees", "nested", "repo")
		if err := os.MkdirAll(filepath.Dir(root), 0700); err != nil {
			t.Fatal(err)
		}
		if err := addDetachedWorktree(repo, root); err != nil {
			t.Fatal(err)
		}
		tc := ToolCall{Tool: "Write", Paths: []string{filepath.Join(root, "source.go")}, CWD: root, RepoRoot: root}
		if v := Evaluate(tc, pathPol()); v.Decision != policy.Deny || v.RuleID != "P5.self-config" {
			t.Fatalf("repo config layout=%+v", v)
		}
	})
	t.Run("default user Codex home", func(t *testing.T) {
		t.Setenv("CODEX_HOME", "")
		nf17SetHome(t, filepath.Dir(home))
		tc := ToolCall{Tool: "Write", Paths: []string{"component/SPEC.md"}, CWD: linked, RepoRoot: linked}
		if v := Evaluate(tc, pathPol()); v.Decision != policy.Allow {
			t.Fatalf("default-home source=%+v", v)
		}
		tc.Paths = []string{filepath.Join(home, "config.toml")}
		if v := Evaluate(tc, pathPol()); v.Decision != policy.Deny || v.RuleID != "P5.self-config" {
			t.Fatalf("default-home config=%+v", v)
		}
	})
}
