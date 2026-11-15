package engine

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
)

func TestWindowsCodexManagedWorktreeKeepsProtectionBoundaries(t *testing.T) {
	repo, home, linked := codexManagedWorktreeFixture(t)
	cases := []struct {
		path     string
		decision policy.Decision
		rule     string
	}{
		{filepath.Join(home, "config.toml"), policy.Deny, "P5.self-config"},
		{filepath.Join(home, "hooks.json"), policy.Deny, "P5.self-config"},
		{filepath.Join(home, "sessions", "s.jsonl"), policy.Deny, "P5.self-config"},
		{filepath.Join(repo, ".codex", "config.toml"), policy.Deny, "P5.self-config"},
		{filepath.Join(linked, ".codex", "config.toml"), policy.Deny, "P5.self-config"},
		{filepath.Join(linked, "AGENTS.md"), policy.Deny, "P5.self-config"},
		{filepath.Join(linked, "CLAUDE.md"), policy.Deny, "P5.self-config"},
		{filepath.Join(linked, ".mcp.json"), policy.Deny, "P5.self-config"},
		{filepath.Join(linked, "guardrail.toml"), policy.Deny, "P5.self-config"},
		{filepath.Join(linked, ".claude", "settings.json"), policy.Deny, "P5.self-config"},
		{filepath.Join(linked, ".git"), policy.Deny, "P5.self-config"},
		{filepath.Join(linked, ".git", "HEAD"), policy.Deny, "P5.self-config"},
		{filepath.Join(linked, ".git", "config"), policy.Deny, "P2.git-protected-path"},
		{filepath.Join(linked, ".env"), policy.Deny, "P4.secret-path"},
		{filepath.Join(linked, ".github", "workflows", "ci.yml"), policy.Ask, "P5.ci-infra-lockfile"},
		{filepath.Join(linked, "Makefile"), policy.Ask, "P5.ci-infra-lockfile"},
	}
	for _, root := range []string{repo, linked} {
		for _, c := range cases {
			t.Run(root+"/"+c.path, func(t *testing.T) {
				tc := ToolCall{Plane: "opencode", Tool: "Write", Paths: []string{c.path}, CWD: root, RepoRoot: root}
				if v := Evaluate(tc, pathPol()); v.Decision != c.decision || v.RuleID != c.rule {
					t.Fatalf("verdict=%+v, want %s/%s", v, c.decision, c.rule)
				}
			})
		}
	}
	target := filepath.Join(linked, "component", "SPEC.md")
	for _, tool := range []string{"Write", "Edit", "MultiEdit", "Bash"} {
		tc := ToolCall{Plane: "opencode", Tool: tool, Paths: []string{target}, CWD: linked, RepoRoot: linked}
		if tool == "Bash" {
			tc.Paths = nil
			tc.Command = fmt.Sprintf("printf x > %q", target)
		}
		if v := Evaluate(tc, pathPol()); v.Decision != policy.Allow {
			t.Fatalf("%s ordinary source = %+v", tool, v)
		}
	}
	t.Run("fake pointer to real worktree bookkeeping", func(t *testing.T) {
		fake := filepath.Join(home, "worktrees", "fake", "repo")
		if err := os.MkdirAll(fake, 0700); err != nil {
			t.Fatal(err)
		}
		gitDir, ok := discoverGitDirectory(linked)
		if !ok {
			t.Fatal("missing real git directory")
		}
		if err := os.WriteFile(filepath.Join(fake, ".git"), []byte("gitdir: "+gitDir+"\n"), 0600); err != nil {
			t.Fatal(err)
		}
		tc := ToolCall{Tool: "Write", Paths: []string{filepath.Join(fake, "source.go")}, CWD: repo, RepoRoot: repo}
		if v := Evaluate(tc, pathPol()); v.Decision != policy.Deny || v.RuleID != "P5.self-config" {
			t.Fatalf("forged bookkeeping=%+v", v)
		}
	})
	t.Run("plain worktree-shaped folder", func(t *testing.T) {
		target := filepath.Join(home, "worktrees", "plain", "repo", "source.go")
		tc := ToolCall{Tool: "Write", Paths: []string{target}, CWD: repo, RepoRoot: repo}
		if v := Evaluate(tc, pathPol()); v.Decision != policy.Deny || v.RuleID != "P5.self-config" {
			t.Fatalf("fake layout=%+v", v)
		}
	})
	t.Run("symlink to global configuration", func(t *testing.T) {
		config := filepath.Join(home, "config.toml")
		if err := os.WriteFile(config, []byte("# config"), 0600); err != nil {
			t.Fatal(err)
		}
		alias := filepath.Join(linked, "source-alias")
		if err := os.Symlink(config, alias); err != nil {
			t.Skipf("symlink unavailable: %v", err)
		}
		tc := ToolCall{Tool: "Write", Paths: []string{alias}, CWD: linked, RepoRoot: linked}
		if v := Evaluate(tc, pathPol()); v.Decision != policy.Deny || v.RuleID != "P4.symlink-escape" {
			t.Fatalf("configuration symlink=%+v", v)
		}
	})
}
