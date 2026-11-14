package engine

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
	"github.com/CtrlCarlitos/agent-guardrails/internal/testenv"
)

// #542: a global core.hooksPath makes every repo on the machine — including
// throwaway tmp-dir fixture repos an agent creates — resolve its hooks
// directory to one shared, real location outside any repository
// (`~/.config/git/hooks` here). An agent writing a "fixture" hook there
// overwrites live machinery, so writes into the directory hooksPath resolves
// to deny exactly like .git/hooks/**.
func writeGitConfig(t *testing.T, body string) {
	t.Helper()
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(home, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".gitconfig"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestGlobalHooksPathWritesDeny(t *testing.T) {
	home := t.TempDir()
	testenv.SetHome(t, home)
	resetGlobalHooksPathCache()
	t.Cleanup(resetGlobalHooksPathCache)
	writeGitConfig(t, "[core]\n\thooksPath = ~/.config/git/hooks\n")

	for _, tc := range []ToolCall{
		{Tool: "Write", Paths: []string{"~/.config/git/hooks/pre-commit"}, RepoRoot: "/repo", CWD: "/repo"},
		{Tool: "Bash", Command: `printf '#!/bin/sh\n' > ~/.config/git/hooks/pre-commit`, RepoRoot: "/repo", CWD: "/repo"},
		{Tool: "Write", Paths: []string{home + "/.config/git/hooks/pre-push"}, RepoRoot: "/repo", CWD: "/repo"},
	} {
		if v := checkPaths(tc, pathPol()); v == nil || v.Decision != policy.Deny || v.RuleID != "P2.git-protected-path" {
			t.Errorf("%+v -> %+v, want deny/P2.git-protected-path", tc, v)
		}
	}
	// Writes next to, not inside, the hooks directory stay untouched by this rule.
	tc := ToolCall{Tool: "Write", Paths: []string{home + "/.config/git/ignore"}, RepoRoot: "/repo", CWD: "/repo"}
	if v := checkPaths(tc, pathPol()); v != nil && v.RuleID == "P2.git-protected-path" {
		t.Errorf("sibling path denied by the hooks rule: %+v", v)
	}
}

func TestAbsoluteHooksPathWritesDeny(t *testing.T) {
	testenv.SetHome(t, t.TempDir())
	resetGlobalHooksPathCache()
	t.Cleanup(resetGlobalHooksPathCache)
	writeGitConfig(t, "[core]\n\thooksPath = /opt/shared-hooks\n")

	tc := ToolCall{Tool: "Write", Paths: []string{"/opt/shared-hooks/pre-commit"}, RepoRoot: "/repo", CWD: "/repo"}
	if v := checkPaths(tc, pathPol()); v == nil || v.RuleID != "P2.git-protected-path" {
		t.Fatalf("-> %+v, want deny/P2.git-protected-path", v)
	}
}

// A repo-local hooksPath pointing outside that repository's own .git is the
// same class: hook code every fetch and commit in that repo will run.
func TestRepoLocalExternalHooksPathWritesDeny(t *testing.T) {
	testenv.SetHome(t, t.TempDir())
	resetGlobalHooksPathCache()
	t.Cleanup(resetGlobalHooksPathCache)
	shared := t.TempDir()
	repo := filepath.Join(t.TempDir(), "repo")
	if err := os.MkdirAll(filepath.Join(repo, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeGitConfig(t, "[user]\n\tname = test\n")
	if err := os.WriteFile(filepath.Join(repo, ".git", "config"), []byte("[core]\n\thooksPath = "+filepath.ToSlash(shared)+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	tc := ToolCall{Tool: "Write", Paths: []string{filepath.Join(shared, "pre-commit")}, RepoRoot: repo, CWD: repo}
	if v := checkPaths(tc, pathPol()); v == nil || v.RuleID != "P2.git-protected-path" {
		t.Fatalf("-> %+v, want deny/P2.git-protected-path", v)
	}
}

// Without any hooksPath configured, git runs hooks from .git/hooks (already
// covered); the config-git/hooks default location must not newly deny.
func TestNoHooksPathLeavesConfigGitHooksAlone(t *testing.T) {
	home := t.TempDir()
	testenv.SetHome(t, home)
	resetGlobalHooksPathCache()
	t.Cleanup(resetGlobalHooksPathCache)
	writeGitConfig(t, "[user]\n\tname = test\n")

	tc := ToolCall{Tool: "Write", Paths: []string{home + "/.config/git/hooks/pre-commit"}, RepoRoot: "/repo", CWD: "/repo"}
	if v := checkPaths(tc, pathPol()); v != nil {
		t.Fatalf("-> %+v, want nil: ~/.config/git/hooks is not special without core.hooksPath", v)
	}
}

// The parser is a strict [core] scanner: other sections, comments and
// quoted values must behave.
func TestGlobalHooksPathParser(t *testing.T) {
	home := t.TempDir()
	testenv.SetHome(t, home)
	resetGlobalHooksPathCache()
	t.Cleanup(resetGlobalHooksPathCache)
	writeGitConfig(t, "# comment\n[user]\n\thooksPath = /should-not-match\n[core]\n  hooksPath = \""+filepath.ToSlash(home)+"/quoted-hooks\"\n")
	if got, ok := resolveGlobalHooksPath(); !ok || got != filepath.Join(home, "quoted-hooks") {
		t.Fatalf("resolveGlobalHooksPath() = %q,%v", got, ok)
	}
	writeGitConfig(t, "[user]\n\tname = x\n")
	resetGlobalHooksPathCache()
	if _, ok := resolveGlobalHooksPath(); ok {
		t.Fatal("hooksPath under a foreign section must not resolve")
	}
}

func TestRepoHooksPathRelativeResolvesAgainstRepoRoot(t *testing.T) {
	testenv.SetHome(t, t.TempDir())
	resetGlobalHooksPathCache()
	t.Cleanup(resetGlobalHooksPathCache)
	base := t.TempDir()
	repo := filepath.Join(base, "repo")
	if err := os.MkdirAll(filepath.Join(repo, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeGitConfig(t, "[user]\n\tname = test\n")
	if err := os.WriteFile(filepath.Join(repo, ".git", "config"), []byte("[core]\n\thooksPath = ../shared-hooks\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(base, "shared-hooks")
	tc := ToolCall{Tool: "Write", Paths: []string{filepath.Join(want, "pre-commit")}, RepoRoot: repo, CWD: repo}
	if v := checkPaths(tc, pathPol()); v == nil || v.RuleID != "P2.git-protected-path" {
		t.Fatalf("-> %+v, want deny/P2.git-protected-path", v)
	}
}
