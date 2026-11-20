package test

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func runGit(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v in %s: %v\n%s", args, dir, err, out)
	}
	return string(out)
}

func runWorktreeCleanScript(t *testing.T, repoDir string, extraArgs ...string) (string, error) {
	t.Helper()
	repoRoot, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		script := filepath.Join(repoRoot, "scripts", "worktree-clean.ps1")
		args := []string{"-NoProfile", "-File", script, "-Base", "main"}
		for _, a := range extraArgs {
			switch a {
			case "--dry-run":
				args = append(args, "-DryRun")
			case "--force":
				args = append(args, "-Force")
			case "--prune-orphans":
				args = append(args, "-PruneOrphans")
			default:
				args = append(args, a)
			}
		}
		cmd = exec.Command("pwsh", args...)
	} else {
		script := filepath.Join(repoRoot, "scripts", "worktree-clean.sh")
		args := append([]string{script, "--base", "main"}, extraArgs...)
		cmd = exec.Command("bash", args...)
	}
	cmd.Dir = repoDir
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func TestWindowsAndPOSIXWorktreeCleanScript(t *testing.T) {
	base := t.TempDir()
	repo := filepath.Join(base, "repo")
	if err := os.MkdirAll(repo, 0o700); err != nil {
		t.Fatal(err)
	}
	runGit(t, repo, "init", "-q", "-b", "main")
	runGit(t, repo, "config", "user.email", "test@example.com")
	runGit(t, repo, "config", "user.name", "Test User")
	if err := os.WriteFile(filepath.Join(repo, "README.md"), []byte("hello\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	runGit(t, repo, "add", "README.md")
	runGit(t, repo, "commit", "-q", "-m", "init")

	mergedWT := filepath.Join(repo, ".worktrees", "merged-wt")
	runGit(t, repo, "worktree", "add", "-q", mergedWT, "-b", "feat/merged", "main")

	unmergedWT := filepath.Join(repo, ".worktrees", "unmerged-wt")
	runGit(t, repo, "worktree", "add", "-q", unmergedWT, "-b", "feat/unmerged", "main")
	if err := os.WriteFile(filepath.Join(unmergedWT, "wip.txt"), []byte("wip\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	runGit(t, unmergedWT, "add", "wip.txt")
	runGit(t, unmergedWT, "commit", "-q", "-m", "wip")

	// Simulate a Windows partial-removal remnant: directory present under .worktrees/
	// with files left behind and its .git file already gone.
	orphanDir := filepath.Join(repo, ".worktrees", "partial-orphan")
	if err := os.MkdirAll(orphanDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(orphanDir, "leftover_test.go"), []byte("package leftover\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	wantOperatorCmd := "rm -rf"
	if runtime.GOOS == "windows" {
		wantOperatorCmd = "Remove-Item -Recurse -Force"
	}

	// 1. Dry run reports merged worktree and orphan remnant without mutating anything.
	out, err := runWorktreeCleanScript(t, repo, "--dry-run")
	if err != nil {
		t.Fatalf("--dry-run failed: %v\n%s", err, out)
	}
	if !strings.Contains(out, "merged-wt") {
		t.Fatalf("--dry-run output missing merged-wt:\n%s", out)
	}
	if !strings.Contains(out, "partial-orphan") || !strings.Contains(out, wantOperatorCmd) {
		t.Fatalf("--dry-run output missing partial-orphan or operator command %q:\n%s", wantOperatorCmd, out)
	}
	if _, statErr := os.Stat(mergedWT); statErr != nil {
		t.Fatalf("--dry-run removed merged-wt: %v", statErr)
	}

	// 2. Real run removes merged-wt, preserves unmerged-wt, and reports partial-orphan (exit 1).
	out, err = runWorktreeCleanScript(t, repo)
	if err == nil {
		t.Fatalf("expected non-zero exit when partial-orphan remnant requires operator cleanup; output:\n%s", out)
	}
	if _, statErr := os.Stat(mergedWT); !os.IsNotExist(statErr) {
		t.Fatalf("merged-wt still exists after cleanup (stat=%v)\n%s", statErr, out)
	}
	if _, statErr := os.Stat(unmergedWT); statErr != nil {
		t.Fatalf("unmerged-wt was wrongly removed: %v\n%s", statErr, out)
	}
	if !strings.Contains(out, "partial-orphan") || !strings.Contains(out, wantOperatorCmd) {
		t.Fatalf("output missing partial-orphan guidance %q:\n%s", wantOperatorCmd, out)
	}

	// 3. With --prune-orphans, partial-orphan is removed cleanly (exit 0) and unmerged-wt stays.
	out, err = runWorktreeCleanScript(t, repo, "--prune-orphans")
	if err != nil {
		t.Fatalf("--prune-orphans failed: %v\n%s", err, out)
	}
	if _, statErr := os.Stat(orphanDir); !os.IsNotExist(statErr) {
		t.Fatalf("partial-orphan still exists after --prune-orphans (stat=%v)\n%s", statErr, out)
	}
	if _, statErr := os.Stat(unmergedWT); statErr != nil {
		t.Fatalf("unmerged-wt was wrongly removed by --prune-orphans: %v\n%s", statErr, out)
	}
}
