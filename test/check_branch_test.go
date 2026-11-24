package test

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func runCheckBranch(t *testing.T, usePowerShell bool, repoDir string, args ...string) (string, error) {
	t.Helper()
	repoRoot, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}
	var cmd *exec.Cmd
	if usePowerShell {
		script := filepath.Join(repoRoot, "scripts", "check-branch.ps1")
		pwshArgs := append([]string{"-NoProfile", "-File", script}, args...)
		cmd = exec.Command("pwsh", pwshArgs...)
	} else {
		script := filepath.Join(repoRoot, "scripts", "check-branch.sh")
		shArgs := append([]string{script}, args...)
		cmd = exec.Command("bash", shArgs...)
	}
	cmd.Dir = repoDir
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func TestWindowsAndPOSIXCheckBranchScript(t *testing.T) {
	isolateGitConfig(t)
	type runner struct {
		name      string
		ps        bool
		baseFlags func(base string) []string
	}
	var runners []runner
	if runtime.GOOS == "windows" {
		runners = append(runners, runner{
			name:      "powershell",
			ps:        true,
			baseFlags: func(base string) []string { return []string{"-Base", base} },
		})
	} else {
		runners = append(runners, runner{
			name:      "bash",
			ps:        false,
			baseFlags: func(base string) []string { return []string{"--base", base} },
		})
		if _, err := exec.LookPath("pwsh"); err == nil {
			runners = append(runners, runner{
				name:      "powershell",
				ps:        true,
				baseFlags: func(base string) []string { return []string{"-Base", base} },
			})
		}
	}

	for _, r := range runners {
		t.Run(r.name, func(t *testing.T) {
			runCheck := func(repoDir, base string, extra ...string) (string, error) {
				args := append(r.baseFlags(base), extra...)
				return runCheckBranch(t, r.ps, repoDir, args...)
			}

			repo := filepath.Join(t.TempDir(), "repo")
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

			// 1. Base branch itself passes.
			if out, err := runCheck(repo, "main"); err != nil {
				t.Fatalf("main branch should pass: %v\n%s", err, out)
			}

			// 2. Fresh feature branch with unmerged work passes (including when invoked as pre-push hook with remote/url args).
			runGit(t, repo, "checkout", "-q", "-b", "feat/fresh")
			if err := os.WriteFile(filepath.Join(repo, "fresh.txt"), []byte("new work\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			runGit(t, repo, "add", "fresh.txt")
			runGit(t, repo, "commit", "-q", "-m", "feat: fresh work")
			if out, err := runCheck(repo, "main"); err != nil {
				t.Fatalf("fresh feature branch should pass: %v\n%s", err, out)
			}
			if out, err := runCheckBranch(t, r.ps, repo, "origin", "https://example.com/repo.git"); err != nil {
				t.Fatalf("pre-push hook invocation on fresh branch should pass: %v\n%s", err, out)
			}

			// 3. Branch already ancestor of main fails with fresh-branch guidance.
			runGit(t, repo, "checkout", "-q", "main")
			runGit(t, repo, "checkout", "-q", "-b", "feat/already-merged")
			if out, err := runCheck(repo, "main"); err == nil {
				t.Fatalf("already-merged branch should fail, got:\n%s", out)
			} else if !strings.Contains(out, "git checkout -b") {
				t.Fatalf("output missing fresh-branch command:\n%s", out)
			}

			// 4. Multi-commit branch squash-merged onto main (different SHA) fails.
			runGit(t, repo, "checkout", "-q", "main")
			runGit(t, repo, "checkout", "-q", "-b", "feat/squashed")
			if err := os.WriteFile(filepath.Join(repo, "a.txt"), []byte("part 1\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			runGit(t, repo, "add", "a.txt")
			runGit(t, repo, "commit", "-q", "-m", "part 1")
			if err := os.WriteFile(filepath.Join(repo, "b.txt"), []byte("part 2\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			runGit(t, repo, "add", "b.txt")
			runGit(t, repo, "commit", "-q", "-m", "part 2")

			runGit(t, repo, "checkout", "-q", "main")
			runGit(t, repo, "merge", "-q", "--squash", "feat/squashed")
			runGit(t, repo, "commit", "-q", "-m", "feat: squashed (#1)")

			runGit(t, repo, "checkout", "-q", "feat/squashed")
			if out, err := runCheck(repo, "main"); err == nil {
				t.Fatalf("squash-merged branch should fail, got:\n%s", out)
			} else if !strings.Contains(out, "git checkout -b") {
				t.Fatalf("squash-merged output missing fresh-branch command:\n%s", out)
			}

			// 5. Adding a follow-up commit onto that multi-commit squash-merged branch also fails with cherry-pick guidance.
			if err := os.WriteFile(filepath.Join(repo, "followup.txt"), []byte("extra work\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			runGit(t, repo, "add", "followup.txt")
			runGit(t, repo, "commit", "-q", "-m", "feat: accidental follow-up on multi-commit squashed branch")
			if out, err := runCheck(repo, "main"); err == nil {
				t.Fatalf("follow-up commit on multi-commit squash-merged branch should fail, got:\n%s", out)
			} else if !strings.Contains(out, "git checkout -b") || !strings.Contains(out, "cherry-pick") {
				t.Fatalf("multi-commit follow-up output missing checkout/cherry-pick guidance:\n%s", out)
			}

			// 6. Adding a new commit onto a single-commit squash-merged branch also fails with cherry-pick guidance.
			runGit(t, repo, "checkout", "-q", "main")
			runGit(t, repo, "checkout", "-q", "-b", "feat/trapped")
			if err := os.WriteFile(filepath.Join(repo, "c.txt"), []byte("merged commit\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			runGit(t, repo, "add", "c.txt")
			runGit(t, repo, "commit", "-q", "-m", "feat: merged commit")

			runGit(t, repo, "checkout", "-q", "main")
			runGit(t, repo, "merge", "-q", "--squash", "feat/trapped")
			runGit(t, repo, "commit", "-q", "-m", "feat: merged commit (#2)")

			runGit(t, repo, "checkout", "-q", "feat/trapped")
			if err := os.WriteFile(filepath.Join(repo, "d.txt"), []byte("accidental follow-up\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			runGit(t, repo, "add", "d.txt")
			runGit(t, repo, "commit", "-q", "-m", "feat: accidental follow-up on stale branch")

			if out, err := runCheck(repo, "main"); err == nil {
				t.Fatalf("new commit on squash-merged branch should fail, got:\n%s", out)
			} else if !strings.Contains(out, "git checkout -b") || !strings.Contains(out, "cherry-pick") {
				t.Fatalf("trapped-branch output missing checkout/cherry-pick guidance:\n%s", out)
			}
		})
	}
}
