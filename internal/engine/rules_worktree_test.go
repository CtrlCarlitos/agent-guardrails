package engine

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// testRepoBase returns a non-temp directory for real git fixtures: targets
// under a system temp root are authorized at the temp write seam by design,
// so out-of-repo verdicts can only be observed from outside it. The fixtures
// live beside the test binary's working directory and are removed on exit.
func testRepoBase(t *testing.T) string {
	t.Helper()
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	// Unique per call, and still under the package directory: a fixed name
	// let concurrent runs in one checkout share and delete each other's repo.
	base, err := os.MkdirTemp(cwd, "guardrail-worktree-tests-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(base) })
	return base
}

// addLinkedWorktree commits the initial repository state and creates a real
// linked worktree, returning its root.
func addLinkedWorktree(t *testing.T, repo string) string {
	t.Helper()
	commit := exec.Command("git", "-C", repo, "-c", "user.name=test", "-c", "user.email=test@example.com", "commit", "--allow-empty", "-m", "init")
	if output, err := commit.CombinedOutput(); err != nil {
		t.Fatalf("git commit: %v: %s", err, output)
	}
	linked := filepath.Join(filepath.Dir(repo), "linked")
	worktree := exec.Command("git", "-C", repo, "worktree", "add", "--detach", linked)
	if output, err := worktree.CombinedOutput(); err != nil {
		t.Fatalf("git worktree add: %v: %s", err, output)
	}
	return linked
}

// TestWindowsLinkedWorktreeWriteStaysInRepo pins the one-branch-per-PR
// discipline: a session rooted in the main checkout may write through a
// linked worktree of the same repository — same git directory, same policy.
func TestWindowsLinkedWorktreeWriteStaysInRepo(t *testing.T) {
	base := testRepoBase(t)
	repo := filepath.Join(base, "main")
	if err := os.MkdirAll(repo, 0o700); err != nil {
		t.Fatal(err)
	}
	initGitRepository(t, repo, false)
	linked := addLinkedWorktree(t, repo)
	target := filepath.Join(linked, "note.md")
	if err := os.WriteFile(target, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}

	tc := ToolCall{Plane: "opencode", Tool: "Write", Paths: []string{target}, CWD: repo, RepoRoot: repo}
	if v := checkOutOfRepoWrite(tc); v != nil {
		t.Fatalf("linked-worktree write -> %+v, want no out-of-repo verdict", v)
	}
}

// TestWindowsForgedWorktreePointerStaysOutOfRepo pins fail-closed against a
// forged .git pointer: without git's own worktree bookkeeping (commondir and
// HEAD inside the pointed git directory) the target is not a sibling
// worktree and stays out-of-repo.
func TestWindowsForgedWorktreePointerStaysOutOfRepo(t *testing.T) {
	base := testRepoBase(t)
	repo := filepath.Join(base, "main-forged")
	if err := os.MkdirAll(repo, 0o700); err != nil {
		t.Fatal(err)
	}
	initGitRepository(t, repo, false)
	attacker := filepath.Join(base, "attacker")
	if err := os.MkdirAll(attacker, 0o700); err != nil {
		t.Fatal(err)
	}
	pointer := filepath.Join(repo, ".git", "worktrees", "forged")
	if err := os.WriteFile(filepath.Join(attacker, ".git"), []byte("gitdir: "+pointer+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(attacker, "stolen.md")
	if err := os.WriteFile(target, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}

	tc := ToolCall{Plane: "opencode", Tool: "Write", Paths: []string{target}, CWD: repo, RepoRoot: repo}
	if v := checkOutOfRepoWrite(tc); v == nil || v.RuleID != "P5.out-of-repo" {
		t.Fatalf("forged pointer write -> %+v, want ask/P5.out-of-repo", v)
	}
}

// TestWindowsUnrelatedRepositoryWriteStaysOutOfRepo pins the boundary: a
// genuinely different repository's tree is still out-of-repo.
func TestWindowsUnrelatedRepositoryWriteStaysOutOfRepo(t *testing.T) {
	base := testRepoBase(t)
	repo := filepath.Join(base, "main-unrelated")
	if err := os.MkdirAll(repo, 0o700); err != nil {
		t.Fatal(err)
	}
	initGitRepository(t, repo, false)
	other := filepath.Join(base, "other")
	if err := os.MkdirAll(other, 0o700); err != nil {
		t.Fatal(err)
	}
	initGitRepository(t, other, false)
	target := filepath.Join(other, "note.md")
	if err := os.WriteFile(target, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}

	tc := ToolCall{Plane: "opencode", Tool: "Write", Paths: []string{target}, CWD: repo, RepoRoot: repo}
	if v := checkOutOfRepoWrite(tc); v == nil || v.RuleID != "P5.out-of-repo" {
		t.Fatalf("unrelated-repo write -> %+v, want ask/P5.out-of-repo", v)
	}
}

// Every test that builds a repository takes its own base directory. A shared
// fixed path let two `go test` runs in one checkout (overlapping Stop hooks,
// parallel agents) clobber each other's repositories and each other's cleanup:
// `could not lock config file: File exists`, `cannot lock ref 'HEAD'`.
func TestWindowsRepoBaseIsUniquePerCall(t *testing.T) {
	first := testRepoBase(t)
	second := testRepoBase(t)
	if first == second {
		t.Fatalf("testRepoBase returned %q twice; concurrent runs would share and delete it", first)
	}
	for _, dir := range []string{first, second} {
		if info, err := os.Stat(dir); err != nil || !info.IsDir() {
			t.Errorf("%q was not created: %v", dir, err)
		}
	}
}
