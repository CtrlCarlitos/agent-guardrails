package policy

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The hook resolved the repository root by spawning `git rev-parse --show-toplevel`,
// twice per call (adapter parse, then overlay discovery). On Windows a git spawn costs
// ~60 ms, which was ~97 of the ~107 ms the hook took (#460, measured per phase). The
// walk below answers the common cases in-process and returns decided=false for
// everything it cannot answer exactly as git would, so the git fallback keeps
// today's behavior for those.

func initTestRepo(t *testing.T, dir string) {
	t.Helper()
	if err := exec.Command("git", "-C", dir, "init", "-q").Run(); err != nil {
		t.Skipf("git unavailable: %v", err)
	}
}

func requireOwned(t *testing.T, dir string) {
	t.Helper()
	if !ownedByCurrentUser(filepath.Join(dir, ".git")) || !ownedByCurrentUser(dir) {
		t.Skip("temp repository is not owned by the current user (elevated shell?); the walk correctly defers to git")
	}
}

// gitAnswer is the oracle: what git itself prints for cwd.
func gitAnswer(t *testing.T, cwd string, ceilings []string) (string, bool) {
	t.Helper()
	return gitRepoRoot(cwd, ceilings)
}

func samePhysicalPath(t *testing.T, a, b string) bool {
	t.Helper()
	norm := func(p string) string {
		p = filepath.FromSlash(p)
		if r, err := filepath.EvalSymlinks(p); err == nil {
			p = r
		}
		return filepath.Clean(p)
	}
	return strings.EqualFold(norm(a), norm(b))
}

func TestWalkRepoRootMatchesGit(t *testing.T) {
	base := t.TempDir()
	repo := filepath.Join(base, "repo")
	deep := filepath.Join(repo, "a", "b", "c")
	if err := os.MkdirAll(deep, 0o755); err != nil {
		t.Fatal(err)
	}
	initTestRepo(t, repo)
	requireOwned(t, repo)

	for _, cwd := range []string{repo, filepath.Join(repo, "a"), deep} {
		root, found, decided := walkRepoRoot(cwd, []string{base})
		if !decided || !found {
			t.Fatalf("walk(%q) decided=%v found=%v; want a decided hit", cwd, decided, found)
		}
		want, ok := gitAnswer(t, cwd, []string{base})
		if !ok || !samePhysicalPath(t, root, want) {
			t.Fatalf("walk(%q) = %q, git says %q (ok=%v)", cwd, root, want, ok)
		}
		// The string callers compare and print must be git's spelling: forward slashes.
		if strings.Contains(root, `\`) {
			t.Fatalf("walk(%q) = %q; want forward slashes like git", cwd, root)
		}
	}
}

func TestWalkRepoRootNotARepoIsDecided(t *testing.T) {
	base := t.TempDir()
	work := filepath.Join(base, "plain", "dir")
	if err := os.MkdirAll(work, 0o755); err != nil {
		t.Fatal(err)
	}
	// The ceiling keeps a stray repository above the temp dir out of the answer.
	root, found, decided := walkRepoRoot(work, []string{base})
	if !decided || found {
		t.Fatalf("walk(%q) = (%q, found=%v, decided=%v); want decided, not found", work, root, found, decided)
	}
}

func TestWalkRepoRootStopsAtCeiling(t *testing.T) {
	base := t.TempDir()
	initTestRepo(t, base)
	requireOwned(t, base)
	work := filepath.Join(base, "proj", "dynamic")
	if err := os.MkdirAll(work, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, found, decided := walkRepoRoot(work, []string{base}); !decided || found {
		t.Fatalf("walk across the ceiling: found=%v decided=%v; want decided, not found (the /tmp/.git lesson)", found, decided)
	}
	root, found, decided := walkRepoRoot(work, nil)
	if !decided || !found || !samePhysicalPath(t, root, base) {
		t.Fatalf("control without a ceiling: (%q, %v, %v); want the stray root %q", root, found, decided, base)
	}
	// git does not exclude the working directory itself from the search.
	if root, found, decided := walkRepoRoot(base, []string{base}); !decided || !found || !samePhysicalPath(t, root, base) {
		t.Fatalf("cwd == ceiling: (%q, %v, %v); want the repo at cwd itself", root, found, decided)
	}
}

func TestWalkRepoRootDefersToGitWhenItCannotBeExact(t *testing.T) {
	base := t.TempDir()
	repo := filepath.Join(base, "repo")
	if err := os.MkdirAll(repo, 0o755); err != nil {
		t.Fatal(err)
	}
	initTestRepo(t, repo)
	requireOwned(t, repo)

	t.Run("foreign owner", func(t *testing.T) {
		old := ownedByCurrentUser
		ownedByCurrentUser = func(string) bool { return false }
		t.Cleanup(func() { ownedByCurrentUser = old })
		if _, _, decided := walkRepoRoot(repo, []string{base}); decided {
			t.Fatal("a repository this user does not own must go to git (safe.directory semantics), not be trusted by the walk")
		}
	})
	t.Run("git environment overrides", func(t *testing.T) {
		for _, key := range []string{"GIT_DIR", "GIT_WORK_TREE"} {
			t.Setenv(key, filepath.Join(repo, ".git"))
			if _, _, decided := walkRepoRoot(repo, []string{base}); decided {
				t.Fatalf("%s set: the walk must defer to git", key)
			}
			t.Setenv(key, "")
		}
	})
	t.Run("gitfile (worktree or submodule)", func(t *testing.T) {
		wt := filepath.Join(base, "linked")
		if err := os.MkdirAll(wt, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(wt, ".git"), []byte("gitdir: "+filepath.Join(repo, ".git")+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, _, decided := walkRepoRoot(wt, []string{base}); decided {
			t.Fatal("a .git file must go to git")
		}
	})
	t.Run("invalid .git directory", func(t *testing.T) {
		odd := filepath.Join(base, "odd")
		if err := os.MkdirAll(filepath.Join(odd, ".git"), 0o755); err != nil {
			t.Fatal(err)
		}
		if _, _, decided := walkRepoRoot(odd, []string{base}); decided {
			t.Fatal("a .git directory without HEAD/objects/refs must go to git")
		}
	})
	t.Run("inside the git directory", func(t *testing.T) {
		if _, _, decided := walkRepoRoot(filepath.Join(repo, ".git", "refs"), []string{base}); decided {
			t.Fatal("a cwd inside .git must go to git")
		}
	})
}

func TestFindRepoRootSpawnsNoGitWhenTheWalkDecides(t *testing.T) {
	base := t.TempDir()
	repo := filepath.Join(base, "repo")
	if err := os.MkdirAll(repo, 0o755); err != nil {
		t.Fatal(err)
	}
	initTestRepo(t, repo)
	requireOwned(t, repo)

	old := repoRootViaGit
	repoRootViaGit = func(string, []string) (string, bool) {
		t.Fatal("git was spawned although the walk could decide")
		return "", false
	}
	t.Cleanup(func() { repoRootViaGit = old })

	root, ok := findRepoRootWithCeilings(repo, []string{base})
	if !ok || !samePhysicalPath(t, root, repo) {
		t.Fatalf("findRepoRootWithCeilings = (%q, %v); want %q", root, ok, repo)
	}
	// A directory that is not in a repository is also answered without git.
	plain := filepath.Join(base, "plain")
	if err := os.MkdirAll(plain, 0o755); err != nil {
		t.Fatal(err)
	}
	if root, ok := findRepoRootWithCeilings(plain, []string{base}); ok {
		t.Fatalf("not-a-repo answered %q; want none", root)
	}
}

func TestFindRepoRootFallsBackToGit(t *testing.T) {
	base := t.TempDir()
	old, oldOwned := repoRootViaGit, ownedByCurrentUser
	called := 0
	repoRootViaGit = func(cwd string, _ []string) (string, bool) {
		called++
		return "via-git", true
	}
	ownedByCurrentUser = func(string) bool { return false }
	t.Cleanup(func() { repoRootViaGit, ownedByCurrentUser = old, oldOwned })

	repo := filepath.Join(base, "repo")
	if err := os.MkdirAll(repo, 0o755); err != nil {
		t.Fatal(err)
	}
	initTestRepo(t, repo)
	root, ok := findRepoRootWithCeilings(repo, []string{base})
	if !ok || root != "via-git" || called != 1 {
		t.Fatalf("fallback = (%q, %v) after %d git call(s); want the git answer, once", root, ok, called)
	}
	if root, ok := findRepoRootWithCeilings("", nil); ok || root != "" {
		t.Fatal("empty cwd must resolve to nothing")
	}
}
