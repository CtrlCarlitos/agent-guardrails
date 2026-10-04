package policy

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// Test seams. Production code never reassigns them.
var (
	ownedByCurrentUser = ownedByCurrentUserOS
	repoRootViaGit     = gitRepoRoot
)

// findRepoRootWithCeilings resolves the repository enclosing cwd, honoring the
// discovery ceilings (see gitRepoRoot).
//
// It used to spawn `git rev-parse --show-toplevel` on every call, twice per hook
// (adapter parse, then overlay discovery). On Windows one git spawn is ~60 ms, which
// was ~97 of the ~107 ms a hook took (measured per phase, #460). walkRepoRoot now
// answers the common cases with a few stats; anything it cannot answer exactly as git
// would (decided=false) still goes to git, so those keep today's behavior.
func findRepoRootWithCeilings(cwd string, ceilings []string) (string, bool) {
	if cwd == "" {
		return "", false
	}
	if root, found, decided := walkRepoRoot(cwd, ceilings); decided {
		return root, found
	}
	return repoRootViaGit(cwd, ceilings)
}

// walkRepoRoot finds the nearest ancestor of cwd (cwd included) that holds a .git
// directory, the way git's discovery does, and reports decided=true only when the
// answer is certain:
//
//   - found, decided: a valid .git directory, owned by this user, in a directory this
//     user owns. A repository owned by someone else is NOT trusted here: git refuses it
//     ("dubious ownership") unless safe.directory says otherwise, and the root decides
//     which guardrail.toml overlay is loaded, so that case goes to git.
//   - not found, decided: no .git entry from cwd up to the filesystem root, a ceiling
//     or a mount boundary (git's own stop conditions).
//   - undecided: GIT_* discovery overrides are set, the path or an entry is unusual
//     (a .git file for a worktree or submodule, an invalid .git directory, cwd inside a
//     .git directory), or anything could not be read.
//
// The returned root uses git's spelling: symlinks resolved, forward slashes.
func walkRepoRoot(cwd string, ceilings []string) (root string, found, decided bool) {
	for _, key := range []string{"GIT_DIR", "GIT_WORK_TREE", "GIT_COMMON_DIR", "GIT_INDEX_FILE", "GIT_DISCOVERY_ACROSS_FILESYSTEM"} {
		if os.Getenv(key) != "" {
			return "", false, false
		}
	}
	abs, err := filepath.Abs(cwd)
	if err != nil {
		return "", false, false
	}
	real, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return "", false, false
	}
	if hasGitComponent(real) {
		return "", false, false
	}
	stops := ceilingStops(real, ceilings)
	startDev, devOK := deviceID(real)

	dir := real
	for {
		gitPath := filepath.Join(dir, ".git")
		fi, err := os.Lstat(gitPath)
		switch {
		case err == nil && fi.IsDir():
			if !looksLikeGitDir(gitPath) || !ownedByCurrentUser(gitPath) || !ownedByCurrentUser(dir) {
				return "", false, false
			}
			return filepath.ToSlash(dir), true, true
		case err == nil:
			return "", false, false
		case !os.IsNotExist(err):
			return "", false, false
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", false, true
		}
		if stops[foldCase(parent)] {
			return "", false, true
		}
		if devOK {
			if d, ok := deviceID(parent); ok && d != startDev {
				return "", false, true
			}
		}
		dir = parent
	}
}

// looksLikeGitDir is the minimum git itself requires of a git directory.
func looksLikeGitDir(dir string) bool {
	if fi, err := os.Stat(filepath.Join(dir, "HEAD")); err != nil || fi.IsDir() {
		return false
	}
	for _, name := range []string{"objects", "refs"} {
		if fi, err := os.Stat(filepath.Join(dir, name)); err != nil || !fi.IsDir() {
			return false
		}
	}
	return true
}

func hasGitComponent(path string) bool {
	for _, part := range strings.Split(filepath.ToSlash(path), "/") {
		if foldCase(part) == ".git" {
			return true
		}
	}
	return false
}

// ceilingStops returns the resolved ceiling directories that are proper ancestors of
// real. git does not chdir up into a ceiling directory while looking for a repository,
// and it never excludes the working directory itself.
func ceilingStops(real string, ceilings []string) map[string]bool {
	stops := map[string]bool{}
	for _, c := range ceilings {
		if c == "" {
			continue
		}
		resolved := filepath.Clean(c)
		if r, err := filepath.EvalSymlinks(resolved); err == nil {
			resolved = r
		}
		key := foldCase(resolved)
		if strings.HasPrefix(foldCase(real), key+string(filepath.Separator)) {
			stops[key] = true
		}
	}
	return stops
}

// foldCase compares paths the way the platform's filesystem usually does.
func foldCase(s string) string {
	if runtime.GOOS == "windows" {
		return strings.ToLower(s)
	}
	return s
}
