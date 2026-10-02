package recipe

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
	"github.com/CtrlCarlitos/agent-guardrails/internal/testenv"
)

// #481: the Go session tier (build, test, lint, vulncheck) took 343 s on
// every Claude Stop in this repository, even when the turn changed no Go
// file. A recipe whose files are unchanged since its checks last passed is
// skipped; anything else runs exactly as before.

func sessionRepo(t *testing.T) string {
	t.Helper()
	testenv.SetState(t, t.TempDir())
	root := t.TempDir()
	git(t, root, "init", "-q")
	write(t, root, "go.mod", "module example.test/skip\n")
	write(t, root, "a.go", "package skip\n")
	write(t, root, "README.md", "readme\n")
	git(t, root, "add", ".")
	git(t, root, "-c", "user.name=test", "-c", "user.email=test@example.com", "-c", "commit.gpgsign=false", "commit", "-q", "-m", "init")
	return root
}

func git(t *testing.T, dir string, args ...string) {
	t.Helper()
	if out, err := exec.Command("git", append([]string{"-C", dir}, args...)...).CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
}

func write(t *testing.T, root, name, content string) {
	t.Helper()
	path := filepath.Join(root, name)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// countingRun stubs the tools and counts session commands; fail makes every
// command exit nonzero.
func countingRun(t *testing.T, fail *bool) *int {
	t.Helper()
	oldFind, oldRun := findExecutable, runCommand
	t.Cleanup(func() { findExecutable, runCommand = oldFind, oldRun })
	findExecutable = func(file string) (string, error) { return file, nil }
	n := 0
	runCommand = func(_ string, _ []string) ([]byte, error) {
		n++
		if fail != nil && *fail {
			return []byte("tests failed"), &exec.ExitError{}
		}
		return nil, nil
	}
	return &n
}

func TestSessionChecksSkipWhenNoRecipeFileChangedSinceTheyPassed(t *testing.T) {
	root := sessionRepo(t)
	runs := countingRun(t, nil)
	if v := CheckSession(root, nil); v != nil {
		t.Fatalf("first run: %+v, want pass", v)
	}
	if *runs != 4 {
		t.Fatalf("first run ran %d commands, want the 4 Go session commands", *runs)
	}
	*runs = 0
	v := CheckSession(root, nil)
	if *runs != 0 {
		t.Fatalf("unchanged repo re-ran %d commands", *runs)
	}
	if v == nil || v.Decision != policy.Allow || v.RuleID != "P8.recipe-lint" || !strings.Contains(v.Reason, "skipped") || !strings.Contains(v.Reason, "go") {
		t.Fatalf("unchanged repo: %+v, want an allow saying the go checks were skipped", v)
	}
}

func TestSessionChecksRunAgainWhenARecipeFileChanges(t *testing.T) {
	for name, change := range map[string]func(t *testing.T, root string){
		"edited .go file":   func(t *testing.T, root string) { write(t, root, "a.go", "package skip\n\nvar X = 1\n") },
		"new untracked .go": func(t *testing.T, root string) { write(t, root, "sub/b.go", "package sub\n") },
		"deleted .go file":  func(t *testing.T, root string) { os.Remove(filepath.Join(root, "a.go")) },
		"go.mod changed":    func(t *testing.T, root string) { write(t, root, "go.mod", "module example.test/skip\n\ngo 1.26\n") },
		"go.sum appeared":   func(t *testing.T, root string) { write(t, root, "go.sum", "x v1.0.0 h1:abc=\n") },
		"committed .go change": func(t *testing.T, root string) {
			write(t, root, "a.go", "package skip\n\nvar Y = 2\n")
			git(t, root, "add", ".")
			git(t, root, "-c", "user.name=test", "-c", "user.email=test@example.com", "-c", "commit.gpgsign=false", "commit", "-q", "-m", "go")
		},
	} {
		t.Run(name, func(t *testing.T) {
			root := sessionRepo(t)
			runs := countingRun(t, nil)
			if v := CheckSession(root, nil); v != nil {
				t.Fatalf("first run: %+v", v)
			}
			change(t, root)
			*runs = 0
			if v := CheckSession(root, nil); v != nil {
				t.Fatalf("after change: %+v, want the checks to run and pass", v)
			}
			if *runs != 4 {
				t.Fatalf("after change ran %d commands, want 4", *runs)
			}
		})
	}
}

func TestSessionChecksStaySkippedWhenOnlyOtherFilesChange(t *testing.T) {
	root := sessionRepo(t)
	runs := countingRun(t, nil)
	if v := CheckSession(root, nil); v != nil {
		t.Fatalf("first run: %+v", v)
	}
	write(t, root, "README.md", "changed\n")
	write(t, root, "docs/new.md", "new\n")
	git(t, root, "add", "README.md")
	git(t, root, "-c", "user.name=test", "-c", "user.email=test@example.com", "-c", "commit.gpgsign=false", "commit", "-q", "-m", "docs")
	*runs = 0
	if v := CheckSession(root, nil); v == nil || !strings.Contains(v.Reason, "skipped") || *runs != 0 {
		t.Fatalf("docs-only change: %+v after %d commands, want skipped", v, *runs)
	}
}

// A failure is never recorded, so a red repository keeps being checked.
func TestSessionChecksRerunAfterAFailure(t *testing.T) {
	root := sessionRepo(t)
	fail := true
	runs := countingRun(t, &fail)
	if v := CheckSession(root, nil); v == nil || v.Decision != policy.Deny {
		t.Fatalf("failing run: %+v, want deny", v)
	}
	*runs = 0
	if v := CheckSession(root, nil); v == nil || v.Decision != policy.Deny || *runs == 0 {
		t.Fatalf("second run after a failure: %+v after %d commands, want it to run and deny again", v, *runs)
	}
}

// Without git there is nothing to compare, so the checks run every time.
func TestSessionChecksAlwaysRunWithoutAFingerprint(t *testing.T) {
	testenv.SetState(t, t.TempDir())
	root := t.TempDir()
	write(t, root, "go.mod", "module example.test/nogit\n")
	runs := countingRun(t, nil)
	oldFingerprint := sessionFingerprint
	t.Cleanup(func() { sessionFingerprint = oldFingerprint })
	sessionFingerprint = func(string, Recipe) (string, error) { return "", errors.New("no git") }
	for i := 0; i < 2; i++ {
		*runs = 0
		if v := CheckSession(root, nil); v != nil || *runs != 4 {
			t.Fatalf("run %d: %+v after %d commands, want all 4 every time", i, v, *runs)
		}
	}
}
