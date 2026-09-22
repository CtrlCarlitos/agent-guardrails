package test

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// CI's windows job does not run the full suite. It runs a fixed package list
// filtered by a name regex, because the engine's policy semantics are
// POSIX-shell-native and most of the suite fails on a Windows host by design.
//
// The consequence is easy to forget and expensive to learn: a Windows test is
// invisible to the Windows runner unless its name matches that regex AND its
// package is on that list. Both halves have already bitten. Eight PowerShell
// tests written for #111 would have run only on ubuntu and macos until they
// were renamed TestWindowsPowerShell*; `internal/policy` has carried two
// Windows-named tests that the job has never run.
//
// These tests read the workflow itself, so the assertion cannot drift from
// what CI actually does.
func windowsJobCommand(t *testing.T) (packages []string, filter *regexp.Regexp) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", ".github", "workflows", "ci.yml"))
	if err != nil {
		t.Fatalf("cannot read the workflow: %v", err)
	}
	line := ""
	for _, candidate := range strings.Split(string(raw), "\n") {
		candidate = strings.TrimSpace(candidate)
		if strings.HasPrefix(candidate, "run: go test ") && strings.Contains(candidate, "-run ") {
			line = candidate
			break
		}
	}
	if line == "" {
		t.Fatal("no filtered `go test ... -run ...` step found in ci.yml; if the windows job changed shape, this guard needs updating with it")
	}
	pattern := regexp.MustCompile(`-run\s+'([^']+)'`).FindStringSubmatch(line)
	if pattern == nil {
		t.Fatalf("cannot read the -run filter from %q", line)
	}
	filter = regexp.MustCompile(pattern[1])
	for _, field := range strings.Fields(line) {
		if strings.HasPrefix(field, "./") {
			packages = append(packages, strings.TrimSuffix(strings.TrimPrefix(field, "./"), "/"))
		}
	}
	if len(packages) == 0 {
		t.Fatalf("cannot read the package list from %q", line)
	}
	return packages, filter
}

var testFuncPattern = regexp.MustCompile(`(?m)^func (Test[A-Za-z0-9_]*)\s*\(`)

// goTestFiles walks the repo for _test.go files, skipping vendored trees and
// other worktrees.
func goTestFiles(t *testing.T) map[string][]string {
	t.Helper()
	byFile := map[string][]string{}
	root := ".."
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			// `go test ./...` runs every package concurrently, and a sibling
			// package's test can create and remove a tree under the repo while
			// this walk is in flight. A path that vanished between listing and
			// visiting is not a Windows-visibility gap, so it must not fail the
			// guard — this test failed once on ubuntu for exactly that and
			// passed on re-run, which is the worst kind of guard.
			if errors.Is(err, fs.ErrNotExist) {
				return nil
			}
			return err
		}
		if info.IsDir() {
			switch info.Name() {
			case ".git", ".worktrees", "graft", ".serena", "node_modules", ".winpipe-stage":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(info.Name(), "_test.go") {
			return nil
		}
		body, err := os.ReadFile(path)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return nil // same race, one step later
			}
			return err
		}
		if !buildsOnWindows(info.Name(), string(body)) {
			// A file the Windows build never compiles cannot be invisible to
			// the Windows job; it is absent by construction, not by accident.
			return nil
		}
		var names []string
		for _, m := range testFuncPattern.FindAllStringSubmatch(string(body), -1) {
			names = append(names, m[1])
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		byFile[filepath.ToSlash(rel)] = names
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(byFile) == 0 {
		t.Fatal("found no _test.go files; the walk root is wrong")
	}
	return byFile
}

// A test file named for Windows that contributes no test the windows job
// selects is a file nobody runs on Windows. It reads as coverage and is not.
func TestWindowsNamedTestFilesAreSelectedByTheWindowsJob(t *testing.T) {
	_, filter := windowsJobCommand(t)
	checked := 0
	for file, names := range goTestFiles(t) {
		base := strings.ToLower(filepath.Base(file))
		if !strings.Contains(base, "win") {
			continue
		}
		checked++
		selected := false
		for _, name := range names {
			if filter.MatchString(name) {
				selected = true
				break
			}
		}
		if !selected {
			t.Errorf("%s is named for Windows but declares no test matching CI's filter %q; on windows-latest nothing in it runs", file, filter)
		}
	}
	if checked == 0 {
		t.Fatal("no Windows-named test files found; the filename heuristic stopped matching and this guard is asleep")
	}
}

// The other half: a correctly named test in a package the job does not list is
// just as invisible. This is the check that catches internal/policy.
func TestWindowsSelectedTestsLiveInPackagesTheWindowsJobRuns(t *testing.T) {
	packages, filter := windowsJobCommand(t)
	runs := map[string]bool{}
	for _, p := range packages {
		runs[p] = true
	}
	// Packages deliberately outside the Windows job. The filter has grown
	// generic words — `Egress`, `Allowance` — so it now selects tests that were
	// never Windows tests, and an exemption with a stated reason is more honest
	// than either breaking CI or deleting the check. Adding an entry is a
	// decision someone has to write down; forgetting a package still fails.
	exempt := map[string]string{
		"test/adversarial": "the adversarial corpus uses POSIX-absolute paths that have different semantics on Windows, so the package cannot pass there yet",
	}
	for file, names := range goTestFiles(t) {
		dir := filepath.ToSlash(filepath.Dir(file))
		if runs[dir] {
			continue
		}
		if reason, ok := exempt[dir]; ok {
			t.Logf("exempt: %s — %s", dir, reason)
			continue
		}
		for _, name := range names {
			if filter.MatchString(name) {
				t.Errorf("%s declares %s, which CI's filter %q selects, but package %q is not in the windows job's list — it never runs on windows-latest",
					file, name, filter, dir)
			}
		}
	}
}

func TestWindowsFullSuiteObservabilityJobIsUnfilteredAndNonblocking(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", ".github", "workflows", "ci.yml"))
	if err != nil {
		t.Fatal(err)
	}
	block := workflowJobBlock(string(raw), "windows-portability")
	if block == "" {
		t.Fatal("ci.yml has no windows-portability job")
	}
	for _, want := range []string{
		"\n    runs-on: windows-latest\n",
		"\n    continue-on-error: true\n",
		"\n        run: go test ./...\n",
	} {
		if !strings.Contains(block, want) {
			t.Errorf("windows-portability job does not contain %q:\n%s", want, block)
		}
	}
	if strings.Contains(block, "-run ") {
		t.Errorf("windows-portability job filters test names instead of exposing the full suite:\n%s", block)
	}
}

func workflowJobBlock(workflow, name string) string {
	lines := strings.Split(workflow, "\n")
	start := -1
	for i, line := range lines {
		if line == "  "+name+":" {
			start = i
			break
		}
	}
	if start < 0 {
		return ""
	}
	end := len(lines)
	for i := start + 1; i < len(lines); i++ {
		line := lines[i]
		if strings.HasPrefix(line, "  ") && !strings.HasPrefix(line, "    ") && strings.HasSuffix(line, ":") {
			end = i
			break
		}
	}
	return strings.Join(lines[start:end], "\n")
}

// buildsOnWindows reports whether a test file is compiled into the Windows
// build: both the filename suffix convention and a //go:build line can exclude
// it, and an excluded file is absent by construction rather than overlooked.
func buildsOnWindows(name, body string) bool {
	for _, suffix := range []string{"_unix_test.go", "_linux_test.go", "_darwin_test.go", "_js_test.go"} {
		if strings.HasSuffix(name, suffix) {
			return false
		}
	}
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "//go:build") {
			if line != "" && !strings.HasPrefix(line, "//") {
				break // past the header
			}
			continue
		}
		constraint := strings.TrimSpace(strings.TrimPrefix(line, "//go:build"))
		if strings.Contains(constraint, "!windows") {
			return false
		}
		if strings.Contains(constraint, "windows") {
			return true
		}
		// Some other constraint (linux, unix, cgo): treat as excluded only when
		// it names a different OS exclusively.
		for _, other := range []string{"linux", "darwin", "unix"} {
			if constraint == other {
				return false
			}
		}
	}
	return true
}
