package test

import (
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
			return err
		}
		if info.IsDir() {
			switch info.Name() {
			case ".git", ".worktrees", "graft", ".serena", "node_modules":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(info.Name(), "_test.go") {
			return nil
		}
		body, err := os.ReadFile(path)
		if err != nil {
			return err
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
	for file, names := range goTestFiles(t) {
		dir := filepath.ToSlash(filepath.Dir(file))
		if runs[dir] {
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
