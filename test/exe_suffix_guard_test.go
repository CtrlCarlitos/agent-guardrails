package test

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// appendsExeSuffix matches a test spelling the Windows executable suffix by
// hand: `name += ".exe"`, `name = name + ".exe"`, or a literal concatenation.
var appendsExeSuffix = regexp.MustCompile(`\+=?\s*"\.exe"`)

// exeSuffixExempt names files allowed to spell the suffix themselves, with the
// reason. Each entry is a decision someone has to write down; forgetting one
// still fails.
var exeSuffixExempt = map[string]string{
	// The updater names a *release asset*, not a test fixture it then runs.
	// That name is part of the published artifact contract and is not the
	// host's executable-naming rule, so it does not belong to the helper.
	"cmd/guardrail/update_test.go": "asserts the release asset name the updater downloads, not a local executable fixture",
}

// A test that builds or copies a helper binary and then runs it has to spell
// the name the way the host requires, and `go build -o` does not do it for
// you: Go writes exactly the name given, so an extensionless file on Windows
// exists and cannot be executed. The error says `executable file not found in
// %PATH%` even for an absolute path that is right there, which reads as an
// environment fault rather than a missing suffix -- which is why the
// adversarial corpus went years without running on Windows at all (#198).
//
// internal/testenv.ExecutableName is the one place that rule lives. This guard
// exists because the failure mode is not a compile error and not an obviously
// wrong assertion: a fourth hand-rolled copy would work on the author's
// machine and silently skip or misbehave on the other platform. Three copies
// had already accumulated before this was consolidated.
func TestNoTestRollsItsOwnExecutableSuffix(t *testing.T) {
	root := ".."
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			// A concurrent package's temp directory can vanish mid-walk; the
			// suite runs packages in parallel.
			if os.IsNotExist(err) {
				return nil
			}
			return err
		}
		if info.IsDir() {
			if name := info.Name(); name == ".git" || name == ".worktrees" || name == "graft" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, "_test.go") {
			return nil
		}
		rel := filepath.ToSlash(strings.TrimPrefix(filepath.ToSlash(path), "../"))
		// The helper's own tests must be able to name the suffix.
		if strings.HasPrefix(rel, "internal/testenv/") {
			return nil
		}
		// A _windows_test.go file is already single-platform by construction.
		if strings.HasSuffix(rel, "_windows_test.go") {
			return nil
		}
		if reason, ok := exeSuffixExempt[rel]; ok {
			t.Logf("exempt: %s — %s", rel, reason)
			return nil
		}
		source, readErr := os.ReadFile(path)
		if readErr != nil {
			if os.IsNotExist(readErr) {
				return nil
			}
			return readErr
		}
		for i, line := range strings.Split(string(source), "\n") {
			// Match code, not prose: this guard's own doc comment names the
			// pattern it looks for, and so would any future explanation of it.
			if comment := strings.Index(line, "//"); comment >= 0 {
				line = line[:comment]
			}
			if appendsExeSuffix.MatchString(line) {
				t.Errorf("%s:%d spells the executable suffix by hand: %s\n\tuse testenv.ExecutableName instead, or add an exemption with a reason",
					rel, i+1, strings.TrimSpace(line))
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
}
