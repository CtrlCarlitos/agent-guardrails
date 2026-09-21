//go:build !windows

package main

import (
	"os"
	"testing"
)

// widenArtifactForTest is the Unix no-op: directory mode bits already carry
// the unsafe shape the tests construct.
func widenArtifactForTest(path string) error { return nil }

// assertJournalDirPrivate is the Unix half of the repair-or-reject
// invariant: ensureAllowanceDir has no repair path here, so a directory the
// grant wrote into must carry the 0700 mode bits the MkdirAll established.
func assertJournalDirPrivate(t *testing.T, path string) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("journal directory: %v", err)
	}
	if info.Mode().Perm() != 0o700 {
		t.Fatalf("journal directory mode = %v, want 0700", info.Mode())
	}
}
