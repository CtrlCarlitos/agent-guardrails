package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestReadCodexKnownSessions(t *testing.T) {
	root := t.TempDir()
	first := time.Date(2026, 9, 20, 8, 0, 0, 0, time.UTC)
	writeCodexRollout(t, root, "first", first)
	writeCodexRollout(t, root, "newest", first.Add(time.Hour))
	writeCodexRollout(t, root, "selftest-ignore", first.Add(2*time.Hour))
	if err := os.WriteFile(filepath.Join(root, "not-a-rollout.jsonl"), []byte("{bad\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	sessions, err := readCodexKnownSessions(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(sessions) != 2 || sessions[0].ID != "newest" || sessions[1].ID != "first" {
		t.Fatalf("sessions = %+v", sessions)
	}
}
