package session

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoadMissingIsZeroState(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	s, err := Load("nonexistent-session")
	if err != nil {
		t.Fatal(err)
	}
	if s.SawPrivateRead || s.SawNetworkCall {
		t.Fatalf("want zero state, got %+v", s)
	}
}

func TestSaveLoadRoundTrip(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	want := &State{SawPrivateRead: true}
	if err := Save("sess1", want); err != nil {
		t.Fatal(err)
	}
	got, err := Load("sess1")
	if err != nil {
		t.Fatal(err)
	}
	if !got.SawPrivateRead || got.SawNetworkCall {
		t.Fatalf("got %+v", got)
	}
	if got.UpdatedAt == "" {
		t.Error("UpdatedAt not set")
	}
}

func TestEmptySessionIDIsNoOp(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	if err := Save("", &State{SawPrivateRead: true}); err != nil {
		t.Fatal(err)
	}
	s, err := Load("")
	if err != nil || s.SawPrivateRead {
		t.Fatalf("empty session id should no-op, got %+v, err=%v", s, err)
	}
}

func TestPathTraversalSessionIDIsRejected(t *testing.T) {
	root := t.TempDir()
	base := filepath.Join(root, "state", "nested")
	t.Setenv("XDG_STATE_HOME", base)

	const traversalID = "../../../../tmp/pwned"
	sessionsDir := filepath.Join(base, "guardrail", "sessions")
	outside := filepath.Join(sessionsDir, traversalID+".json")
	wantOutside := filepath.Join(root, "tmp", "pwned.json")
	if outside != wantOutside {
		t.Fatalf("invalid traversal fixture: target = %q, want %q", outside, wantOutside)
	}
	if err := os.MkdirAll(filepath.Dir(outside), 0o700); err != nil {
		t.Fatal(err)
	}
	sentinel := []byte("session traversal test sentinel")
	if err := os.WriteFile(outside, sentinel, 0o600); err != nil {
		t.Fatal(err)
	}

	if err := Save(traversalID, &State{SawPrivateRead: true}); err != nil {
		t.Fatalf("Save(exact traversal) should no-op, not error: %v", err)
	}
	if got, err := os.ReadFile(outside); err != nil || string(got) != string(sentinel) {
		t.Errorf("Save(exact traversal) wrote outside the sessions dir: got %q, err=%v", got, err)
	}
	if err := os.WriteFile(outside, []byte(`{"saw_private_read":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(traversalID)
	if err != nil {
		t.Fatalf("Load(exact traversal) should no-op, not error: %v", err)
	}
	if loaded.SawPrivateRead {
		t.Error("Load(exact traversal) read state outside the sessions dir")
	}

	for _, bad := range []string{"a/b", `a\b`, ".", "..", "a..b"} {
		if got := Path(bad); got != "" {
			t.Errorf("Path(%q) = %q, want rejection", bad, got)
		}
		state := &State{SawPrivateRead: true}
		if err := Save(bad, state); err != nil {
			t.Errorf("Save(%q) should no-op, not error: %v", bad, err)
		}
		if state.UpdatedAt != "" {
			t.Errorf("Save(%q) mutated state during no-op", bad)
		}
	}
	if _, err := os.Stat(sessionsDir); !os.IsNotExist(err) {
		t.Errorf("unsafe session IDs created the sessions dir: %v", err)
	}

	for _, good := range []string{"session-1", "session.id"} {
		want := filepath.Join(base, "guardrail", "sessions", good+".json")
		if got := Path(good); got != want {
			t.Errorf("Path(%q) = %q, want %q", good, got, want)
		}
	}
}

func TestPruneRemovesOldSessions(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	Save("old", &State{})
	oldPath := Path("old")
	oldTime := time.Now().Add(-48 * time.Hour)
	os.Chtimes(oldPath, oldTime, oldTime)

	Save("new", &State{}) // triggers a prune sweep as a side effect

	if _, err := os.Stat(oldPath); !os.IsNotExist(err) {
		t.Error("old session file should have been pruned")
	}
	if _, err := os.Stat(Path("new")); err != nil {
		t.Error("new session file should still exist")
	}
}
