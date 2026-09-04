package session

import (
	"os"
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
