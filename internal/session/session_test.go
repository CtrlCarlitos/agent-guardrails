package session

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestTransactionMissingIsZeroState(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	if err := Transaction("nonexistent-session", func(s *State) error {
		if s.SawPrivateRead || s.SawNetworkCall {
			t.Fatalf("want zero state, got %+v", s)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestTransactionRoundTrip(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	if err := Transaction("sess1", func(s *State) error {
		s.SawPrivateRead = true
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := Transaction("sess1", func(got *State) error {
		if !got.SawPrivateRead || got.SawNetworkCall {
			t.Fatalf("got %+v", got)
		}
		if got.UpdatedAt == "" {
			t.Error("UpdatedAt not set")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestTransactionRejectsEmptySessionID(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	called := false
	err := Transaction("", func(*State) error {
		called = true
		return nil
	})
	if err == nil {
		t.Fatal("Transaction(empty) returned nil, want an error")
	}
	if called {
		t.Fatal("Transaction(empty) called the callback")
	}
}

func TestPortableSessionStorageKeys(t *testing.T) {
	base := filepath.Join(t.TempDir(), "state", "nested")
	t.Setenv("XDG_STATE_HOME", base)
	sessionsDir := filepath.Join(base, "guardrail", "sessions")
	if got := Path(""); got != "" {
		t.Fatalf("Path(empty) = %q, want invalid", got)
	}

	ids := []string{
		"session-1",
		"/",
		`\`,
		"..",
		"native:id:with:colons",
		"native\x00id\nwith\tcontrols",
		strings.Repeat("x", 4<<10),
	}
	seen := make(map[string]string)
	for _, id := range ids {
		got := Path(id)
		if filepath.Dir(got) != sessionsDir {
			t.Errorf("Path(%q) escaped session directory: %q", id, got)
			continue
		}
		name := filepath.Base(got)
		key := strings.TrimSuffix(name, ".json")
		if len(key) != 64 || len(name) != 69 || strings.Trim(key, "0123456789abcdef") != "" {
			t.Errorf("Path(%q) filename = %q, want 64 lowercase hex characters plus .json", id, name)
		}
		if again := Path(id); again != got {
			t.Errorf("Path(%q) is not deterministic: %q then %q", id, got, again)
		}
		if previous, duplicate := seen[name]; duplicate {
			t.Errorf("Path(%q) collides with Path(%q): %q", id, previous, name)
		}
		seen[name] = id
	}

	const wantSessionOne = "84097828fc31a8c8d29210df48901a85de7fd013f686b17be77d1be29cb7a98b.json"
	if got := filepath.Base(Path("session-1")); got != wantSessionOne {
		t.Errorf("Path(session-1) filename = %q, want SHA-256 key %q", got, wantSessionOne)
	}
}

func TestPruneRemovesOldSessions(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	if err := Transaction("old", func(*State) error { return nil }); err != nil {
		t.Fatal(err)
	}
	oldPath := Path("old")
	oldTime := time.Now().Add(-48 * time.Hour)
	if err := os.Chtimes(oldPath, oldTime, oldTime); err != nil {
		t.Fatal(err)
	}

	if err := Transaction("new", func(*State) error { return nil }); err != nil {
		t.Fatal(err)
	}

	if _, err := os.Stat(oldPath); !os.IsNotExist(err) {
		t.Error("old session file should have been pruned")
	}
	if _, err := os.Stat(Path("new")); err != nil {
		t.Error("new session file should still exist")
	}
}

func TestConcurrentTransactionsPreserveMonotonicSignals(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	const updates = 100
	start := make(chan struct{})
	errs := make(chan error, updates)
	var wg sync.WaitGroup
	for i := 0; i < updates; i++ {
		wg.Add(1)
		go func(private bool) {
			defer wg.Done()
			<-start
			errs <- Transaction("shared-session", func(s *State) error {
				if private {
					s.SawPrivateRead = true
				} else {
					s.SawNetworkCall = true
				}
				time.Sleep(time.Microsecond)
				return nil
			})
		}(i%2 == 0)
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent Transaction: %v", err)
		}
	}

	if err := Transaction("shared-session", func(s *State) error {
		if !s.SawPrivateRead || !s.SawNetworkCall {
			t.Fatalf("concurrent updates lost a monotonic signal: %+v", s)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestTransactionSerializesAcrossProcessesAndRecoversAfterCrash(t *testing.T) {
	const sessionID = "cross-process-session"
	if os.Getenv("GUARDRAIL_TEST_HOLD_TRANSACTION") == "1" {
		err := Transaction(sessionID, func(s *State) error {
			s.SawNetworkCall = true
			if err := os.WriteFile(os.Getenv("GUARDRAIL_TEST_LOCK_MARKER"), []byte("locked"), 0o600); err != nil {
				return err
			}
			var release [1]byte
			_, err := os.Stdin.Read(release[:])
			return err
		})
		if err != nil {
			os.Stderr.WriteString(err.Error())
			os.Exit(3)
		}
		os.Exit(4)
	}

	stateHome := t.TempDir()
	t.Setenv("XDG_STATE_HOME", stateHome)
	if err := Transaction(sessionID, func(s *State) error {
		s.SawPrivateRead = true
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(t.TempDir(), "lock-acquired")
	cmd := exec.Command(os.Args[0], "-test.run=^TestTransactionSerializesAcrossProcessesAndRecoversAfterCrash$")
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	var childErr strings.Builder
	cmd.Stderr = &childErr
	cmd.Env = append(os.Environ(),
		"GUARDRAIL_TEST_HOLD_TRANSACTION=1",
		"GUARDRAIL_TEST_LOCK_MARKER="+marker,
		"XDG_STATE_HOME="+stateHome,
	)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	waited := false
	t.Cleanup(func() {
		stdin.Close()
		if !waited {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
	})
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := os.Stat(marker); err == nil {
			break
		} else if !os.IsNotExist(err) {
			t.Fatal(err)
		}
		if time.Now().After(deadline) {
			t.Fatalf("subprocess did not acquire transaction lock; stderr=%s", childErr.String())
		}
		time.Sleep(10 * time.Millisecond)
	}

	callbackCalled := false
	started := time.Now()
	err = Transaction(sessionID, func(s *State) error {
		callbackCalled = true
		s.SawNetworkCall = true
		return nil
	})
	if callbackCalled {
		t.Error("contending cross-process Transaction invoked its callback")
	}
	if err == nil {
		t.Error("contending cross-process Transaction returned nil, want bounded acquisition error")
	}
	if elapsed := time.Since(started); elapsed > 4*time.Second {
		t.Errorf("contending cross-process Transaction blocked for %s, want bounded failure", elapsed)
	}
	state := readDurableState(t, sessionID)
	if !state.SawPrivateRead || state.SawNetworkCall {
		t.Errorf("failed contender changed durable state while subprocess held lock: %+v", state)
	}

	if err := cmd.Process.Kill(); err != nil {
		t.Fatalf("crash lock-holder subprocess: %v", err)
	}
	if err := cmd.Wait(); err == nil {
		t.Fatal("lock-holder subprocess exited successfully, want forced crash")
	}
	waited = true
	if err := Transaction(sessionID, func(s *State) error {
		if !s.SawPrivateRead || s.SawNetworkCall {
			t.Fatalf("state after lock-holder crash = %+v, want preseeded durable state", s)
		}
		s.SawNetworkCall = true
		return nil
	}); err != nil {
		t.Fatalf("transaction after lock-holder crash: %v", err)
	}
	state = readDurableState(t, sessionID)
	if !state.SawPrivateRead || !state.SawNetworkCall {
		t.Fatalf("post-crash recovery update was not durable: %+v", state)
	}
}

func readDurableState(t *testing.T, sessionID string) State {
	t.Helper()
	raw, err := os.ReadFile(Path(sessionID))
	if err != nil {
		t.Fatal(err)
	}
	var state State
	if err := json.Unmarshal(raw, &state); err != nil {
		t.Fatal(err)
	}
	return state
}
