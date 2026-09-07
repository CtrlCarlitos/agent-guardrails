package session

import (
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

func TestTransactionCrashRecovery(t *testing.T) {
	if os.Getenv("GUARDRAIL_TEST_CRASH_TRANSACTION") == "1" {
		marker := os.Getenv("GUARDRAIL_TEST_CRASH_MARKER")
		err := Transaction("crash-session", func(s *State) error {
			s.SawNetworkCall = true
			if err := os.WriteFile(marker, []byte("locked"), 0o600); err != nil {
				return err
			}
			os.Exit(0)
			return nil
		})
		if err != nil {
			os.Exit(3)
		}
		os.Exit(4)
	}

	stateHome := t.TempDir()
	t.Setenv("XDG_STATE_HOME", stateHome)
	if err := Transaction("crash-session", func(s *State) error {
		s.SawPrivateRead = true
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(t.TempDir(), "callback-entered")
	cmd := exec.Command(os.Args[0], "-test.run=^TestTransactionCrashRecovery$")
	cmd.Env = append(os.Environ(),
		"GUARDRAIL_TEST_CRASH_TRANSACTION=1",
		"GUARDRAIL_TEST_CRASH_MARKER="+marker,
		"XDG_STATE_HOME="+stateHome,
	)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("crashing transaction subprocess: %v\n%s", err, output)
	}
	if _, err := os.Stat(marker); err != nil {
		t.Fatalf("subprocess did not exit while holding the transaction: %v", err)
	}

	if err := Transaction("crash-session", func(s *State) error {
		if !s.SawPrivateRead || s.SawNetworkCall {
			t.Fatalf("post-crash state = %+v, want prior durable state only", s)
		}
		s.SawNetworkCall = true
		return nil
	}); err != nil {
		t.Fatalf("transaction after crashed lock holder: %v", err)
	}
	if err := Transaction("crash-session", func(s *State) error {
		if !s.SawPrivateRead || !s.SawNetworkCall {
			t.Fatalf("post-recovery update was not durable: %+v", s)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestBoundedTransactionAcquisitionFailureDoesNotOverwrite(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	acquired := make(chan struct{})
	release := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- Transaction("bounded-session", func(s *State) error {
			close(acquired)
			<-release
			s.SawPrivateRead = true
			return nil
		})
	}()
	<-acquired

	started := time.Now()
	err := Transaction("bounded-session", func(s *State) error {
		s.SawNetworkCall = true
		return nil
	})
	if err == nil {
		t.Fatal("contending Transaction returned nil, want bounded acquisition error")
	}
	if elapsed := time.Since(started); elapsed > 4*time.Second {
		t.Fatalf("contending Transaction blocked for %s, want bounded failure", elapsed)
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatalf("lock holder Transaction: %v", err)
	}

	if err := Transaction("bounded-session", func(s *State) error {
		if !s.SawPrivateRead || s.SawNetworkCall {
			t.Fatalf("failed contender overwrote state: %+v", s)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
