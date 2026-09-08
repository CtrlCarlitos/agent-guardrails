package session

import (
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
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

func TestAdditiveStatePreservesExistingM7JSON(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	const sessionID = "existing-m7-state"
	path := Path(sessionID)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(`{"saw_private_read":true,"saw_network_call":true,"updated_at":"2026-09-07T11:00:00Z"}`), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := Transaction(sessionID, func(s *State) error {
		if !s.SawPrivateRead || !s.SawNetworkCall {
			t.Fatalf("existing M-7 signals = %+v, want both preserved", s)
		}
		if s.PendingApprovals != nil {
			t.Fatalf("missing additive field decoded as %+v, want nil", s.PendingApprovals)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	got := readDurableState(t, sessionID)
	if !got.SawPrivateRead || !got.SawNetworkCall {
		t.Fatalf("persisted M-7 signals = %+v, want both preserved", got)
	}
}

func TestPendingApprovalRoundTripOmitsRawIdentity(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	const (
		sessionID   = "distinctive-raw-session-id"
		rawArgument = "distinctive raw argument text"
	)
	expiresAt := time.Date(2026, 9, 7, 12, 10, 0, 0, time.UTC)
	want := PendingApproval{
		OriginRuleID: "P2.git-checkout-restore",
		ExpiresAt:    expiresAt,
	}

	if err := Transaction(sessionID, func(s *State) error {
		s.PendingApprovals = map[string]PendingApproval{"digest": want}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	got := readDurableState(t, sessionID)
	if approval, ok := got.PendingApprovals["digest"]; !ok || approval != want {
		t.Fatalf("pending approval = %+v, present=%v, want %+v", approval, ok, want)
	}
	raw, err := os.ReadFile(Path(sessionID))
	if err != nil {
		t.Fatal(err)
	}
	for _, wantText := range []string{"digest", "P2.git-checkout-restore", "2026-09-07T12:10:00Z"} {
		if !strings.Contains(string(raw), wantText) {
			t.Errorf("persisted state %q does not contain %q", raw, wantText)
		}
	}
	for _, secret := range []string{sessionID, rawArgument} {
		if strings.Contains(string(raw), secret) {
			t.Errorf("persisted state contains raw identity %q: %s", secret, raw)
		}
	}
}

func TestTransactionMigratesLegacyStateAfterSuccessfulHashedPersistence(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	const sessionID = "legacy-session"
	legacyPath := filepath.Join(dir(), sessionID+".json")
	writeStateFixture(t, legacyPath, State{SawPrivateRead: true, UpdatedAt: "legacy"})

	observedPrivate := false
	if err := Transaction(sessionID, func(s *State) error {
		observedPrivate = s.SawPrivateRead
		s.SawNetworkCall = true
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if !observedPrivate {
		t.Fatal("transaction callback did not observe the legacy private-data signal")
	}
	state := readDurableState(t, sessionID)
	if !state.SawPrivateRead || !state.SawNetworkCall {
		t.Fatalf("migrated hashed state = %+v, want both monotonic signals", state)
	}
	if _, err := os.Stat(legacyPath); err != nil {
		t.Fatalf("legacy state was removed after successful migration: %v", err)
	}
}

func TestTransactionPreservesLegacyPathReplacement(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	const sessionID = "replaced-legacy"
	legacyPath := filepath.Join(dir(), sessionID+".json")
	writeStateFixture(t, legacyPath, State{SawPrivateRead: true})
	replacement := []byte(`{"replacement":true}`)

	if err := Transaction(sessionID, func(s *State) error {
		if !s.SawPrivateRead || s.SawNetworkCall {
			t.Fatalf("callback state = %+v, want legacy private signal", s)
		}
		if err := os.Remove(legacyPath); err != nil {
			return err
		}
		if err := os.WriteFile(legacyPath, replacement, 0o600); err != nil {
			return err
		}
		oldTime := time.Now().Add(-48 * time.Hour)
		if err := os.Chtimes(legacyPath, oldTime, oldTime); err != nil {
			return err
		}
		s.SawNetworkCall = true
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if got := readDurableState(t, sessionID); !got.SawPrivateRead || !got.SawNetworkCall {
		t.Fatalf("migrated v2 state = %+v, want both signals", got)
	}
	if raw, err := os.ReadFile(legacyPath); err != nil || string(raw) != string(replacement) {
		t.Fatalf("replacement legacy entry changed: raw=%q err=%v", raw, err)
	}
}

func TestTransactionMigratesDigestShapedLegacySessionID(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	sessionID := strings.Repeat("a", 64)
	legacyPath := filepath.Join(dir(), sessionID+".json")
	writeStateFixture(t, legacyPath, State{SawPrivateRead: true})

	if err := Transaction(sessionID, func(s *State) error {
		if !s.SawPrivateRead || s.SawNetworkCall {
			t.Fatalf("callback state = %+v, want digest-shaped legacy state", s)
		}
		s.SawNetworkCall = true
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if got := readDurableState(t, sessionID); !got.SawPrivateRead || !got.SawNetworkCall {
		t.Fatalf("migrated state = %+v, want both signals", got)
	}
	if _, err := os.Stat(legacyPath); err != nil {
		t.Fatalf("digest-shaped legacy state was removed after migration: %v", err)
	}
}

func TestTransactionPrefersHashedStateOverLegacyState(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	const sessionID = "state-precedence"
	legacyPath := filepath.Join(dir(), sessionID+".json")
	writeStateFixture(t, legacyPath, State{SawPrivateRead: true})
	writeStateFixture(t, Path(sessionID), State{SawNetworkCall: true})

	if err := Transaction(sessionID, func(s *State) error {
		if s.SawPrivateRead || !s.SawNetworkCall {
			t.Fatalf("callback state = %+v, want hashed state to take precedence", s)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(legacyPath); err != nil {
		t.Fatalf("unused legacy state was removed: %v", err)
	}
}

func TestTransactionDoesNotFallbackFromCorruptV2State(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	const sessionID = "corrupt-v2"
	legacyPath := filepath.Join(dir(), sessionID+".json")
	writeStateFixture(t, legacyPath, State{SawPrivateRead: true})
	if err := os.MkdirAll(filepath.Dir(Path(sessionID)), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(Path(sessionID), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}

	called := false
	if err := Transaction(sessionID, func(*State) error {
		called = true
		return nil
	}); err == nil {
		t.Fatal("corrupt v2 state returned nil, want decode error")
	}
	if called {
		t.Fatal("corrupt v2 state reached callback")
	}
	if _, err := os.Stat(legacyPath); err != nil {
		t.Fatalf("legacy state was touched after corrupt v2 state: %v", err)
	}
	if raw, err := os.ReadFile(Path(sessionID)); err != nil || string(raw) != "{" {
		t.Fatalf("corrupt v2 state changed: raw=%q err=%v", raw, err)
	}
}

func TestV2NamespaceDoesNotCollideWithLegacySessionID(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	const originalID = "original-session"
	if err := Transaction(originalID, func(s *State) error {
		s.SawPrivateRead = true
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	digestID := strings.TrimSuffix(filepath.Base(Path(originalID)), ".json")
	if err := Transaction(digestID, func(s *State) error {
		if s.SawPrivateRead || s.SawNetworkCall {
			t.Fatalf("digest-shaped session ID read another session's state: %+v", s)
		}
		s.SawNetworkCall = true
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	original := readDurableState(t, originalID)
	if !original.SawPrivateRead || original.SawNetworkCall {
		t.Fatalf("original state changed during digest-shaped transaction: %+v", original)
	}
	digest := readDurableState(t, digestID)
	if digest.SawPrivateRead || !digest.SawNetworkCall {
		t.Fatalf("digest-shaped session state = %+v, want isolated network signal", digest)
	}
}

func TestTransactionUsesV2ForEveryNonemptyNativeID(t *testing.T) {
	tests := []struct {
		name string
		id   string
	}{
		{name: "nul", id: "native\x00id"},
		{name: "controls", id: "native\nid\t"},
		{name: "colon", id: "native:id"},
		{name: "slash", id: "nested/session"},
		{name: "backslash", id: `nested\session`},
		{name: "traversal", id: "../session"},
		{name: "long", id: strings.Repeat("x", 4<<10)},
		{name: "windows reserved", id: "CON"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("XDG_STATE_HOME", t.TempDir())
			if err := Transaction(tt.id, func(s *State) error {
				if s.SawPrivateRead || s.SawNetworkCall {
					t.Fatalf("first transaction state = %+v, want zero state", s)
				}
				s.SawPrivateRead = true
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			if err := Transaction(tt.id, func(s *State) error {
				if !s.SawPrivateRead || s.SawNetworkCall {
					t.Fatalf("second transaction state = %+v, want durable private signal", s)
				}
				s.SawNetworkCall = true
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			if got := readDurableState(t, tt.id); !got.SawPrivateRead || !got.SawNetworkCall {
				t.Fatalf("durable state = %+v, want both signals", got)
			}
			if got, want := filepath.Dir(Path(tt.id)), filepath.Join(dir(), "v2"); got != want {
				t.Fatalf("state directory = %q, want %q", got, want)
			}
			entries, err := os.ReadDir(dir())
			if err != nil {
				t.Fatal(err)
			}
			for _, entry := range entries {
				if strings.HasSuffix(entry.Name(), ".json") {
					t.Errorf("new transaction wrote root-level state %q", entry.Name())
				}
			}
		})
	}
}

func TestTransactionRejectsLegacySymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("creating symlinks requires privileges not guaranteed on Windows")
	}
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	const sessionID = "linked-legacy"
	externalPath := filepath.Join(t.TempDir(), "external.json")
	writeStateFixture(t, externalPath, State{SawPrivateRead: true})
	if err := os.MkdirAll(dir(), 0o700); err != nil {
		t.Fatal(err)
	}
	legacyPath := filepath.Join(dir(), sessionID+".json")
	if err := os.Symlink(externalPath, legacyPath); err != nil {
		t.Fatal(err)
	}

	called := false
	if err := Transaction(sessionID, func(*State) error {
		called = true
		return nil
	}); err == nil {
		t.Fatal("Transaction returned nil for legacy symlink")
	}
	if called {
		t.Fatal("legacy symlink state reached callback")
	}
	assertLegacyOnly(t, sessionID, legacyPath)
}

func TestTransactionNeverReadsFormerlyRejectedLegacyIDs(t *testing.T) {
	for _, sessionID := range []string{".", "..", "legacy..session", "nested/session", `nested\session`} {
		t.Run(sessionID, func(t *testing.T) {
			t.Setenv("XDG_STATE_HOME", t.TempDir())
			legacyPath := filepath.Join(dir(), sessionID+".json")
			writeStateFixture(t, legacyPath, State{SawPrivateRead: true})

			if err := Transaction(sessionID, func(s *State) error {
				if s.SawPrivateRead || s.SawNetworkCall {
					t.Fatalf("callback read rejected legacy path %q: %+v", legacyPath, s)
				}
				s.SawNetworkCall = true
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			state := readDurableState(t, sessionID)
			if state.SawPrivateRead || !state.SawNetworkCall {
				t.Fatalf("hashed state for rejected legacy ID = %+v", state)
			}
			if _, err := os.Stat(legacyPath); err != nil {
				t.Fatalf("rejected legacy path was touched: %v", err)
			}
		})
	}
}

func TestTransactionKeepsLegacyStateOnFailure(t *testing.T) {
	t.Run("decode", func(t *testing.T) {
		t.Setenv("XDG_STATE_HOME", t.TempDir())
		const sessionID = "corrupt-legacy"
		legacyPath := filepath.Join(dir(), sessionID+".json")
		if err := os.MkdirAll(dir(), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(legacyPath, []byte("{"), 0o600); err != nil {
			t.Fatal(err)
		}
		called := false
		if err := Transaction(sessionID, func(*State) error {
			called = true
			return nil
		}); err == nil {
			t.Fatal("corrupt legacy state returned nil, want decode error")
		}
		if called {
			t.Fatal("corrupt legacy state reached callback")
		}
		assertLegacyOnly(t, sessionID, legacyPath)
	})

	t.Run("callback", func(t *testing.T) {
		t.Setenv("XDG_STATE_HOME", t.TempDir())
		const sessionID = "callback-failure"
		legacyPath := filepath.Join(dir(), sessionID+".json")
		writeStateFixture(t, legacyPath, State{SawPrivateRead: true})
		callbackErr := errors.New("callback failed")
		err := Transaction(sessionID, func(s *State) error {
			if !s.SawPrivateRead {
				t.Fatal("callback did not receive legacy state")
			}
			return callbackErr
		})
		if !errors.Is(err, callbackErr) {
			t.Fatalf("Transaction error = %v, want callback error", err)
		}
		assertLegacyOnly(t, sessionID, legacyPath)
	})

	t.Run("hashed write", func(t *testing.T) {
		t.Setenv("XDG_STATE_HOME", t.TempDir())
		const sessionID = "write-failure"
		legacyPath := filepath.Join(dir(), sessionID+".json")
		writeStateFixture(t, legacyPath, State{SawPrivateRead: true})
		err := Transaction(sessionID, func(s *State) error {
			if !s.SawPrivateRead {
				t.Fatal("callback did not receive legacy state")
			}
			return os.MkdirAll(Path(sessionID), 0o700)
		})
		if err == nil {
			t.Fatal("Transaction returned nil, want hashed persistence error")
		}
		if _, err := os.Stat(legacyPath); err != nil {
			t.Fatalf("legacy state was removed after hashed write failure: %v", err)
		}
	})
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
	sessionsDir := filepath.Join(base, "guardrail", "sessions", "v2")
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
	legacyPath := filepath.Join(dir(), "old-legacy.json")
	writeStateFixture(t, legacyPath, State{})
	if err := os.Chtimes(legacyPath, oldTime, oldTime); err != nil {
		t.Fatal(err)
	}
	rootTemp := filepath.Join(dir(), ".session-root.tmp")
	v2Temp := filepath.Join(dir(), "v2", ".session-v2.tmp")
	for _, path := range []string{rootTemp, v2Temp} {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("temporary"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(path, oldTime, oldTime); err != nil {
			t.Fatal(err)
		}
	}

	if err := Transaction("new", func(*State) error { return nil }); err != nil {
		t.Fatal(err)
	}

	if _, err := os.Stat(oldPath); !os.IsNotExist(err) {
		t.Errorf("old v2 session file should have been pruned: %v", err)
	}
	if _, err := os.Stat(legacyPath); !os.IsNotExist(err) {
		t.Errorf("old legacy session file should have been pruned: %v", err)
	}
	if _, err := os.Stat(Path("new")); err != nil {
		t.Errorf("new session file should still exist: %v", err)
	}
	for _, path := range []string{filepath.Join(dir(), ".lock"), rootTemp, v2Temp} {
		if _, err := os.Stat(path); err != nil {
			t.Errorf("non-state file %q was pruned: %v", path, err)
		}
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

func TestStoreWideTransactionSerializesDifferentSessionsAcrossProcesses(t *testing.T) {
	const holderSessionID = "cross-process-holder"
	const migratingSessionID = "cross-process-migration"
	if os.Getenv("GUARDRAIL_TEST_HOLD_TRANSACTION") == "1" {
		err := Transaction(holderSessionID, func(s *State) error {
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
	if err := Transaction(holderSessionID, func(s *State) error {
		s.SawPrivateRead = true
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	legacyPath := filepath.Join(dir(), migratingSessionID+".json")
	writeStateFixture(t, legacyPath, State{SawPrivateRead: true})
	legacyBefore, err := os.ReadFile(legacyPath)
	if err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(t.TempDir(), "lock-acquired")
	cmd := exec.Command(os.Args[0], "-test.run=^TestStoreWideTransactionSerializesDifferentSessionsAcrossProcesses$")
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
	err = Transaction(migratingSessionID, func(s *State) error {
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
	holderState := readDurableState(t, holderSessionID)
	if !holderState.SawPrivateRead || holderState.SawNetworkCall {
		t.Errorf("failed cross-session contender changed holder state: %+v", holderState)
	}
	if legacyAfter, readErr := os.ReadFile(legacyPath); readErr != nil || string(legacyAfter) != string(legacyBefore) {
		t.Errorf("failed cross-session contender changed legacy state: raw=%q err=%v", legacyAfter, readErr)
	}
	if _, statErr := os.Stat(Path(migratingSessionID)); !os.IsNotExist(statErr) {
		t.Errorf("failed cross-session contender created v2 state: %v", statErr)
	}

	if err := cmd.Process.Kill(); err != nil {
		t.Fatalf("crash lock-holder subprocess: %v", err)
	}
	if err := cmd.Wait(); err == nil {
		t.Fatal("lock-holder subprocess exited successfully, want forced crash")
	}
	waited = true
	if err := Transaction(migratingSessionID, func(s *State) error {
		if !s.SawPrivateRead || s.SawNetworkCall {
			t.Fatalf("state after lock-holder crash = %+v, want migrating session's legacy state", s)
		}
		s.SawNetworkCall = true
		return nil
	}); err != nil {
		t.Fatalf("transaction after lock-holder crash: %v", err)
	}
	migratedState := readDurableState(t, migratingSessionID)
	if !migratedState.SawPrivateRead || !migratedState.SawNetworkCall {
		t.Fatalf("post-crash legacy migration was not durable: %+v", migratedState)
	}
	if legacyAfter, readErr := os.ReadFile(legacyPath); readErr != nil || string(legacyAfter) != string(legacyBefore) {
		t.Fatalf("successful migration changed retained legacy state: raw=%q err=%v", legacyAfter, readErr)
	}
	holderState = readDurableState(t, holderSessionID)
	if !holderState.SawPrivateRead || holderState.SawNetworkCall {
		t.Fatalf("crashed holder changed its durable state: %+v", holderState)
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

func writeStateFixture(t *testing.T, path string, state State) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(&state)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
}

func assertLegacyOnly(t *testing.T, sessionID, legacyPath string) {
	t.Helper()
	if _, err := os.Stat(legacyPath); err != nil {
		t.Fatalf("legacy state was removed after failed migration: %v", err)
	}
	if _, err := os.Stat(Path(sessionID)); !os.IsNotExist(err) {
		t.Fatalf("hashed state exists after failed migration: %v", err)
	}
}
