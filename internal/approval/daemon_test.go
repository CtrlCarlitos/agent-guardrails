package approval_test

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/CtrlCarlitos/agent-guardrails/internal/approval"
	"github.com/CtrlCarlitos/agent-guardrails/internal/operatorauth"
)

func TestDaemonUsesPrivateSocketAndSubmitsRequestOnce(t *testing.T) {
	setStateHome(t, t.TempDir())
	if err := os.Mkdir(filepath.Join(os.Getenv("XDG_STATE_HOME"), "guardrail"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := operatorauth.NewStore(filepath.Join(os.Getenv("XDG_STATE_HOME"), "guardrail")).Replace([]operatorauth.Credential{{ID: "AQI", PublicKey: "AQI", Algorithm: -7}}); err != nil {
		t.Fatal(err)
	}
	socket := shortSocketPath(t)
	var opened string
	store := operatorauth.NewStore(filepath.Join(os.Getenv("XDG_STATE_HOME"), "guardrail"))
	daemon, err := approval.StartDaemon(socket, approval.New(), &store, func(rawURL string) error {
		opened = rawURL
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	defer daemon.Close()

	if runtime.GOOS != "windows" {
		info, err := os.Stat(filepath.Dir(socket))
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o700 {
			t.Fatalf("socket directory mode = %o, want 0700", info.Mode().Perm())
		}
	}
	r, err := approval.Submit(socket, request())
	if err != nil {
		t.Fatal(err)
	}
	if r.ID == "" || r.Status != "pending" {
		t.Fatalf("submitted request = %+v, want pending request with identity", r)
	}
	if opened == "" {
		t.Fatal("default operator-auth store was not used to start the browser ceremony")
	}
	if r.ApprovalURL != opened {
		t.Fatalf("approval URL = %q, want %q", r.ApprovalURL, opened)
	}
}

func TestDaemonDoesNotReplaceALiveSocket(t *testing.T) {
	setStateHome(t, t.TempDir())
	socket := shortSocketPath(t)
	first, err := approval.StartDaemon(socket, approval.New(), browserStore(t), func(string) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	second, err := approval.StartDaemon(socket, approval.New(), nil, func(string) error { return nil })
	if err == nil {
		second.Close()
		t.Fatal("second daemon replaced the live socket")
	}
	if _, err := approval.Submit(socket, request()); err != nil {
		t.Fatalf("live daemon stopped accepting requests: %v", err)
	}
}

func TestDefaultDaemonSupportsLongStateDirectory(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Setenv("LOCALAPPDATA", filepath.Join(t.TempDir(), strings.Repeat("state-", 30)))
	} else {
		setStateHome(t, filepath.Join(t.TempDir(), strings.Repeat("state-", 30)))
	}
	socket := approval.DefaultSocketPath()
	daemon, err := approval.StartDaemon(socket, approval.New(), nil, func(string) error { return nil })
	if err != nil {
		t.Fatalf("start daemon with long state directory: %v", err)
	}
	defer daemon.Close()
	if runtime.GOOS == "windows" {
		return // pipe privacy is asserted by the DACL test, not mode bits
	}
	info, err := os.Stat(filepath.Dir(socket))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o700 {
		t.Fatalf("socket directory mode = %o, want 0700", info.Mode().Perm())
	}
}

func TestQueryStatusReportsRequestState(t *testing.T) {
	setStateHome(t, t.TempDir())
	socket := shortSocketPath(t)
	daemon, err := approval.StartDaemon(socket, approval.New(), browserStore(t), func(string) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	defer daemon.Close()

	created, err := approval.Submit(socket, request())
	if err != nil {
		t.Fatal(err)
	}
	got, err := approval.QueryStatus(socket, created.ID)
	if err != nil {
		t.Fatal(err)
	}
	// The approval URL is not durable: it is only attached to the submit
	// reply; status polling reports lifecycle state and identity.
	if got.ID != created.ID || got.Status != "pending" {
		t.Fatalf("queried request = %+v, want pending %s", got, created.ID)
	}
	if _, err := approval.QueryStatus(socket, "missing"); err == nil {
		t.Fatal("unknown request status succeeded")
	}
}

func TestShutdownDaemonClosesALiveDaemon(t *testing.T) {
	setStateHome(t, t.TempDir())
	socket := shortSocketPath(t)
	_, err := approval.StartDaemon(socket, approval.New(), browserStore(t), func(string) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	if _, err := approval.Submit(socket, request()); err != nil {
		t.Fatalf("live daemon rejected submit: %v", err)
	}
	if err := approval.ShutdownDaemon(socket); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := approval.Submit(socket, request()); err != nil {
			return // socket no longer accepts: daemon is down
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("daemon still accepting requests after shutdown")
}

func TestDaemonListsAndPresentsPendingRequests(t *testing.T) {
	setStateHome(t, t.TempDir())
	socket := shortSocketPath(t)
	presented := make(chan string, 4)
	daemon, err := approval.StartDaemon(socket, approval.New(), browserStore(t), func(rawURL string) error {
		presented <- rawURL
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	defer daemon.Close()

	created, err := approval.Submit(socket, request())
	if err != nil {
		t.Fatal(err)
	}

	pending, err := approval.ListPending(socket)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, r := range pending {
		if r.ID == created.ID && r.Status == "pending" {
			found = true
		}
	}
	if !found {
		t.Fatalf("pending list = %+v", pending)
	}

	// Re-presenting must re-open a ceremony without completing anything:
	// completion requires the WebAuthn assertion, never the socket.
	if err := approval.PresentApproval(socket, created.ID); err != nil {
		t.Fatal(err)
	}
	select {
	case url := <-presented:
		if !strings.HasPrefix(url, "http://localhost:") {
			t.Fatalf("presented URL = %q", url)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("present did not re-open the ceremony")
	}
	got, err := approval.QueryStatus(socket, created.ID)
	if err != nil || got.Status != "pending" {
		t.Fatalf("status after present = %+v err=%v, want still pending", got, err)
	}
	if err := approval.PresentApproval(socket, "missing"); err == nil {
		t.Fatal("unknown id presented")
	}
}

// shortSocketPath returns a socket path within darwin's ~104-char unix
// socket limit: runner temp dirs (/var/folders/...) exceed it, so tests
// hand-roll short paths the way DefaultSocketPath's fallback does in
// production. On Windows the broker endpoint is a named pipe, not a file.
func shortSocketPath(t *testing.T) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		return shortPipeName(t)
	}
	dir, err := os.MkdirTemp("", "grdsock")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return filepath.Join(dir, "broker", "approvals.sock")
}

func shortPipeName(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "grdpipe")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return `\\.\pipe\guardrail-test-` + filepath.Base(dir)
}
