package approval_test

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/CtrlCarlitos/agent-guardrails/internal/approval"
)

func TestDaemonUsesPrivateSocketAndSubmitsRequestOnce(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	socket := filepath.Join(t.TempDir(), "broker", "approvals.sock")
	var opened string
	daemon, err := approval.StartDaemon(socket, approval.New(), func(rawURL string) error {
		opened = rawURL
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	defer daemon.Close()

	info, err := os.Stat(filepath.Dir(socket))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o700 {
		t.Fatalf("socket directory mode = %o, want 0700", info.Mode().Perm())
	}
	r, err := approval.Submit(socket, request())
	if err != nil {
		t.Fatal(err)
	}
	if r.ID == "" || r.Status != "pending" {
		t.Fatalf("submitted request = %+v, want pending request with identity", r)
	}
	if opened != "" {
		t.Fatalf("opened URL = %q, want no browser until an assertion store is configured", opened)
	}
	if err := approval.Approve(socket, r.ID, approval.RepoScope); err == nil {
		t.Fatal("socket approval succeeded without a WebAuthn assertion")
	}
	stored, err := approval.Lookup(socket, r.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Status != "pending" {
		t.Fatalf("request status = %q, want pending", stored.Status)
	}
}

func TestDaemonDoesNotReplaceALiveSocket(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("persistent approvals are unavailable on Windows")
	}
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	socket := filepath.Join(t.TempDir(), "broker", "approvals.sock")
	first, err := approval.StartDaemon(socket, approval.New(), func(string) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	second, err := approval.StartDaemon(socket, approval.New(), func(string) error { return nil })
	if err == nil {
		second.Close()
		t.Fatal("second daemon replaced the live socket")
	}
	if _, err := approval.Submit(socket, request()); err != nil {
		t.Fatalf("live daemon stopped accepting requests: %v", err)
	}
}

func TestDefaultDaemonSupportsLongStateDirectory(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", filepath.Join(t.TempDir(), strings.Repeat("state-", 30)))
	socket := approval.DefaultSocketPath()
	daemon, err := approval.StartDaemon(socket, approval.New(), func(string) error { return nil })
	if err != nil {
		t.Fatalf("start daemon with long state directory: %v", err)
	}
	defer daemon.Close()
	info, err := os.Stat(filepath.Dir(socket))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o700 {
		t.Fatalf("socket directory mode = %o, want 0700", info.Mode().Perm())
	}
}
