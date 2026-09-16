package approval_test

import (
	"net/url"
	"os"
	"path/filepath"
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
	if opened == "" || !strings.HasPrefix(opened, "http://127.0.0.1:") {
		t.Fatalf("opened URL = %q, want loopback browser URL", opened)
	}
	parsed, err := url.Parse(opened)
	if err != nil || len(parsed.Query().Get("token")) != 64 {
		t.Fatalf("browser URL lacks a 256-bit token: %q", opened)
	}
	if err := approval.Approve(socket, r.ID, approval.RepoScope); err != nil {
		t.Fatal(err)
	}
	if err := approval.Approve(socket, r.ID, approval.RepoScope); err == nil {
		t.Fatal("replayed approval succeeded")
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
