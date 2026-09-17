package approval_test

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/CtrlCarlitos/agent-guardrails/internal/approval"
	"github.com/CtrlCarlitos/agent-guardrails/internal/operatorauth"
)

func TestDaemonUsesPrivateSocketAndSubmitsRequestOnce(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	if err := os.Mkdir(filepath.Join(os.Getenv("XDG_STATE_HOME"), "guardrail"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := operatorauth.NewStore(filepath.Join(os.Getenv("XDG_STATE_HOME"), "guardrail")).Replace([]operatorauth.Credential{{ID: "AQI", PublicKey: "AQI", Algorithm: -7}}); err != nil {
		t.Fatal(err)
	}
	socket := filepath.Join(t.TempDir(), "broker", "approvals.sock")
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
	if opened == "" {
		t.Fatal("default operator-auth store was not used to start the browser ceremony")
	}
}

func TestDaemonDoesNotReplaceALiveSocket(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("persistent approvals are unavailable on Windows")
	}
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	socket := filepath.Join(t.TempDir(), "broker", "approvals.sock")
	first, err := approval.StartDaemon(socket, approval.New(), nil, func(string) error { return nil })
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
	t.Setenv("XDG_STATE_HOME", filepath.Join(t.TempDir(), strings.Repeat("state-", 30)))
	socket := approval.DefaultSocketPath()
	daemon, err := approval.StartDaemon(socket, approval.New(), nil, func(string) error { return nil })
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
