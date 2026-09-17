package approval

import (
	"path/filepath"
	"testing"
)

func TestDaemonRecoversInterruptedAction(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	action := "night-off"
	RegisterAction(action, func(Request) error { return nil })
	broker := New()
	r, err := broker.Create(Request{Plane: "opencode", SessionID: "recover-action", RepoRoot: "/repo", Scope: Allow, Reason: "test", Action: action})
	if err != nil {
		t.Fatal(err)
	}
	if err := broker.transition(r.ID, "executing"); err != nil {
		t.Fatal(err)
	}
	socket := filepath.Join(t.TempDir(), "broker", "approvals.sock")
	d, err := StartDaemon(socket, New(), func(string) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	stored, err := New().Request(r.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Status != "pending" {
		t.Fatalf("recovered action status = %q, want pending", stored.Status)
	}
}

func TestFailedDaemonStartDoesNotRecoverLiveActions(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	broker := New()
	r, err := broker.Create(Request{Plane: "opencode", SessionID: "live-action", RepoRoot: "/repo", Scope: Allow, Reason: "test", Action: "night-off"})
	if err != nil {
		t.Fatal(err)
	}
	socket := filepath.Join(t.TempDir(), "broker", "approvals.sock")
	live, err := StartDaemon(socket, broker, func(string) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	defer live.Close()
	if err := broker.transition(r.ID, "executing"); err != nil {
		t.Fatal(err)
	}
	if _, err := StartDaemon(socket, New(), func(string) error { return nil }); err == nil {
		t.Fatal("second daemon unexpectedly started")
	}
	got, err := broker.Request(r.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != "executing" {
		t.Fatalf("live action status = %q, want executing", got.Status)
	}
}
