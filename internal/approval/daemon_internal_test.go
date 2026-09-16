package approval

import (
	"encoding/json"
	"net"
	"path/filepath"
	"testing"
	"time"
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
	if err := Approve(socket, r.ID, Allow); err != nil {
		t.Fatal(err)
	}
}

func TestDaemonRecordsActivityAfterActionCompletion(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	RegisterAction("night-off", func(Request) error {
		time.Sleep(20 * time.Millisecond)
		return nil
	})
	broker := New()
	r, err := broker.Create(Request{Plane: "opencode", SessionID: "activity-action", RepoRoot: "/repo", Scope: Allow, Reason: "test", Action: "night-off"})
	if err != nil {
		t.Fatal(err)
	}
	d := &Daemon{broker: broker, activity: time.Now()}
	server, client := net.Pipe()
	defer client.Close()
	go d.handle(server)
	started := time.Now()
	if err := json.NewEncoder(client).Encode(daemonMessage{Operation: "approve", ID: r.ID, Scope: Allow}); err != nil {
		t.Fatal(err)
	}
	var reply daemonReply
	if err := json.NewDecoder(client).Decode(&reply); err != nil {
		t.Fatal(err)
	}
	d.mu.Lock()
	completedAt := d.activity
	d.mu.Unlock()
	if !completedAt.After(started.Add(10 * time.Millisecond)) {
		t.Fatalf("activity = %v, want timestamp after action completion", completedAt)
	}
}
