package approval

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

type daemonAuthStore struct{}

func (daemonAuthStore) BeginApprovalAssertion(Request, string) (Assertion, error) {
	return Assertion{ID: "test-ceremony", Options: map[string]any{"challenge": "AQI"}}, nil
}

func (daemonAuthStore) FinishApprovalAssertion(string, []byte) error { return nil }

func TestDaemonRejectsCompletionMessages(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	broker := New()
	request, err := broker.Create(Request{Plane: "opencode", SessionID: "completion-message", RepoRoot: "/repo", Scope: Allow, Reason: "test"})
	if err != nil {
		t.Fatal(err)
	}
	socket := shortSocketPath(t)
	daemon, err := StartDaemon(socket, broker, nil, func(string) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	defer daemon.Close()

	for _, message := range []daemonMessage{{Operation: "approve", ID: request.ID, Scope: RepoScope}, {Operation: "deny", ID: request.ID}, {Operation: "request", ID: request.ID}} {
		var reply daemonReply
		if err := send(socket, message, &reply); err != nil {
			t.Fatal(err)
		}
		if reply.Error == "" {
			t.Fatalf("%s accepted", message.Operation)
		}
		stored, err := broker.Request(request.ID)
		if err != nil {
			t.Fatal(err)
		}
		if stored.Status != "pending" {
			t.Fatalf("%s changed request to %s", message.Operation, stored.Status)
		}
	}
}

func TestDaemonSubmitRedactsSensitiveRequestDetails(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	socket := shortSocketPath(t)
	daemon, err := StartDaemon(socket, New(), daemonAuthStore{}, func(string) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	defer daemon.Close()

	var reply daemonReply
	if err := send(socket, daemonMessage{Operation: "submit", Request: Request{Plane: "opencode", SessionID: "submit-redaction", RepoRoot: "/secret/repo", Host: "secret.example", Scope: Allow, Reason: "secret reason", Action: "night-on", Parameters: map[string]string{"until": "08:00"}}}, &reply); err != nil {
		t.Fatal(err)
	}
	if reply.Error != "" {
		t.Fatalf("submit reply = %q", reply.Error)
	}
	if reply.Request.ID == "" || reply.Request.Status != "pending" || reply.Request.ExpiresAt.IsZero() {
		t.Fatalf("submit reply = %+v, want ID, pending status, and expiry", reply.Request)
	}
	if reply.Request.Plane != "" || reply.Request.RepoRoot != "" || reply.Request.Host != "" || reply.Request.Action != "" || reply.Request.Scope != "" || reply.Request.Reason != "" || reply.Request.Parameters != nil {
		t.Fatalf("submit leaked sensitive request details: %+v", reply.Request)
	}
}

func TestDaemonRejectsRequestWhenApprovalPageCannotBePresented(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	broker := New()
	socket := shortSocketPath(t)
	daemon, err := StartDaemon(socket, broker, nil, func(string) error { return errors.New("presentation failed") })
	if err != nil {
		t.Fatal(err)
	}
	defer daemon.Close()

	if _, err := Submit(socket, Request{Plane: "opencode", SessionID: "presentation-failure", RepoRoot: "/repo", Scope: Allow, Reason: "test", Action: "night-on", Parameters: map[string]string{"until": "08:00"}}); err == nil {
		t.Fatal("submission succeeded without an approval page")
	}
	if broker.hasPending() {
		t.Fatal("unpresentable approval request remained pending")
	}
}

func TestDaemonStatusRedactsSensitiveRequestDetails(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	broker := New()
	request, err := broker.Create(Request{Plane: "opencode", SessionID: "status-redaction", RepoRoot: "/secret/repo", Host: "secret.example", Scope: Allow, Reason: "secret reason", Action: "night-on", Parameters: map[string]string{"until": "08:00"}})
	if err != nil {
		t.Fatal(err)
	}
	socket := shortSocketPath(t)
	daemon, err := StartDaemon(socket, broker, nil, func(string) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	defer daemon.Close()

	var reply daemonReply
	if err := send(socket, daemonMessage{Operation: "status", ID: request.ID}, &reply); err != nil {
		t.Fatal(err)
	}
	if reply.Error != "" {
		t.Fatalf("status reply = %q", reply.Error)
	}
	if reply.Request.ID != request.ID || reply.Request.Status != "pending" || !reply.Request.ExpiresAt.Equal(request.ExpiresAt) {
		t.Fatalf("status reply = %+v, want ID, pending status, and expiry", reply.Request)
	}
	if reply.Request.Plane != "" || reply.Request.RepoRoot != "" || reply.Request.Host != "" || reply.Request.Action != "" || reply.Request.Scope != "" || reply.Request.Reason != "" || reply.Request.Parameters != nil {
		t.Fatalf("status leaked sensitive request details: %+v", reply.Request)
	}
}

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
	socket := shortSocketPath(t)
	d, err := StartDaemon(socket, New(), nil, func(string) error { return nil })
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
	socket := shortSocketPath(t)
	live, err := StartDaemon(socket, broker, nil, func(string) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	defer live.Close()
	if err := broker.transition(r.ID, "executing"); err != nil {
		t.Fatal(err)
	}
	if _, err := StartDaemon(socket, New(), nil, func(string) error { return nil }); err == nil {
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

// shortSocketPath mirrors the external test package's helper: darwin caps
// unix socket paths near 104 chars and runner temp dirs exceed it.
func shortSocketPath(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "grdsock")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return filepath.Join(dir, "broker", "approvals.sock")
}
