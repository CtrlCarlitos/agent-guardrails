package approval

import (
	"errors"
	"testing"
)

// A rejected request used to come back as "approval request unavailable",
// the same words as a browser that failed to start, so an operator whose
// `plane enable` was refused for its parameters had nothing to go on. A
// malformed request now says so; the other failures keep the generic reply.
func TestDaemonNamesAMalformedRequest(t *testing.T) {
	setStateHome(t, t.TempDir())
	socket := shortSocketPath(t)
	daemon, err := StartDaemon(socket, New(), nil, func(string) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	defer daemon.Close()

	bad := enrollmentRequest("malformed")
	bad.Parameters = map[string]string{"planes": "claude", "no_such_key": "1"}
	_, err = Submit(socket, bad)
	if err == nil {
		t.Fatal("a malformed request was accepted")
	}
	if errors.Is(err, ErrDaemonUnavailable) {
		t.Fatalf("a daemon that answered was reported unavailable: %v", err)
	}
	if err.Error() != "approval request malformed" {
		t.Fatalf("error = %q, want %q", err, "approval request malformed")
	}
}
