package approval

import (
	"errors"
	"fmt"
	"testing"
	"time"
)

// notEnrolledStore stands in for an operator-auth store with no credential
// set: every assertion attempt fails the way the real store does (#326).
type notEnrolledStore struct{}

func (notEnrolledStore) BeginApprovalAssertion(Request, string) (Assertion, error) {
	return Assertion{}, fmt.Errorf("begin assertion: %w", ErrNotEnrolled)
}

func (notEnrolledStore) FinishApprovalAssertion(string, []byte) error { return nil }

func enrollmentRequest(session string) Request {
	return Request{Plane: "operator", SessionID: session, RepoRoot: testRepoRoot(), Scope: GlobalScope, Reason: "test", Action: "plane-enable", Parameters: map[string]string{"planes": "claude"}, ExpiresAt: time.Now().Add(time.Minute)}
}

// TestSubmitReportsDaemonUnavailableOnlyWhenUnreachable pins the meaning of
// the string: nothing answered on the socket.
func TestSubmitReportsDaemonUnavailableOnlyWhenUnreachable(t *testing.T) {
	setStateHome(t, t.TempDir())
	_, err := Submit(shortSocketPath(t), enrollmentRequest("unreachable"))
	if !errors.Is(err, ErrDaemonUnavailable) {
		t.Fatalf("submit to a dead socket = %v, want ErrDaemonUnavailable", err)
	}
}

// TestSubmitPropagatesDaemonReplyError: a daemon that answered with an error
// is not "unavailable"; the caller gets the daemon's reason (#326).
func TestSubmitPropagatesDaemonReplyError(t *testing.T) {
	setStateHome(t, t.TempDir())
	socket := shortSocketPath(t)
	daemon, err := StartDaemon(socket, New(), nil, func(string) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	defer daemon.Close()

	_, err = Submit(socket, enrollmentRequest("reply-error"))
	if err == nil {
		t.Fatal("submit succeeded without an approval page")
	}
	if errors.Is(err, ErrDaemonUnavailable) {
		t.Fatalf("daemon reply error was rewritten as unavailable: %v", err)
	}
	if err.Error() != "approval request unavailable" {
		t.Fatalf("submit error = %q, want the daemon's reply", err)
	}
}

// TestDaemonReportsMissingEnrollment: with no authenticator enrolled the
// daemon says so, and the request does not linger as pending.
func TestDaemonReportsMissingEnrollment(t *testing.T) {
	setStateHome(t, t.TempDir())
	broker := New()
	socket := shortSocketPath(t)
	daemon, err := StartDaemon(socket, broker, notEnrolledStore{}, func(string) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	defer daemon.Close()

	_, err = Submit(socket, enrollmentRequest("not-enrolled"))
	if !errors.Is(err, ErrNotEnrolled) {
		t.Fatalf("submit error = %v, want ErrNotEnrolled", err)
	}
	if broker.hasPending() {
		t.Fatal("unpresentable approval request remained pending")
	}
}

// TestSubmitOnDemandReturnsDaemonReplyErrorWithoutRespawn: a live daemon
// that refused the request must not be treated as absent (which used to
// spawn a second daemon, wait a second, and report "unavailable").
func TestSubmitOnDemandReturnsDaemonReplyErrorWithoutRespawn(t *testing.T) {
	setStateHome(t, t.TempDir())
	daemon, err := StartDaemon(DefaultSocketPath(), New(), notEnrolledStore{}, func(string) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	defer daemon.Close()

	_, err = SubmitOnDemand(enrollmentRequest("on-demand"))
	if !errors.Is(err, ErrNotEnrolled) {
		t.Fatalf("SubmitOnDemand error = %v, want ErrNotEnrolled", err)
	}
	// Under the test flag the respawn path creates the request in-process;
	// an empty pending set proves that path was not taken.
	if New().hasPending() {
		t.Fatal("SubmitOnDemand fell through to the respawn path after a daemon reply error")
	}
}
