package operatorauth_test

import (
	"errors"
	"testing"
	"time"

	"github.com/CtrlCarlitos/agent-guardrails/internal/approval"
	"github.com/CtrlCarlitos/agent-guardrails/internal/operatorauth"
)

// TestBeginAssertionWithoutEnrollmentReportsNotEnrolled: an empty store
// names the real reason instead of a file-read error (#326).
func TestBeginAssertionWithoutEnrollmentReportsNotEnrolled(t *testing.T) {
	request := approval.Request{
		ID: "request-1", IssuedAt: time.Now(), Action: "plane-enable", Parameters: map[string]string{"planes": "claude"}, RepoRoot: "/repo", Scope: approval.GlobalScope, ExpiresAt: time.Now().Add(time.Minute),
	}
	store := operatorauth.NewStore(t.TempDir())
	if _, err := store.BeginAssertion(request, "http://localhost:12345"); !errors.Is(err, approval.ErrNotEnrolled) {
		t.Fatalf("BeginAssertion on an empty store = %v, want ErrNotEnrolled", err)
	}
	if _, err := store.BeginApprovalAssertion(request, "http://localhost:12345"); !errors.Is(err, approval.ErrNotEnrolled) {
		t.Fatalf("BeginApprovalAssertion on an empty store = %v, want ErrNotEnrolled", err)
	}
}
