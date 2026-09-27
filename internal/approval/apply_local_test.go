package approval_test

import (
	"errors"
	"testing"
	"time"

	"github.com/CtrlCarlitos/agent-guardrails/internal/approval"
	"github.com/CtrlCarlitos/agent-guardrails/internal/testenv"
)

// ADR-0033: a prompt-mode approval runs the same registered action handler
// the broker runs, in-process, attributed to the transport that approved it.
func TestApplyLocalRunsTheRegisteredHandlerWithAttribution(t *testing.T) {
	testenv.SetState(t, t.TempDir())
	var got approval.Request
	approval.RegisterAction("recover", func(r approval.Request) error { got = r; return nil })
	t.Cleanup(func() { approval.RegisterAction("recover", nil) })

	applied, err := approval.ApplyLocal(approval.Request{
		Plane: "operator", SessionID: "terminal", RepoRoot: testRepoRoot(), Scope: approval.GlobalScope,
		Reason: "operator terminal recovery", Action: "recover", Parameters: map[string]string{"repair": "claude-settings"},
	}, "terminal-prompt")
	if err != nil {
		t.Fatal(err)
	}
	if got.ID == "" || got.ID != applied.ID || got.Transport != "terminal-prompt" || got.Parameters["repair"] != "claude-settings" {
		t.Fatalf("handler saw %+v, ApplyLocal returned %+v", got, applied)
	}
	if applied.Status != "completed" {
		t.Fatalf("status = %q, want completed", applied.Status)
	}
}

func TestApplyLocalRejectsWhatTheBrokerRejects(t *testing.T) {
	testenv.SetState(t, t.TempDir())
	called := false
	approval.RegisterAction("recover", func(approval.Request) error { called = true; return nil })
	t.Cleanup(func() { approval.RegisterAction("recover", nil) })
	for _, r := range []approval.Request{
		{Plane: "operator", SessionID: "terminal", RepoRoot: "relative", Scope: approval.GlobalScope, Reason: "x", Action: "recover"},
		{Plane: "operator", SessionID: "terminal", RepoRoot: testRepoRoot(), Scope: approval.GlobalScope, Reason: "x", Action: "rm-rf"},
		{Plane: "operator", SessionID: "terminal", RepoRoot: testRepoRoot(), Scope: approval.GlobalScope, Reason: "x", Action: "recover", Parameters: map[string]string{"repair": "everything"}},
		{Plane: "operator", SessionID: "terminal", RepoRoot: testRepoRoot(), Scope: approval.Allow, Reason: "x", Action: "night-on"},
	} {
		if _, err := approval.ApplyLocal(r, "host-ask"); err == nil {
			t.Errorf("ApplyLocal(%+v) succeeded; want the broker's validation error or a missing handler", r)
		}
	}
	if _, err := approval.ApplyLocal(approval.Request{Plane: "operator", SessionID: "terminal", RepoRoot: testRepoRoot(), Scope: approval.GlobalScope, Reason: "x", Action: "recover", Parameters: map[string]string{"repair": "x"}}, ""); err == nil {
		t.Error("ApplyLocal without a transport must fail: every local approval names what approved it")
	}
	if called {
		t.Fatal("a rejected request must never reach the handler")
	}
}

func TestApplyLocalNormalizesNightExpiryLikeTheBroker(t *testing.T) {
	testenv.SetState(t, t.TempDir())
	var got approval.Request
	approval.RegisterAction("night-on", func(r approval.Request) error { got = r; return nil })
	t.Cleanup(func() { approval.RegisterAction("night-on", nil) })
	if _, err := approval.ApplyLocal(approval.Request{
		Plane: "claude", SessionID: "s1", RepoRoot: testRepoRoot(), Scope: approval.Allow, Reason: "canonical operator action",
		Action: "night-on", Parameters: map[string]string{"until": "07:30"},
	}, "host-ask"); err != nil {
		t.Fatal(err)
	}
	expires, err := time.Parse(time.RFC3339Nano, got.Parameters["expires_at"])
	if err != nil || len(got.Parameters) != 1 || !expires.After(time.Now()) {
		t.Fatalf("night-on parameters = %v, want one future expires_at", got.Parameters)
	}
}

func TestApplyLocalReportsHandlerFailure(t *testing.T) {
	testenv.SetState(t, t.TempDir())
	approval.RegisterAction("recover", func(approval.Request) error { return errors.New("disk full") })
	t.Cleanup(func() { approval.RegisterAction("recover", nil) })
	_, err := approval.ApplyLocal(approval.Request{Plane: "operator", SessionID: "terminal", RepoRoot: testRepoRoot(), Scope: approval.GlobalScope, Reason: "x", Action: "recover", Parameters: map[string]string{"repair": "claude-settings"}}, "terminal-prompt")
	if err == nil {
		t.Fatal("a failing handler must fail ApplyLocal")
	}
}
