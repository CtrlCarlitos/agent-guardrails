package approval_test

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/CtrlCarlitos/agent-guardrails/internal/approval"
)

func request() approval.Request {
	return approval.Request{
		Plane: "opencode", SessionID: "session-1", RepoRoot: filepath.FromSlash("/repo"),
		Host: "api.example.test", Scope: approval.RepoScope, Reason: "request web host",
	}
}

func TestBrowserBindsOnlyLoopback(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	broker := approval.New()
	r, err := broker.Create(request())
	if err != nil {
		t.Fatal(err)
	}
	server, url, err := approval.StartBrowser(broker, r.ID)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	if !strings.HasPrefix(url, "http://127.0.0.1:") {
		t.Fatalf("browser URL = %q, want loopback address", url)
	}
}

func TestApproveConsumesExactUnexpiredRequestOnce(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	broker := approval.New()
	r, err := broker.Create(request())
	if err != nil {
		t.Fatal(err)
	}
	if err := broker.Approve(r.ID, approval.RepoScope); err != nil {
		t.Fatal(err)
	}
	if err := broker.Approve(r.ID, approval.RepoScope); !errors.Is(err, approval.ErrConsumed) {
		t.Fatalf("second approval = %v, want consumed request", err)
	}
}

func TestApproveRejectsAChangedScope(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	broker := approval.New()
	r, err := broker.Create(request())
	if err != nil {
		t.Fatal(err)
	}
	if err := broker.Approve(r.ID, approval.GlobalScope); !errors.Is(err, approval.ErrScope) {
		t.Fatalf("approval with global scope = %v, want scope rejection", err)
	}
}

func TestApproveRejectsExpiredRequest(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	broker := approval.New()
	r := request()
	r.ExpiresAt = time.Now().Add(-time.Second)
	r, err := broker.Create(r)
	if err != nil {
		t.Fatal(err)
	}
	if err := broker.Approve(r.ID, approval.RepoScope); !errors.Is(err, approval.ErrExpired) {
		t.Fatalf("expired approval = %v, want expiry rejection", err)
	}
}

func TestCreateRejectsAnOverlongExpiry(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	broker := approval.New()
	r := request()
	r.ExpiresAt = time.Now().Add(time.Hour)
	if _, err := broker.Create(r); !errors.Is(err, approval.ErrMalformed) {
		t.Fatalf("overlong request = %v, want malformed request", err)
	}
}

func TestBrokerDoesNotPersistReasonOrParameters(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	broker := approval.New()
	r := request()
	r.Reason = "super-secret-reason"
	r.Action = "night-on"
	r.Parameters = map[string]string{"until": "08:00", "token": "super-secret-parameter"}
	if _, err := broker.Create(r); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(approval.StatePath())
	if err != nil {
		t.Fatal(err)
	}
	if got := string(raw); strings.Contains(got, "super-secret") {
		t.Fatalf("broker state contains raw sensitive input: %q", got)
	}
}
