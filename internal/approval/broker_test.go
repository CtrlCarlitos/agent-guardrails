package approval_test

import (
	"errors"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/CtrlCarlitos/agent-guardrails/internal/approval"
	"github.com/CtrlCarlitos/agent-guardrails/internal/operatorauth"
)

func request() approval.Request {
	return approval.Request{
		Plane: "opencode", SessionID: "session-1", RepoRoot: filepath.FromSlash("/repo"),
		Host: "api.example.test", Scope: approval.RepoScope, Reason: "request web host",
	}
}

func browserStore(t *testing.T) *operatorauth.Store {
	t.Helper()
	store := operatorauth.NewStore(t.TempDir())
	if err := store.Replace([]operatorauth.Credential{{ID: "AQI", PublicKey: "AQI", Algorithm: -7}}); err != nil {
		t.Fatal(err)
	}
	return &store
}

func TestBrowserBindsOnlyLoopback(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	broker := approval.New()
	r, err := broker.Create(request())
	if err != nil {
		t.Fatal(err)
	}
	server, url, err := approval.StartBrowser(broker, browserStore(t), r.ID)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	if !strings.HasPrefix(url, "http://localhost:") {
		t.Fatalf("browser URL = %q, want localhost WebAuthn origin", url)
	}
}

func TestBrowserNeverCompletesFromFormChoice(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	broker := approval.New()
	r, err := broker.Create(request())
	if err != nil {
		t.Fatal(err)
	}
	server, pageURL, err := approval.StartBrowser(broker, browserStore(t), r.ID)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	response, err := http.PostForm(pageURL, url.Values{"choice": {"approve"}})
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusNotFound {
		t.Fatalf("form approval status = %d, want %d", response.StatusCode, http.StatusNotFound)
	}
	stored, err := broker.Request(r.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Status != "pending" {
		t.Fatalf("request status = %q, want pending", stored.Status)
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

func TestWebHostActionPreservesRequestedScopeAndHost(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	broker := approval.New()
	r := request()
	r.Action = "web-host-grant"
	r.Scope = approval.GlobalScope
	r.Host = "api.example.test"
	created, err := broker.Create(r)
	if err != nil {
		t.Fatal(err)
	}
	got, err := broker.Request(created.ID)
	if err != nil || got.Scope != approval.GlobalScope || got.Parameters["host"] != "api.example.test" {
		t.Fatalf("restored request = %+v, error %v", got, err)
	}
}

func TestPlaneLifecycleActionAcceptsSupportedPlane(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	broker := approval.New()
	r := request()
	r.Action = "plane-disable"
	r.Scope = approval.GlobalScope
	r.Parameters = map[string]string{"plane": "claude"}

	created, err := broker.Create(r)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := broker.Request(created.ID); err != nil || got.Parameters["plane"] != "claude" {
		t.Fatalf("restored request = %+v, error %v", got, err)
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

func TestCreateAssignsAndPersistsIssuedAt(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	broker := approval.New()
	r := request()
	r.IssuedAt = time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)
	before := time.Now().UTC()
	created, err := broker.Create(r)
	if err != nil {
		t.Fatal(err)
	}
	if created.IssuedAt.Before(before) || created.IssuedAt.Equal(r.IssuedAt) {
		t.Fatalf("created issued at = %s, want Broker.Create-assigned value", created.IssuedAt)
	}
	restored, err := broker.Request(created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !restored.IssuedAt.Equal(created.IssuedAt) {
		t.Fatalf("restored issued at = %s, want %s", restored.IssuedAt, created.IssuedAt)
	}
}

func TestBrokerDoesNotPersistReasonOrRawNightParameters(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	broker := approval.New()
	r := request()
	r.Reason = "super-secret-reason"
	r.Action = "night-on"
	r.Parameters = map[string]string{"until": "08:00"}
	if _, err := broker.Create(r); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(approval.StatePath())
	if err != nil {
		t.Fatal(err)
	}
	if got := string(raw); strings.Contains(got, "super-secret") || strings.Contains(got, `"until":"08:00"`) {
		t.Fatalf("broker state contains raw sensitive input: %q", got)
	}
}

func TestCreateCanonicalizesNightExpiryAndRejectsMalformedClock(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	broker := approval.New()
	request := request()
	request.Action = "night-on"
	request.Parameters = map[string]string{"until": time.Now().Add(2 * time.Hour).Format("15:04")}
	created, err := broker.Create(request)
	if err != nil {
		t.Fatal(err)
	}
	if created.Parameters["until"] != "" || created.Parameters["expires_at"] == "" {
		t.Fatalf("created night parameters = %v, want canonical expires_at only", created.Parameters)
	}
	if _, err := time.Parse(time.RFC3339Nano, created.Parameters["expires_at"]); err != nil {
		t.Fatalf("canonical expiry = %q: %v", created.Parameters["expires_at"], err)
	}
	restored, err := broker.Request(created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if restored.Parameters["expires_at"] != created.Parameters["expires_at"] {
		t.Fatalf("restored expiry = %q, want %q", restored.Parameters["expires_at"], created.Parameters["expires_at"])
	}

	request.Parameters = map[string]string{"until": "8:00"}
	if _, err := broker.Create(request); !errors.Is(err, approval.ErrMalformed) {
		t.Fatalf("non-canonical clock = %v, want malformed request", err)
	}
}
