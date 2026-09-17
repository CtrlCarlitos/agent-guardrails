package approval_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"syscall"
	"testing"
	"time"

	"github.com/CtrlCarlitos/agent-guardrails/internal/approval"
	"github.com/CtrlCarlitos/agent-guardrails/internal/operatorauth"
	"github.com/fxamacker/cbor/v2"
	"github.com/go-webauthn/webauthn/protocol"
)

type browserAssertionHarness struct {
	store     operatorauth.Store
	id        []byte
	private   ed25519.PrivateKey
	assertion approval.Assertion
}

func (h *browserAssertionHarness) BeginApprovalAssertion(request approval.Request, origin string) (approval.Assertion, error) {
	assertion, err := h.store.BeginApprovalAssertion(request, origin)
	if err == nil {
		h.assertion = assertion
	}
	return assertion, err
}

func (h *browserAssertionHarness) FinishApprovalAssertion(id string, response []byte) error {
	return h.store.FinishApprovalAssertion(id, response)
}

func (h *browserAssertionHarness) FinishApprovalAssertionAttribution(id string, response []byte) (approval.CompletionAttribution, error) {
	return h.store.FinishApprovalAssertionAttribution(id, response)
}

func TestBrowserHandlerCompletesValidSignedAssertionOnce(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	harness := newBrowserAssertionHarness(t)
	broker := approval.New()
	calls := 0
	var completed approval.Request
	approval.RegisterAction("night-off", func(request approval.Request) error {
		calls++
		completed = request
		return nil
	})
	request, err := broker.Create(approval.Request{Plane: "opencode", SessionID: "session-1", RepoRoot: "/repo", Scope: approval.RepoScope, Reason: "signed assertion", Action: "night-off"})
	if err != nil {
		t.Fatal(err)
	}
	browser, origin, err := approval.StartBrowser(broker, harness, request.ID)
	if err != nil {
		t.Fatal(err)
	}
	defer browser.Close()
	handler := browser.Handler()
	body := browserSignedAssertion(t, harness, harness.assertion, origin)

	response := httptest.NewRecorder()
	validRequest := httptest.NewRequest(http.MethodPost, "/assertion", bytes.NewReader(body))
	validRequest.Header.Set("Content-Type", "application/json")
	handler.ServeHTTP(response, validRequest)
	if response.Code != http.StatusOK {
		t.Fatalf("signed assertion status = %d, want %d", response.Code, http.StatusOK)
	}
	if calls != 1 {
		t.Fatalf("action calls = %d, want 1", calls)
	}
	if completed.Transport != "webauthn" || completed.CredentialFingerprint == "" {
		t.Fatalf("completion attribution = %+v, want WebAuthn fingerprint", completed)
	}
	stored, err := broker.Request(request.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Status != "completed" {
		t.Fatalf("request status = %q, want completed", stored.Status)
	}

	replay := httptest.NewRecorder()
	replayRequest := httptest.NewRequest(http.MethodPost, "/assertion", bytes.NewReader(body))
	replayRequest.Header.Set("Content-Type", "application/json")
	handler.ServeHTTP(replay, replayRequest)
	if replay.Code != http.StatusGone {
		t.Fatalf("replay status = %d, want %d", replay.Code, http.StatusGone)
	}
	if calls != 1 {
		t.Fatalf("replayed action calls = %d, want 1", calls)
	}
}

func TestBrowserClosesLoopbackAfterValidAssertion(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	harness := newBrowserAssertionHarness(t)
	broker := approval.New()
	approval.RegisterAction("night-on", func(approval.Request) error { return nil })
	request, err := broker.Create(approval.Request{Plane: "opencode", SessionID: "session-1", RepoRoot: "/repo", Scope: approval.RepoScope, Reason: "signed assertion", Action: "night-on", Parameters: map[string]string{"until": "08:00"}})
	if err != nil {
		t.Fatal(err)
	}
	browser, origin, err := approval.StartBrowser(broker, harness, request.ID)
	if err != nil {
		t.Fatal(err)
	}
	defer browser.Close()

	response, err := http.Post(origin+"/assertion", "application/json", bytes.NewReader(browserSignedAssertion(t, harness, harness.assertion, origin)))
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("signed assertion status = %d, want %d", response.StatusCode, http.StatusOK)
	}
	deadline := time.Now().Add(time.Second)
	if testDeadline, ok := t.Deadline(); ok && testDeadline.Before(deadline) {
		deadline = testDeadline
	}
	var lastErr error
	for {
		response, err := http.Get(origin)
		if errors.Is(err, syscall.ECONNREFUSED) {
			return
		}
		if err != nil {
			lastErr = err
		} else {
			response.Body.Close()
			lastErr = fmt.Errorf("loopback listener returned %s", response.Status)
		}
		if time.Now().After(deadline) {
			t.Fatalf("loopback listener did not refuse connections before deadline: %v", lastErr)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func newBrowserAssertionHarness(t *testing.T) *browserAssertionHarness {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publicKey, err := cbor.Marshal(map[int]any{1: int64(1), 3: int64(-8), -1: int64(6), -2: []byte(public)})
	if err != nil {
		t.Fatal(err)
	}
	store := operatorauth.NewStore(t.TempDir())
	id := []byte("browser-test-credential")
	if err := store.Replace([]operatorauth.Credential{{ID: base64.RawURLEncoding.EncodeToString(id), PublicKey: base64.RawURLEncoding.EncodeToString(publicKey), Algorithm: -8}}); err != nil {
		t.Fatal(err)
	}
	return &browserAssertionHarness{store: store, id: id, private: private}
}

func browserSignedAssertion(t *testing.T, harness *browserAssertionHarness, ceremony approval.Assertion, origin string) []byte {
	t.Helper()
	options := ceremony.Options.(*protocol.CredentialAssertion)
	clientData, err := json.Marshal(map[string]any{"type": "webauthn.get", "challenge": base64.RawURLEncoding.EncodeToString([]byte(options.Response.Challenge)), "origin": origin})
	if err != nil {
		t.Fatal(err)
	}
	rpHash := sha256.Sum256([]byte("localhost"))
	authenticatorData := append([]byte{}, rpHash[:]...)
	authenticatorData = append(authenticatorData, byte(protocol.FlagUserPresent|protocol.FlagUserVerified), 0, 0, 0, 1)
	clientHash := sha256.Sum256(clientData)
	signature := ed25519.Sign(harness.private, append(authenticatorData, clientHash[:]...))
	response, err := json.Marshal(map[string]any{
		"id": base64.RawURLEncoding.EncodeToString(harness.id), "rawId": base64.RawURLEncoding.EncodeToString(harness.id), "type": "public-key",
		"response": map[string]any{"clientDataJSON": base64.RawURLEncoding.EncodeToString(clientData), "authenticatorData": base64.RawURLEncoding.EncodeToString(authenticatorData), "signature": base64.RawURLEncoding.EncodeToString(signature)},
	})
	if err != nil {
		t.Fatal(err)
	}
	return response
}
