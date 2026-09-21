package approval_test

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"os/exec"
	"testing"

	"github.com/CtrlCarlitos/agent-guardrails/internal/approval"
)

type retryStore struct{ begins int }

func (s *retryStore) BeginApprovalAssertion(approval.Request, string) (approval.Assertion, error) {
	s.begins++
	return approval.Assertion{ID: "ceremony-" + string(rune('0'+s.begins)), Options: map[string]any{"challenge": "AQI"}}, nil
}

func (s *retryStore) FinishApprovalAssertion(string, []byte) error {
	return errors.New("invalid assertion")
}

func TestBrowserRejectsMissingAssertionWithoutCompleting(t *testing.T) {
	setStateHome(t, t.TempDir())
	broker := approval.New()
	request, err := broker.Create(request())
	if err != nil {
		t.Fatal(err)
	}
	browser, pageURL, err := approval.StartBrowser(broker, browserStore(t), request.ID)
	if err != nil {
		t.Fatal(err)
	}
	defer browser.Close()

	response, err := http.Post(pageURL+"/assertion", "application/json", bytes.NewBufferString(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusNotFound {
		t.Fatalf("empty assertion status = %d, want %d", response.StatusCode, http.StatusNotFound)
	}
	stored, err := broker.Request(request.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Status != "pending" {
		t.Fatalf("request status = %q, want pending", stored.Status)
	}
}

func TestBrowserReissuesCeremonyAfterMalformedAssertion(t *testing.T) {
	setStateHome(t, t.TempDir())
	broker := approval.New()
	request, err := broker.Create(request())
	if err != nil {
		t.Fatal(err)
	}
	store := &retryStore{}
	browser, pageURL, err := approval.StartBrowser(broker, store, request.ID)
	if err != nil {
		t.Fatal(err)
	}
	defer browser.Close()

	response, err := http.Post(pageURL+"/assertion", "application/json", bytes.NewBufferString(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusNotFound {
		t.Fatalf("malformed assertion status = %d, want %d", response.StatusCode, http.StatusNotFound)
	}
	if store.begins != 2 {
		t.Fatalf("ceremonies begun = %d, want 2", store.begins)
	}
	stored, err := broker.Request(request.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Status != "pending" {
		t.Fatalf("request status = %q, want pending", stored.Status)
	}
}

func TestBrowserDoesNotReissueCeremonyAfterFailedAssertion(t *testing.T) {
	setStateHome(t, t.TempDir())
	broker := approval.New()
	request, err := broker.Create(request())
	if err != nil {
		t.Fatal(err)
	}
	store := &retryStore{}
	browser, pageURL, err := approval.StartBrowser(broker, store, request.ID)
	if err != nil {
		t.Fatal(err)
	}
	defer browser.Close()

	body := `{"id":"AQI","rawId":"AQI","type":"public-key","response":{"authenticatorData":"AQI","clientDataJSON":"AQI","signature":"AQI"}}`
	response, err := http.Post(pageURL+"/assertion", "application/json", bytes.NewBufferString(body))
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("failed assertion status = %d, want %d", response.StatusCode, http.StatusForbidden)
	}
	bodyText, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(bodyText, []byte("Denied: invalid assertion")) {
		t.Fatalf("failed assertion response = %q, want denial confirmation", bodyText)
	}
	if store.begins != 1 {
		t.Fatalf("ceremonies begun = %d, want 1", store.begins)
	}
	stored, err := broker.Request(request.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Status != "pending" {
		t.Fatalf("request status = %q, want pending", stored.Status)
	}
}

func TestBrowserPagePresentsCanonicalRequest(t *testing.T) {
	setStateHome(t, t.TempDir())
	broker := approval.New()
	request, err := broker.Create(request())
	if err != nil {
		t.Fatal(err)
	}
	browser, pageURL, err := approval.StartBrowser(broker, browserStore(t), request.ID)
	if err != nil {
		t.Fatal(err)
	}
	defer browser.Close()

	response, err := http.Get(pageURL)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"opencode", request.RepoRoot, "api.example.test", "repo", request.ID[:12], "navigator.credentials.get"} {
		if !bytes.Contains(body, []byte(want)) {
			t.Fatalf("approval page does not present %q", want)
		}
	}
}

func TestBrowserLoopbackFailurePath(t *testing.T) {
	agentBrowser, err := exec.LookPath("agent-browser")
	if err != nil {
		t.Skip("agent-browser is not installed")
	}
	setStateHome(t, t.TempDir())
	broker := approval.New()
	request, err := broker.Create(request())
	if err != nil {
		t.Fatal(err)
	}
	browser, pageURL, err := approval.StartBrowser(broker, browserStore(t), request.ID)
	if err != nil {
		t.Fatal(err)
	}
	defer browser.Close()

	session := "guardrail-" + request.ID[:12]
	t.Cleanup(func() { _ = exec.Command(agentBrowser, "--session", session, "close").Run() })
	if output, err := exec.Command(agentBrowser, "--session", session, "open", pageURL).CombinedOutput(); err != nil {
		t.Fatalf("open approval page: %v\n%s", err, output)
	}
	if output, err := exec.Command(agentBrowser, "--session", session, "eval", `navigator.credentials.get = () => Promise.reject(new DOMException("stubbed credential rejection", "NotAllowedError")); window.requestWebAuthnAssertion();`).CombinedOutput(); err != nil {
		t.Fatalf("stub WebAuthn credential request: %v\n%s", err, output)
	}
	if output, err := exec.Command(agentBrowser, "--session", session, "wait", "--text", "WebAuthn authentication was not completed (NotAllowedError)").CombinedOutput(); err != nil {
		t.Fatalf("wait for WebAuthn rejection: %v\n%s", err, output)
	}
	output, err := exec.Command(agentBrowser, "--session", session, "read").CombinedOutput()
	if err != nil {
		t.Fatalf("read approval page: %v\n%s", err, output)
	}
	for _, want := range []string{"opencode", request.RepoRoot, "api.example.test", "WebAuthn authentication was not completed (NotAllowedError)"} {
		if !bytes.Contains(output, []byte(want)) {
			t.Fatalf("browser page does not present %q", want)
		}
	}
	stored, err := broker.Request(request.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Status != "pending" {
		t.Fatalf("request status after browser without a credential = %q, want pending", stored.Status)
	}
}
