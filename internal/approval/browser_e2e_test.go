package approval_test

import (
	"bytes"
	"io"
	"net/http"
	"os/exec"
	"testing"

	"github.com/CtrlCarlitos/agent-guardrails/internal/approval"
)

func TestBrowserRejectsMissingAssertionWithoutCompleting(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
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

func TestBrowserPagePresentsCanonicalRequest(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
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
	for _, want := range []string{"opencode", "/repo", "api.example.test", "repo", "navigator.credentials.get"} {
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
	t.Setenv("XDG_STATE_HOME", t.TempDir())
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
	output, err := exec.Command(agentBrowser, "--session", session, "read").CombinedOutput()
	if err != nil {
		t.Fatalf("read approval page: %v\n%s", err, output)
	}
	for _, want := range []string{"opencode", "/repo", "api.example.test"} {
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
