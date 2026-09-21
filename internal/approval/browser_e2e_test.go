package approval_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"os"
	"os/exec"
	"testing"
	"time"

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

// agentBrowserSink creates the file a step's output is written to.
//
// Deliberately NOT under t.TempDir(): the browser `open` launches inherits
// this handle and keeps it open, and Windows refuses to unlink a file that is
// still in use, so the framework's own cleanup fails the test. Removal is
// therefore best-effort — in the common case the process has exited and the
// file goes immediately; when a browser still holds it, one small log is left
// in the OS temp directory, which is the trade this buys the fix with.
func agentBrowserSink(t *testing.T, step string) *os.File {
	t.Helper()
	sink, err := os.CreateTemp("", "guardrail-agent-browser-"+step+"-*.log")
	if err != nil {
		t.Fatalf("create output sink: %v", err)
	}
	t.Cleanup(func() {
		_ = sink.Close()
		_ = os.Remove(sink.Name())
	})
	return sink
}

// agentBrowserStepTimeout bounds one agent-browser subcommand.
//
// Every step below drives a real browser through an external CLI, and none of
// them was bounded. On a host where the CLI is installed and a browser
// launches, a step could block forever and take the whole package down with
// the default ten-minute test timeout, surfacing as a goroutine dump rather
// than a named failure (#199). Generous enough for a browser to start, short
// enough that a stuck step is a test failure and not a stalled suite.
const agentBrowserStepTimeout = 30 * time.Second

// runAgentBrowserStep runs one agent-browser subcommand under a deadline and
// fails with a diagnostic naming the step that stuck.
//
// Two independent bounds, because the original had neither and they fail
// differently: the context kills a step that genuinely runs too long, and
// WaitDelay covers the case where the process is gone but an inherited handle
// is not. Neither is the primary fix — the output sink below is — but a test
// that drives an external browser should not be able to outlive its own
// timeout by any route.
func runAgentBrowserStep(t *testing.T, bin, session, step string, args ...string) []byte {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), agentBrowserStepTimeout)
	defer cancel()

	// Output goes to a file, not a pipe. CombinedOutput gives the child a pipe
	// and then waits for every writer to close it; `agent-browser open`
	// launches a browser that inherits those handles and keeps running, so the
	// wait never ends — measured as `WaitDelay expired before I/O complete` on
	// the open step, and before that as a ten-minute hang. A file handle is
	// inherited just as happily and has nothing to wait on, so Wait returns
	// when the process does.
	sink := agentBrowserSink(t, step)

	cmd := exec.CommandContext(ctx, bin, append([]string{"--session", session}, args...)...)
	cmd.Stdout, cmd.Stderr = sink, sink
	cmd.WaitDelay = 5 * time.Second
	runErr := cmd.Run()

	output, readErr := os.ReadFile(sink.Name())
	if readErr != nil {
		t.Fatalf("read agent-browser %s output: %v", step, readErr)
	}
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		t.Fatalf("agent-browser %s did not finish within %s; a browser step is stuck on this host: %s",
			step, agentBrowserStepTimeout, output)
	}
	if runErr != nil {
		t.Fatalf("agent-browser %s: %v\n%s", step, runErr, output)
	}
	return output
}

// requireBrowserLaunch runs the `open` step, treating "no browser on this
// host" as a missing precondition rather than a failure.
//
// agent-browser being installed does not mean a browser is: on Linux the CLI
// is present and reports `Auto-launch failed: Chrome not found`, which is the
// same class of fact as the LookPath skip above and should read the same way.
// The check is deliberately narrow — only this step, only a launch failure —
// because a broad "skip when the browser misbehaves" would hide exactly the
// failures this test exists to catch.
func requireBrowserLaunch(t *testing.T, bin, session, pageURL string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), agentBrowserStepTimeout)
	defer cancel()
	sink := agentBrowserSink(t, "open")

	cmd := exec.CommandContext(ctx, bin, "--session", session, "open", pageURL)
	cmd.Stdout, cmd.Stderr = sink, sink
	cmd.WaitDelay = 5 * time.Second
	runErr := cmd.Run()
	output, _ := os.ReadFile(sink.Name())

	if runErr != nil && bytes.Contains(output, []byte("Auto-launch failed")) {
		t.Skipf("no browser available to agent-browser on this host, so the WebAuthn loopback failure path is NOT covered here: %s", output)
	}
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		t.Fatalf("agent-browser open did not finish within %s; a browser step is stuck on this host: %s",
			agentBrowserStepTimeout, output)
	}
	if runErr != nil {
		t.Fatalf("agent-browser open: %v\n%s", runErr, output)
	}
}

func TestBrowserLoopbackFailurePath(t *testing.T) {
	agentBrowser, err := exec.LookPath("agent-browser")
	if err != nil {
		// No CI runner has agent-browser, so this skips everywhere it is
		// watched and runs only on a developer machine. Saying so keeps the
		// gap visible: a skip here is not evidence the loopback failure path
		// works, and before #199 this test could not have produced that
		// evidence anywhere — it hung on the hosts that did run it.
		t.Skip("agent-browser is not installed: the WebAuthn loopback failure path is NOT covered on this host")
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
	t.Cleanup(func() {
		closeCmd := exec.Command(agentBrowser, "--session", session, "close")
		closeCmd.WaitDelay = 5 * time.Second
		_ = closeCmd.Run()
	})
	requireBrowserLaunch(t, agentBrowser, session, pageURL)
	runAgentBrowserStep(t, agentBrowser, session, "eval", "eval",
		`navigator.credentials.get = () => Promise.reject(new DOMException("stubbed credential rejection", "NotAllowedError")); window.requestWebAuthnAssertion();`)
	runAgentBrowserStep(t, agentBrowser, session, "wait", "wait",
		"--text", "WebAuthn authentication was not completed (NotAllowedError)")
	output := runAgentBrowserStep(t, agentBrowser, session, "read", "read")
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
