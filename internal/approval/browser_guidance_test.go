package approval_test

import (
	"io"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/CtrlCarlitos/agent-guardrails/internal/approval"
)

// The approval page starts the WebAuthn request the moment it loads, so an
// operator meets a small system dialog with no page around it. On a machine with
// two guardrail instances (Windows and WSL) that share the rpId `localhost`, and
// with a phone/QR option the browser offers unconditionally, that cost an
// operator a day (#383): scanning the QR code "linked", and the phone then said
// "No passkeys available", because a passkey for localhost lives only where it
// was created. The page now says what it is, whose it is, and what to do.

func approvalPage(t *testing.T) string {
	t.Helper()
	setStateHome(t, t.TempDir())
	broker := approval.New()
	r, err := broker.Create(request())
	if err != nil {
		t.Fatal(err)
	}
	browser, origin, err := approval.StartBrowser(broker, browserStore(t), r.ID)
	if err != nil {
		t.Fatal(err)
	}
	defer browser.Close()
	response, err := http.Get(origin + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

func TestApprovalPageNamesTheGuardrailInstanceThatIsAsking(t *testing.T) {
	t.Setenv("WSL_DISTRO_NAME", "")
	host, _ := os.Hostname()
	page := approvalPage(t)
	if !strings.Contains(page, "Guardrail instance") || !strings.Contains(page, host) {
		t.Fatalf("the page does not name the host that is asking (%q):\n%s", host, page)
	}
}

func TestApprovalPageSaysWhenTheInstanceIsWSL(t *testing.T) {
	t.Setenv("WSL_DISTRO_NAME", "Ubuntu-24.04")
	if page := approvalPage(t); !strings.Contains(page, "WSL Ubuntu-24.04") {
		t.Fatalf("the page does not say it is a WSL instance:\n%s", page)
	}
}

// What an operator needs before the dialog appears, and after it fails.
func TestApprovalPageExplainsLocalhostPasskeysAndHowToRecover(t *testing.T) {
	page := approvalPage(t)
	for _, want := range []string{
		"Passkeys for localhost",
		"phone",
		"guardrail operator recover-reset",
		"guardrail operator enroll",
		"No enrolled authenticator responded",
	} {
		if !strings.Contains(page, want) {
			t.Errorf("the page lacks %q:\n%s", want, page)
		}
	}
}

func TestApprovalPageStillRunsTheWebAuthnRequestAndKeepsItsOptions(t *testing.T) {
	page := approvalPage(t)
	for _, want := range []string{"navigator.credentials.get", "allowCredentials", "requestWebAuthnAssertion"} {
		if !strings.Contains(page, want) {
			t.Errorf("the page lost %q:\n%s", want, page)
		}
	}
}
