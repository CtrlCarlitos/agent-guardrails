package main

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/CtrlCarlitos/agent-guardrails/internal/approval"
	"github.com/CtrlCarlitos/agent-guardrails/internal/testenv"
)

// stubOperatorEnrolled fixes what the enrollment preflight sees (#326).
func stubOperatorEnrolled(t *testing.T, enrolled bool) {
	t.Helper()
	orig := operatorEnrolled
	t.Cleanup(func() { operatorEnrolled = orig })
	operatorEnrolled = func() bool { return enrolled }
}

// refuseSubmits fails the test if any approval request is submitted.
func refuseSubmits(t *testing.T) {
	t.Helper()
	orig := submitPlaneRequest
	t.Cleanup(func() { submitPlaneRequest = orig })
	submitPlaneRequest = func(request approval.Request) (approval.Request, error) {
		t.Fatalf("submitted an approval that cannot succeed: %+v", request)
		return approval.Request{}, nil
	}
}

const wantEnrollHint = "no operator authenticator is enrolled; run 'guardrail operator enroll'"

// A machine that has nothing to (re)register needs no approval, so it needs
// no enrollment either: unattended re-runs of the installer stay exit 0.
func TestSetupSteadyStateNeedsNoEnrollment(t *testing.T) {
	driftSandbox(t)
	enableForDrift(t, "claude")
	useInstalledPlanes(t, "claude")
	stubOperatorEnrolled(t, false)
	refuseSubmits(t)
	stubSetupGates(t, false, 0, 0)

	code, out, errb := runSetup(t)
	if code != 0 {
		t.Fatalf("exit = %d, want 0; stdout=%q stderr=%q", code, out, errb)
	}
	if strings.Contains(errb, wantEnrollHint) {
		t.Fatalf("steady state demanded enrollment:\n%s", errb)
	}
}

func TestSetupDisableWithoutEnrollmentExitsNeedsEnrollment(t *testing.T) {
	driftSandbox(t)
	enableForDrift(t, "claude")
	useInstalledPlanes(t, "claude")
	stubOperatorEnrolled(t, false)
	refuseSubmits(t)
	stubSetupGates(t, false, 0, 0)

	code, out, errb := runSetup(t, "--state", "disabled")
	if code != exitNotEnrolled {
		t.Fatalf("exit = %d, want %d; stdout=%q stderr=%q", code, exitNotEnrolled, out, errb)
	}
	if !strings.Contains(errb, "then 'guardrail setup --state disabled'") {
		t.Fatalf("stderr lacks the disable re-run hint:\n%s", errb)
	}
	if !planeIntegrationRegistered("claude") {
		t.Fatal("claude was unregistered without an approval")
	}
}

// The daemon's own reason reaches the operator when the preflight and the
// daemon disagree (a store the daemon reads differently, a race with a
// recovery reset): never rewritten as "daemon unavailable".
func TestSetupPrintsDaemonReasonVerbatim(t *testing.T) {
	driftSandbox(t)
	useInstalledPlanes(t, "claude")
	stubOperatorEnrolled(t, true)
	stubSetupGates(t, false, 0, 0)
	orig := submitPlaneRequest
	t.Cleanup(func() { submitPlaneRequest = orig })
	submitPlaneRequest = func(approval.Request) (approval.Request, error) {
		return approval.Request{}, approval.ErrNotEnrolled
	}
	origShutdown := setupShutdownDaemon
	t.Cleanup(func() { setupShutdownDaemon = origShutdown })
	setupShutdownDaemon = func(string) error { return nil }

	code, _, errb := runSetup(t)
	if code != 1 {
		t.Fatalf("exit = %d, want 1; stderr=%q", code, errb)
	}
	if !strings.Contains(errb, "claude: approval request failed: no operator authenticator is enrolled") {
		t.Fatalf("stderr lacks the daemon's reason:\n%s", errb)
	}
	if strings.Contains(errb, "approval daemon unavailable") {
		t.Fatalf("stderr rewrote the daemon's reason:\n%s", errb)
	}
}

func TestRecoverWithoutEnrollmentExitsNeedsEnrollment(t *testing.T) {
	home := t.TempDir()
	testenv.SetHome(t, home)
	testenv.SetConfig(t, filepath.Join(home, ".config"))
	testenv.SetState(t, t.TempDir())
	stubOperatorEnrolled(t, false)
	refuseSubmits(t)

	var out, errb strings.Builder
	code := cmdRecover([]string{"claude-settings"}, true, &out, &errb)
	if code != exitNotEnrolled {
		t.Fatalf("exit = %d, want %d; stdout=%q stderr=%q", code, exitNotEnrolled, out.String(), errb.String())
	}
	if !strings.Contains(errb.String(), "then 'guardrail recover claude-settings'") {
		t.Fatalf("stderr lacks the recover re-run hint:\n%s", errb.String())
	}
}

func TestUsageDocumentsEnrollmentExitCode(t *testing.T) {
	var out, errb strings.Builder
	if code := run([]string{"help"}, strings.NewReader(""), &out, &errb); code != 0 {
		t.Fatalf("exit = %d, want 0", code)
	}
	if !strings.Contains(out.String(), "exit 3") {
		t.Fatalf("usage does not document exit 3 for a missing enrollment:\n%s", out.String())
	}
}
