package main

import (
	"errors"
	"strings"
	"testing"

	"github.com/CtrlCarlitos/agent-guardrails/internal/approval"
)

// An unattended caller (a dotfiles apply, CI, a provisioning script) has to
// tell "the binary is installed, the re-wiring waits for the operator" from a
// real failure. Both used to exit 1, so the caller grepped the log for the
// phrase "approval request" (#364). Exit 3 now means operator action pending,
// and only that.

func stubApprovalSubmit(t *testing.T, err error) {
	t.Helper()
	orig := submitPlaneRequest
	t.Cleanup(func() { submitPlaneRequest = orig })
	submitPlaneRequest = func(approval.Request) (approval.Request, error) {
		return approval.Request{}, err
	}
	origShutdown := setupShutdownDaemon
	t.Cleanup(func() { setupShutdownDaemon = origShutdown })
	setupShutdownDaemon = func(string) error { return nil }
}

func TestSetupExitsPendingWhenTheApprovalDaemonIsUnreachable(t *testing.T) {
	driftSandbox(t)
	useInstalledPlanes(t, "claude")
	stubOperatorEnrolled(t, true)
	stubSetupGates(t, false, 0, 0)
	stubApprovalSubmit(t, approval.ErrDaemonUnavailable)

	code, _, errb := runSetup(t)
	if code != exitOperatorActionPending {
		t.Fatalf("exit = %d, want %d (operator action pending); stderr=%q", code, exitOperatorActionPending, errb)
	}
	for _, want := range []string{
		"operator action pending",
		"the approval daemon is not running",
		"keeps enforcing",
		"interactive terminal",
		"guardrail setup",
		"passkey",
	} {
		if !strings.Contains(errb, want) {
			t.Errorf("stderr missing %q:\n%s", want, errb)
		}
	}
}

func TestSetupExitsPendingWhenTheOperatorDeniesOrTheApprovalExpires(t *testing.T) {
	for name, statuses := range map[string][]string{
		"denied":  {"denied"},
		"expired": {"expired"},
		"timeout": {},
	} {
		t.Run(name, func(t *testing.T) {
			driftSandbox(t)
			useInstalledPlanes(t, "claude")
			stubSetupGates(t, false, 0, 0)
			useTransport(t, statuses)

			code, _, errb := runSetup(t)
			if code != exitOperatorActionPending {
				t.Fatalf("exit = %d, want %d; stderr=%q", code, exitOperatorActionPending, errb)
			}
			if !strings.Contains(errb, "operator action pending") {
				t.Errorf("stderr does not say the operator has to act:\n%s", errb)
			}
		})
	}
}

// A request that fails for any other reason is a failure. Exit 1 stays exit 1,
// or the distinction is worthless.
func TestSetupStillExitsOneOnAGenuineApprovalFailure(t *testing.T) {
	driftSandbox(t)
	useInstalledPlanes(t, "claude")
	stubOperatorEnrolled(t, true)
	stubSetupGates(t, false, 0, 0)
	stubApprovalSubmit(t, errors.New("request rejected: malformed"))

	code, _, errb := runSetup(t)
	if code != 1 {
		t.Fatalf("exit = %d, want 1; stderr=%q", code, errb)
	}
	if strings.Contains(errb, "operator action pending") {
		t.Errorf("a genuine failure was reported as pending:\n%s", errb)
	}
}

func TestPlaneEnableExitsPendingWhenTheApprovalDaemonIsUnreachable(t *testing.T) {
	driftSandbox(t)
	useInstalledPlanes(t, "claude")
	stubOperatorEnrolled(t, true)
	stubApprovalSubmit(t, approval.ErrDaemonUnavailable)

	var out, errb strings.Builder
	code := runPlaneTerminal(t, []string{"plane", "enable", "claude"}, &out, &errb)
	if code != exitOperatorActionPending {
		t.Fatalf("exit = %d, want %d; stderr=%q", code, exitOperatorActionPending, errb.String())
	}
	if !strings.Contains(errb.String(), "operator action pending") {
		t.Errorf("stderr does not say the operator has to act:\n%s", errb.String())
	}
}
