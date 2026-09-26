package main

import (
	"strings"
	"testing"

	"github.com/CtrlCarlitos/agent-guardrails/internal/testenv"
)

// A change that needs a passkey approval needs a terminal to host the
// ceremony. With no terminal attached that is the operator's to fix, not a
// usage error, so `setup` and `plane enable|disable` exit 3 (operator action
// pending) and not 2. Exit 2 goes back to meaning only usage and unsupported
// platform, which lets an unattended caller (an installer, CI, a dotfiles
// apply) treat every "waiting on a human" outcome the same way (#364).
//
// Scope is exactly those two commands. operator, recover, web-research and
// approvals are interactive by nature, no unattended caller runs them, and
// they keep exit 2.

func sandboxHome(t *testing.T) {
	t.Helper()
	testenv.SetHome(t, t.TempDir())
	testenv.SetConfig(t, t.TempDir())
	testenv.SetState(t, t.TempDir())
}

func assertPendingNoTerminal(t *testing.T, code int, stderr string) {
	t.Helper()
	if code != exitOperatorActionPending {
		t.Fatalf("exit = %d, want %d (operator action pending); stderr=%q", code, exitOperatorActionPending, stderr)
	}
	for _, want := range []string{
		"requires an interactive local terminal",
		"operator action pending",
		"no interactive terminal is attached",
	} {
		if !strings.Contains(stderr, want) {
			t.Errorf("stderr missing %q:\n%s", want, stderr)
		}
	}
}

func TestSetupEnrolledWithoutATerminalExitsPending(t *testing.T) {
	sandboxHome(t)
	stubOperatorEnrolled(t, true)
	var out, errb strings.Builder
	// run() derives terminal from *os.File stdin; a strings.Reader is not one.
	code := run([]string{"setup"}, strings.NewReader(""), &out, &errb)
	assertPendingNoTerminal(t, code, errb.String())
	if !strings.Contains(errb.String(), "guardrail setup") {
		t.Errorf("stderr does not say how to finish:\n%s", errb.String())
	}
}

func TestSetupDisableWithoutATerminalExitsPending(t *testing.T) {
	sandboxHome(t)
	stubOperatorEnrolled(t, false)
	var out, errb strings.Builder
	code := run([]string{"setup", "--state", "disabled"}, strings.NewReader(""), &out, &errb)
	assertPendingNoTerminal(t, code, errb.String())
}

func TestPlaneEnableAndDisableEnrolledWithoutATerminalExitPending(t *testing.T) {
	for _, verb := range []string{"enable", "disable"} {
		t.Run(verb, func(t *testing.T) {
			sandboxHome(t)
			stubOperatorEnrolled(t, true)
			var out, errb strings.Builder
			code := run([]string{"plane", verb, "claude"}, strings.NewReader(""), &out, &errb)
			assertPendingNoTerminal(t, code, errb.String())
		})
	}
}

// The first-install bootstrap needs no terminal and still exits 0.
func TestPlaneEnableWithoutEnrollmentStillBootstrapsWithoutATerminal(t *testing.T) {
	driftSandbox(t)
	useInstalledPlanes(t, "claude")
	stubOperatorEnrolled(t, false)
	refuseSubmits(t)
	recordAudits(t)
	var out, errb strings.Builder
	if code := run([]string{"plane", "enable", "claude"}, strings.NewReader(""), &out, &errb); code != 0 {
		t.Fatalf("exit = %d, want 0 (bootstrap); stderr=%q", code, errb.String())
	}
}

// Usage errors are still 2: the code no longer doubles as "no terminal".
func TestUsageErrorsStillExitTwo(t *testing.T) {
	sandboxHome(t)
	stubOperatorEnrolled(t, true)
	for name, args := range map[string][]string{
		"unknown setup flag": {"setup", "--bogus"},
		"unknown plane":      {"plane", "enable", "emacs"},
		"missing plane":      {"plane", "enable"},
	} {
		var out, errb strings.Builder
		if code := run(args, strings.NewReader(""), &out, &errb); code != 2 {
			t.Errorf("%s: exit = %d, want 2; stderr=%q", name, code, errb.String())
		}
	}
}

// Out of scope on purpose: these are interactive by nature and no unattended
// caller runs them, so they keep the documented usage code.
func TestOtherInteractiveCommandsKeepExitTwoWithoutATerminal(t *testing.T) {
	sandboxHome(t)
	stubOperatorEnrolled(t, true)
	for name, args := range map[string][]string{
		"operator enroll":   {"operator", "enroll"},
		"recover":           {"recover", "claude-settings"},
		"web-research on":   {"web-research", "on"},
		"approvals grant":   {"approvals", "grant"},
		"approvals approve": {"approvals", "approve", "x"},
	} {
		var out, errb strings.Builder
		code := run(args, strings.NewReader(""), &out, &errb)
		if code == exitOperatorActionPending {
			t.Errorf("%s: exit = %d; this command is out of scope and must keep exit 2 (stderr=%q)", name, code, errb.String())
		}
	}
}
