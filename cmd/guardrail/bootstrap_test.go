package main

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/CtrlCarlitos/agent-guardrails/internal/audit"
	"github.com/CtrlCarlitos/agent-guardrails/internal/testenv"
)

// recordAudits captures every record the action-audit seam receives.
func recordAudits(t *testing.T) *[]audit.Record {
	t.Helper()
	var seen []audit.Record
	orig := writeActionAudit
	t.Cleanup(func() { writeActionAudit = orig })
	writeActionAudit = func(rec audit.Record, _ string) error {
		seen = append(seen, rec)
		return nil
	}
	return &seen
}

const (
	wantBootstrapArmed   = "planes armed without an approval because no operator authenticator is enrolled."
	wantBootstrapControl = "run 'guardrail operator enroll' from a real terminal to take control; every later plane change needs your passkey."
)

func TestBootstrapAuditRecordShape(t *testing.T) {
	seen := recordAudits(t)
	if err := writeBootstrapAudit([]string{"claude", "codex"}); err != nil {
		t.Fatal(err)
	}
	if len(*seen) != 1 {
		t.Fatalf("audit records = %d, want 1", len(*seen))
	}
	rec := (*seen)[0]
	want := audit.Record{Plane: "operator", Tool: "guardrail", Event: "operator-action", Decision: "completed", OperatorAction: "plane-enable", Transport: "bootstrap", Reason: "bootstrap: no operator enrolled; planes claude,codex"}
	if !reflect.DeepEqual(rec, want) {
		t.Fatalf("bootstrap record = %+v\nwant %+v", rec, want)
	}
}

func TestSetupBootstrapsWhenNoOperatorEnrolled(t *testing.T) {
	driftSandbox(t)
	useInstalledPlanes(t, "claude", "codex")
	stubOperatorEnrolled(t, false)
	refuseSubmits(t)
	calls := stubSetupGates(t, false, 0, 0)
	seen := recordAudits(t)

	code, out, errb := runSetup(t)
	if code != 0 {
		t.Fatalf("exit = %d, want 0; stdout=%q stderr=%q", code, out, errb)
	}
	for _, plane := range []string{"claude", "codex"} {
		if !planeIntegrationRegistered(plane) {
			t.Fatalf("%s not registered on disk after bootstrap", plane)
		}
		if !strings.Contains(out, plane+" enabled (bootstrap: no operator enrolled)\n") {
			t.Fatalf("stdout missing the %s bootstrap line:\n%s", plane, out)
		}
	}
	if strings.Contains(out, "approval required") {
		t.Fatalf("bootstrap prompted for an approval:\n%s", out)
	}
	if calls.selftest != 1 {
		t.Fatalf("selftest calls = %d, want 1", calls.selftest)
	}
	lines := stdoutLines(out)
	status := indexOfLine(lines, func(l string) bool { return l == "setup: plane status" })
	armed := indexOfLine(lines, func(l string) bool { return l == "setup: "+wantBootstrapArmed })
	control := indexOfLine(lines, func(l string) bool { return l == "setup: "+wantBootstrapControl })
	codex := indexOfLine(lines, func(l string) bool {
		return l == "setup: for Codex, run /hooks inside Codex to review and trust the generated hooks; restart the agents you wired."
	})
	if status < 0 || armed <= status || control <= armed || codex <= control {
		t.Fatalf("want status block, then armed, control, codex lines in order; got %d,%d,%d,%d in:\n%s", status, armed, control, codex, out)
	}
	if len(*seen) != 1 || (*seen)[0].Transport != "bootstrap" || (*seen)[0].OperatorAction != "plane-enable" {
		t.Fatalf("audit records = %+v, want one bootstrap plane-enable", *seen)
	}
	if strings.Contains((*seen)[0].Reason, "codex") == false || strings.Contains((*seen)[0].Reason, "claude") == false {
		t.Fatalf("audit reason does not name the planes: %q", (*seen)[0].Reason)
	}
}

func TestSetupBootstrapWithoutCodexOmitsCodexHint(t *testing.T) {
	driftSandbox(t)
	useInstalledPlanes(t, "claude")
	stubOperatorEnrolled(t, false)
	refuseSubmits(t)
	stubSetupGates(t, false, 0, 0)
	recordAudits(t)

	code, out, errb := runSetup(t)
	if code != 0 {
		t.Fatalf("exit = %d, want 0; stdout=%q stderr=%q", code, out, errb)
	}
	if strings.Contains(out, "/hooks inside Codex") {
		t.Fatalf("codex hint printed although codex was not armed:\n%s", out)
	}
	if !strings.Contains(out, "setup: restart the agents you wired.\n") {
		t.Fatalf("stdout missing the restart line:\n%s", out)
	}
}

// The bootstrap path hosts no ceremony, so it needs no terminal: an
// unattended first install arms the machine.
func TestSetupBootstrapSkipsTerminalGate(t *testing.T) {
	driftSandbox(t)
	useInstalledPlanes(t, "claude")
	stubOperatorEnrolled(t, false)
	refuseSubmits(t)
	stubSetupGates(t, false, 0, 0)
	recordAudits(t)

	var out, errb strings.Builder
	code := run([]string{"setup"}, strings.NewReader(""), &out, &errb)
	if code != 0 {
		t.Fatalf("exit = %d, want 0; stdout=%q stderr=%q", code, out.String(), errb.String())
	}
	if !planeIntegrationRegistered("claude") {
		t.Fatal("claude not registered after a non-terminal bootstrap")
	}
}

// Once an operator is enrolled the terminal gate is back, before anything
// touches the home directory.
func TestSetupEnrolledStillRequiresTerminal(t *testing.T) {
	home := t.TempDir()
	testenv.SetHome(t, home)
	testenv.SetConfig(t, t.TempDir())
	testenv.SetState(t, t.TempDir())
	stubOperatorEnrolled(t, true)

	var out, errb strings.Builder
	code := run([]string{"setup"}, strings.NewReader(""), &out, &errb)
	if code != 2 {
		t.Fatalf("exit = %d, want 2; stderr=%q", code, errb.String())
	}
	if !strings.Contains(errb.String(), "setup requires an interactive local terminal") {
		t.Fatalf("stderr = %q", errb.String())
	}
	entries, _ := os.ReadDir(home)
	if len(entries) != 0 {
		t.Fatalf("setup touched the sandboxed home before the terminal check: %v", entries)
	}
}

// Disabling is a loosening action: no terminal is still exit 2, and no
// enrollment is still exit 3, whatever the bootstrap does for enable.
func TestSetupDisableWithoutEnrollmentKeepsTerminalGate(t *testing.T) {
	driftSandbox(t)
	enableForDrift(t, "claude")
	useInstalledPlanes(t, "claude")
	stubOperatorEnrolled(t, false)
	refuseSubmits(t)

	var out, errb strings.Builder
	code := run([]string{"setup", "--state", "disabled"}, strings.NewReader(""), &out, &errb)
	if code != 2 {
		t.Fatalf("exit = %d, want 2; stderr=%q", code, errb.String())
	}
	if !planeIntegrationRegistered("claude") {
		t.Fatal("claude was unregistered without a terminal")
	}
}

func TestSetupBootstrapContinuesWhenAuditWriteFails(t *testing.T) {
	driftSandbox(t)
	useInstalledPlanes(t, "claude")
	stubOperatorEnrolled(t, false)
	refuseSubmits(t)
	stubSetupGates(t, false, 0, 0)
	orig := writeActionAudit
	t.Cleanup(func() { writeActionAudit = orig })
	writeActionAudit = func(audit.Record, string) error { return os.ErrPermission }

	code, out, errb := runSetup(t)
	if code != 0 {
		t.Fatalf("exit = %d, want 0; stdout=%q stderr=%q", code, out, errb)
	}
	if !planeIntegrationRegistered("claude") {
		t.Fatal("claude not registered when the audit write failed")
	}
	if !strings.Contains(errb, "guardrail: setup: bootstrap audit record not written: ") {
		t.Fatalf("stderr lacks the audit warning:\n%s", errb)
	}
}

func TestSetupBootstrapFailsWhenEnableFails(t *testing.T) {
	driftSandbox(t)
	useInstalledPlanes(t, "claude")
	stubOperatorEnrolled(t, false)
	refuseSubmits(t)
	calls := stubSetupGates(t, false, 0, 0)
	recordAudits(t)
	// A regular file where the plane's config directory must go makes the
	// merge fail without depending on permission semantics.
	home, _ := os.UserHomeDir()
	if err := os.WriteFile(filepath.Join(home, ".claude"), []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}

	code, out, errb := runSetup(t)
	if code != 1 {
		t.Fatalf("exit = %d, want 1; stdout=%q stderr=%q", code, out, errb)
	}
	if !strings.Contains(errb, "guardrail: setup: claude: ") {
		t.Fatalf("stderr lacks the per-plane failure:\n%s", errb)
	}
	if calls.selftest != 0 {
		t.Fatalf("selftest ran after a failed bootstrap (%d calls)", calls.selftest)
	}
}

func TestPlaneEnableBootstrapsWhenNoOperatorEnrolled(t *testing.T) {
	home := t.TempDir()
	testenv.SetHome(t, home)
	testenv.SetConfig(t, filepath.Join(home, ".config"))
	testenv.SetState(t, t.TempDir())
	stubOperatorEnrolled(t, false)
	refuseSubmits(t)
	seen := recordAudits(t)

	var out, errb strings.Builder
	code := runPlaneTerminal(t, []string{"plane", "enable", "claude"}, &out, &errb)
	if code != 0 {
		t.Fatalf("exit = %d, want 0; stdout=%q stderr=%q", code, out.String(), errb.String())
	}
	if !planeIntegrationRegistered("claude") {
		t.Fatal("claude not registered after bootstrap")
	}
	if !strings.Contains(out.String(), "claude enabled (bootstrap: no operator enrolled)\n") || !strings.Contains(out.String(), "plane enable: "+wantBootstrapControl) {
		t.Fatalf("stdout lacks the bootstrap lines:\n%s", out.String())
	}
	if len(*seen) != 1 || (*seen)[0].Transport != "bootstrap" {
		t.Fatalf("audit records = %+v, want one bootstrap record", *seen)
	}
}

func TestPlaneEnableBootstrapSkipsTerminalGate(t *testing.T) {
	home := t.TempDir()
	testenv.SetHome(t, home)
	testenv.SetConfig(t, filepath.Join(home, ".config"))
	testenv.SetState(t, t.TempDir())
	stubOperatorEnrolled(t, false)
	refuseSubmits(t)
	recordAudits(t)

	var out, errb strings.Builder
	code := cmdPlane([]string{"enable", "claude"}, false, &out, &errb)
	if code != 0 {
		t.Fatalf("exit = %d, want 0; stderr=%q", code, errb.String())
	}
	if !planeIntegrationRegistered("claude") {
		t.Fatal("claude not registered after a non-terminal bootstrap")
	}
}

func TestPlaneDisableWithoutEnrollmentExitsNeedsEnrollment(t *testing.T) {
	home := t.TempDir()
	testenv.SetHome(t, home)
	testenv.SetConfig(t, filepath.Join(home, ".config"))
	testenv.SetState(t, t.TempDir())
	stubOperatorEnrolled(t, false)
	refuseSubmits(t)
	recordAudits(t)
	if err := enablePlaneIntegration("claude"); err != nil {
		t.Fatal(err)
	}

	var out, errb strings.Builder
	code := runPlaneTerminal(t, []string{"plane", "disable", "claude"}, &out, &errb)
	if code != exitNotEnrolled {
		t.Fatalf("exit = %d, want %d; stderr=%q", code, exitNotEnrolled, errb.String())
	}
	if !planeIntegrationRegistered("claude") {
		t.Fatal("claude was unregistered without an approval")
	}
	code = cmdPlane([]string{"disable", "claude"}, false, &out, &errb)
	if code != 2 {
		t.Fatalf("non-terminal disable exit = %d, want 2", code)
	}
}

func TestOperatorApprovalStatusWording(t *testing.T) {
	cases := []struct {
		enrolled, armed bool
		want            string
	}{
		{true, true, "operator approvals: WebAuthn"},
		{true, false, "operator approvals: WebAuthn"},
		{false, true, "operator approvals: disabled (no authenticator enrolled; planes armed by bootstrap; run guardrail operator enroll)"},
		{false, false, "operator approvals: disabled (no authenticator enrolled; run guardrail operator enroll)"},
	}
	for _, c := range cases {
		if got := operatorApprovalStatus(c.enrolled, c.armed); got != c.want {
			t.Errorf("operatorApprovalStatus(%v, %v) = %q, want %q", c.enrolled, c.armed, got, c.want)
		}
	}
}

func TestDoctorReportsBootstrapArmedPlanes(t *testing.T) {
	home := t.TempDir()
	testenv.SetHome(t, home)
	testenv.SetConfig(t, filepath.Join(home, ".config"))
	testenv.SetState(t, filepath.Join(home, "state"))
	t.Setenv("GUARDRAIL_CONFIG", "")
	if err := enablePlaneIntegration("claude"); err != nil {
		t.Fatal(err)
	}

	var out, errb strings.Builder
	if code := run([]string{"doctor"}, strings.NewReader(""), &out, &errb); code != 0 {
		t.Fatalf("doctor exit = %d, want 0; stderr=%q", code, errb.String())
	}
	if !strings.Contains(out.String(), "operator approvals: disabled (no authenticator enrolled; planes armed by bootstrap; run guardrail operator enroll)") {
		t.Fatalf("doctor output lacks the bootstrap line:\n%s", out.String())
	}
}
