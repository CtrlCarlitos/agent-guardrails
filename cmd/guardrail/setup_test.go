package main

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/CtrlCarlitos/agent-guardrails/internal/approval"
	"github.com/CtrlCarlitos/agent-guardrails/internal/genconfig"
	"github.com/CtrlCarlitos/agent-guardrails/internal/testenv"
)

func TestSetupRequiresInteractiveTerminal(t *testing.T) {
	home := t.TempDir()
	testenv.SetHome(t, home)
	testenv.SetConfig(t, t.TempDir())
	testenv.SetState(t, t.TempDir())

	var out, errb strings.Builder
	// run() derives terminal from *os.File stdin; a strings.Reader is not one.
	code := run([]string{"setup"}, strings.NewReader(""), &out, &errb)
	if code != 2 {
		t.Fatalf("exit = %d, want 2", code)
	}
	const want = "guardrail: setup requires an interactive local terminal (run it from your shell, not from an agent or CI)"
	if !strings.Contains(errb.String(), want) {
		t.Fatalf("stderr = %q, want to contain %q", errb.String(), want)
	}

	var found []string
	if err := filepath.Walk(home, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if path != home && !info.IsDir() {
			found = append(found, path)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(found) != 0 {
		t.Fatalf("setup touched the sandboxed home before the terminal check: %v", found)
	}
}

func TestSetupRejectsBadState(t *testing.T) {
	testenv.SetHome(t, t.TempDir())
	testenv.SetConfig(t, t.TempDir())
	testenv.SetState(t, t.TempDir())
	guardTestHome(t)

	var out, errb strings.Builder
	code := cmdSetup([]string{"--state", "maybe"}, true, &out, &errb)
	if code != 2 {
		t.Fatalf("exit = %d, want 2", code)
	}
	const want = `guardrail: setup --state must be enabled or disabled`
	if !strings.Contains(errb.String(), want) {
		t.Fatalf("stderr = %q, want to contain %q", errb.String(), want)
	}
}

func TestSetupRejectsUnsupportedPlane(t *testing.T) {
	testenv.SetHome(t, t.TempDir())
	testenv.SetConfig(t, t.TempDir())
	testenv.SetState(t, t.TempDir())
	guardTestHome(t)

	var out, errb strings.Builder
	code := cmdSetup([]string{"--planes", "claude,gemini"}, true, &out, &errb)
	if code != 2 {
		t.Fatalf("exit = %d, want 2", code)
	}
	const want = `unsupported plane "gemini"`
	if !strings.Contains(errb.String(), want) {
		t.Fatalf("stderr = %q, want to contain %q", errb.String(), want)
	}
}

func TestSetupRejectsUnknownFlag(t *testing.T) {
	testenv.SetHome(t, t.TempDir())
	testenv.SetConfig(t, t.TempDir())
	testenv.SetState(t, t.TempDir())
	guardTestHome(t)

	var out, errb strings.Builder
	code := cmdSetup([]string{"--verbose"}, true, &out, &errb)
	if code != 2 {
		t.Fatalf("exit = %d, want 2", code)
	}
	const want = `unknown flag "--verbose"`
	if !strings.Contains(errb.String(), want) {
		t.Fatalf("stderr = %q, want to contain %q", errb.String(), want)
	}
}

func TestSetupRefusesStagingPath(t *testing.T) {
	testenv.SetHome(t, t.TempDir())
	testenv.SetConfig(t, t.TempDir())
	testenv.SetState(t, t.TempDir())
	guardTestHome(t)

	tmp := t.TempDir()
	origInstalled := installedExecutable
	defer func() { installedExecutable = origInstalled }()

	installedExecutable = func() (string, error) { return filepath.Join(tmp, ".guardrail-update"), nil }
	var out, errb strings.Builder
	if code := cmdSetup(nil, true, &out, &errb); code != 2 {
		t.Fatalf("exit = %d, want 2", code)
	} else if !strings.Contains(errb.String(), "refuses to register a staging or superseded binary path") {
		t.Fatalf("stderr = %q, want staging refusal", errb.String())
	}

	oldName := testenv.ExecutableName("guardrail") + ".old"
	installedExecutable = func() (string, error) { return filepath.Join(tmp, oldName), nil }
	out.Reset()
	errb.Reset()
	if code := cmdSetup(nil, true, &out, &errb); code != 2 {
		t.Fatalf("exit = %d, want 2", code)
	} else if !strings.Contains(errb.String(), "refuses to register a staging or superseded binary path") {
		t.Fatalf("stderr = %q, want staging refusal", errb.String())
	}
}

func TestSetupPrintsRegisteredPathFirst(t *testing.T) {
	driftSandbox(t)

	tmp := t.TempDir()
	path := filepath.Join(tmp, "bin", "guardrail")

	origInstalled := installedExecutable
	origPlaneInstalled := planeInstalled
	defer func() {
		installedExecutable = origInstalled
		planeInstalled = origPlaneInstalled
	}()
	installedExecutable = func() (string, error) { return path, nil }
	planeInstalled = func(string) bool { return false }
	stubSetupGates(t, false, 0, 0)

	var out, errb strings.Builder
	code := cmdSetup(nil, true, &out, &errb)
	if code != 0 {
		t.Fatalf("exit = %d, want 0; stderr=%q", code, errb.String())
	}
	lines := strings.SplitN(out.String(), "\n", 2)
	want := "setup: registering " + path
	if lines[0] != want {
		t.Fatalf("first stdout line = %q, want %q", lines[0], want)
	}
}

func TestUsageMentionsSetup(t *testing.T) {
	var out, errb strings.Builder
	if code := run([]string{"help"}, strings.NewReader(""), &out, &errb); code != 0 {
		t.Fatalf("exit = %d, want 0", code)
	}
	if !strings.Contains(out.String(), "setup [flags]") {
		t.Fatalf("usage does not mention setup [flags]:\n%s", out.String())
	}
}

// gateCalls records how often the setup gate seams ran.
type gateCalls struct {
	doctor   int
	selftest int
}

// stubSetupGates replaces the three setup seams so no test ever runs the
// real doctor or selftest; agy reports presence, the gates return the codes.
func stubSetupGates(t *testing.T, agy bool, doctorCode, selftestCode int) *gateCalls {
	t.Helper()
	calls := &gateCalls{}
	origAgy, origDoctor, origSelftest := setupAgyPresent, setupDoctorCoverage, setupSelftest
	t.Cleanup(func() {
		setupAgyPresent, setupDoctorCoverage, setupSelftest = origAgy, origDoctor, origSelftest
	})
	setupAgyPresent = func() bool { return agy }
	setupDoctorCoverage = func(stdout, stderr io.Writer) int { calls.doctor++; return doctorCode }
	setupSelftest = func(stdout, stderr io.Writer) int { calls.selftest++; return selftestCode }
	return calls
}

// useInstalledPlanes makes planeInstalled report exactly the given planes.
func useInstalledPlanes(t *testing.T, planes ...string) {
	t.Helper()
	orig := planeInstalled
	t.Cleanup(func() { planeInstalled = orig })
	set := map[string]bool{}
	for _, p := range planes {
		set[p] = true
	}
	planeInstalled = func(plane string) bool { return set[plane] }
}

// useTransport installs stubPlaneTransport with the given statuses and
// restores it on cleanup.
func useTransport(t *testing.T, statuses []string) {
	t.Helper()
	t.Cleanup(stubPlaneTransport(t, statuses))
}

// countSubmits wraps the (stubbed) submitPlaneRequest to record every request.
func countSubmits(t *testing.T) *[]approval.Request {
	t.Helper()
	var seen []approval.Request
	inner := submitPlaneRequest
	t.Cleanup(func() { submitPlaneRequest = inner })
	submitPlaneRequest = func(r approval.Request) (approval.Request, error) {
		seen = append(seen, r)
		return inner(r)
	}
	return &seen
}

func runSetup(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var out, errb strings.Builder
	code := cmdSetup(args, true, &out, &errb)
	return code, out.String(), errb.String()
}

func stdoutLines(s string) []string {
	return strings.Split(strings.TrimRight(s, "\n"), "\n")
}

func indexOfLine(lines []string, pred func(string) bool) int {
	for i, l := range lines {
		if pred(l) {
			return i
		}
	}
	return -1
}

func TestSetupEnablesUnregisteredPlanes(t *testing.T) {
	driftSandbox(t)
	useInstalledPlanes(t, "claude")
	useTransport(t, []string{"approved"})
	calls := stubSetupGates(t, false, 0, 0)

	code, out, errb := runSetup(t)
	if code != 0 {
		t.Fatalf("exit = %d, want 0; stdout=%q stderr=%q", code, out, errb)
	}
	lines := stdoutLines(out)
	reason := indexOfLine(lines, func(l string) bool { return l == "claude: not registered; enabling" })
	prompt := indexOfLine(lines, func(l string) bool {
		return strings.HasSuffix(l, "approval required; open http://localhost:39169/approve")
	})
	enabled := indexOfLine(lines, func(l string) bool { return l == "claude enabled" })
	if reason < 0 || prompt <= reason || enabled <= prompt {
		t.Fatalf("want reason, prompt, enabled in order; got indexes %d,%d,%d in:\n%s", reason, prompt, enabled, out)
	}
	if !planeIntegrationRegistered("claude") {
		t.Fatal("claude not registered on disk after setup")
	}
	if calls.selftest != 1 {
		t.Fatalf("selftest calls = %d, want 1", calls.selftest)
	}
	if calls.doctor != 0 {
		t.Fatalf("doctor coverage calls = %d, want 0 (agy absent)", calls.doctor)
	}
}

func TestSetupSkipsConsistentPlanes(t *testing.T) {
	driftSandbox(t)
	enableForDrift(t, "claude")
	useInstalledPlanes(t, "claude")
	useTransport(t, nil)
	stubSetupGates(t, false, 0, 0)

	code, out, errb := runSetup(t)
	if code != 0 {
		t.Fatalf("exit = %d, want 0; stdout=%q stderr=%q", code, out, errb)
	}
	if !strings.Contains(out, "claude: already enabled\n") {
		t.Fatalf("stdout missing already-enabled line:\n%s", out)
	}
	if strings.Contains(out, "approval required") {
		t.Fatalf("consistent plane prompted for approval:\n%s", out)
	}
}

func TestSetupReenablesOnHandlerDrift(t *testing.T) {
	a, b := driftSandbox(t)
	enableForDrift(t, "claude")
	useInstalledExecutable(t, b)
	useInstalledPlanes(t, "claude")
	useTransport(t, []string{"approved"})
	stubSetupGates(t, false, 0, 0)

	code, out, errb := runSetup(t)
	if code != 0 {
		t.Fatalf("exit = %d, want 0; stdout=%q stderr=%q", code, out, errb)
	}
	if !strings.Contains(out, "claude: registered handlers differ from this binary; re-enabling\n") {
		t.Fatalf("stdout missing handler-drift line:\n%s", out)
	}
	if !strings.Contains(out, "approval required") {
		t.Fatalf("handler drift did not prompt:\n%s", out)
	}
	path, err := planeConfigPath("claude")
	if err != nil {
		t.Fatal(err)
	}
	settings := readPlaneJSON(t, path)
	quote := func(p string) string { raw, _ := json.Marshal(p); return strings.Trim(string(raw), `"`) }
	if !strings.Contains(settings, quote(b)) {
		t.Fatalf("settings do not reference %s:\n%s", b, settings)
	}
	if strings.Contains(settings, quote(a)) {
		t.Fatalf("settings still reference %s:\n%s", a, settings)
	}
}

func TestSetupOneApprovalForTheBatch(t *testing.T) {
	driftSandbox(t)
	useInstalledPlanes(t, "claude", "antigravity")
	useTransport(t, []string{"approved"})
	seen := countSubmits(t)
	stubSetupGates(t, false, 0, 0)

	code, out, errb := runSetup(t)
	if code != 0 {
		t.Fatalf("exit = %d, want 0; stdout=%q stderr=%q", code, out, errb)
	}
	if len(*seen) != 1 {
		t.Fatalf("submitPlaneRequest calls = %d, want 1", len(*seen))
	}
	req := (*seen)[0]
	if req.Action != "plane-enable" {
		t.Fatalf("action = %q, want plane-enable", req.Action)
	}
	if got := req.Parameters["planes"]; got != "claude,antigravity" {
		t.Fatalf("planes = %q, want claude,antigravity", got)
	}
}

func TestSetupDeniedApprovalFails(t *testing.T) {
	driftSandbox(t)
	useInstalledPlanes(t, "claude")
	useTransport(t, []string{"denied"})
	calls := stubSetupGates(t, false, 0, 0)

	code, out, errb := runSetup(t)
	if code != 1 {
		t.Fatalf("exit = %d, want 1; stdout=%q stderr=%q", code, out, errb)
	}
	if calls.selftest != 0 {
		t.Fatalf("selftest calls = %d, want 0 after denial", calls.selftest)
	}
}

func TestSetupRunsAntigravityGateWhenAgyPresent(t *testing.T) {
	driftSandbox(t)
	useInstalledPlanes(t)
	useTransport(t, nil)
	calls := stubSetupGates(t, true, 0, 0)

	code, out, errb := runSetup(t)
	if code != 0 {
		t.Fatalf("exit = %d, want 0; stdout=%q stderr=%q", code, out, errb)
	}
	if calls.doctor != 1 {
		t.Fatalf("doctor coverage calls = %d, want 1", calls.doctor)
	}
}

func TestSetupFailsWhenAntigravityGateFails(t *testing.T) {
	driftSandbox(t)
	useInstalledPlanes(t)
	useTransport(t, nil)
	calls := stubSetupGates(t, true, 1, 0)

	code, out, errb := runSetup(t)
	if code != 1 {
		t.Fatalf("exit = %d, want 1; stdout=%q stderr=%q", code, out, errb)
	}
	if !strings.Contains(errb, "doctor --coverage antigravity failed (exit 1)") {
		t.Fatalf("stderr = %q, want coverage gate failure", errb)
	}
	if calls.selftest != 0 {
		t.Fatalf("selftest calls = %d, want 0 after gate failure", calls.selftest)
	}
}

func TestSetupFailsWhenSelftestFails(t *testing.T) {
	driftSandbox(t)
	useInstalledPlanes(t)
	useTransport(t, nil)
	stubSetupGates(t, false, 0, 1)

	code, out, errb := runSetup(t)
	if code != 1 {
		t.Fatalf("exit = %d, want 1; stdout=%q stderr=%q", code, out, errb)
	}
	if !strings.Contains(errb, "selftest failed on this binary") {
		t.Fatalf("stderr = %q, want selftest failure", errb)
	}
}

func TestSetupHonoursPlanesSubset(t *testing.T) {
	driftSandbox(t)
	useInstalledPlanes(t, supportedPlanes...)
	useTransport(t, []string{"approved"})
	stubSetupGates(t, false, 0, 0)

	code, out, errb := runSetup(t, "--planes", "opencode")
	if code != 0 {
		t.Fatalf("exit = %d, want 0; stdout=%q stderr=%q", code, out, errb)
	}
	lines := stdoutLines(out)
	marker := indexOfLine(lines, func(l string) bool { return l == "setup: plane status" })
	if marker < 0 {
		t.Fatalf("no plane status marker:\n%s", out)
	}
	var reasons []string
	for _, l := range lines[:marker] {
		if strings.HasSuffix(l, "; enabling") || strings.HasSuffix(l, "; re-enabling") ||
			strings.HasSuffix(l, ": already enabled") || strings.HasSuffix(l, ": not detected") {
			reasons = append(reasons, l)
		}
		if strings.HasPrefix(l, "claude:") {
			t.Fatalf("claude line before status marker with --planes opencode: %q", l)
		}
	}
	if len(reasons) != 1 || !strings.HasPrefix(reasons[0], "opencode:") {
		t.Fatalf("reason lines = %q, want exactly one opencode line", reasons)
	}
}

func TestSetupDisableRemovesRegisteredPlanes(t *testing.T) {
	driftSandbox(t)
	enableForDrift(t, "claude")
	enableForDrift(t, "antigravity")
	useInstalledPlanes(t, "claude", "antigravity")
	useTransport(t, []string{"approved"})
	seen := countSubmits(t)
	calls := stubSetupGates(t, false, 0, 0)

	code, out, errb := runSetup(t, "--state", "disabled")
	if code != 0 {
		t.Fatalf("exit = %d, want 0; stdout=%q stderr=%q", code, out, errb)
	}
	if planeIntegrationRegistered("claude") {
		t.Fatal("claude still registered after disable")
	}
	if planeIntegrationRegistered("antigravity") {
		t.Fatal("antigravity still registered after disable")
	}
	if calls.selftest != 0 {
		t.Fatalf("selftest calls = %d, want 0", calls.selftest)
	}
	if len(*seen) != 1 {
		t.Fatalf("submitPlaneRequest calls = %d, want 1", len(*seen))
	}
	req := (*seen)[0]
	if req.Action != "plane-disable" {
		t.Fatalf("action = %q, want plane-disable", req.Action)
	}
	if got := req.Parameters["planes"]; got != "claude,antigravity" {
		t.Fatalf("planes = %q, want claude,antigravity", got)
	}
}

func TestSetupDisableIsNoOpWhenNothingRegistered(t *testing.T) {
	driftSandbox(t)
	useInstalledPlanes(t, "claude")
	useTransport(t, nil)
	calls := stubSetupGates(t, false, 0, 0)

	code, out, errb := runSetup(t, "--state", "disabled")
	if code != 0 {
		t.Fatalf("exit = %d, want 0; stdout=%q stderr=%q", code, out, errb)
	}
	if !strings.Contains(out, "claude: already disabled\n") {
		t.Fatalf("stdout missing already-disabled line:\n%s", out)
	}
	if strings.Contains(out, "approval required") {
		t.Fatalf("no-op disable prompted for approval:\n%s", out)
	}
	if calls.selftest != 0 {
		t.Fatalf("selftest calls = %d, want 0", calls.selftest)
	}
}

func TestSetupDisableDeniedFails(t *testing.T) {
	driftSandbox(t)
	enableForDrift(t, "claude")
	useInstalledPlanes(t, "claude")
	useTransport(t, []string{"denied"})
	calls := stubSetupGates(t, false, 0, 0)

	code, out, errb := runSetup(t, "--state", "disabled")
	if code != 1 {
		t.Fatalf("exit = %d, want 1; stdout=%q stderr=%q", code, out, errb)
	}
	if !planeIntegrationRegistered("claude") {
		t.Fatal("claude no longer registered after denied disable")
	}
	if calls.selftest != 0 {
		t.Fatalf("selftest calls = %d, want 0", calls.selftest)
	}
}

func TestSetupPrintsPlaneStatusLast(t *testing.T) {
	driftSandbox(t)
	useInstalledPlanes(t, "claude")
	useTransport(t, []string{"approved"})
	stubSetupGates(t, false, 0, 0)

	code, out, errb := runSetup(t)
	if code != 0 {
		t.Fatalf("exit = %d, want 0; stdout=%q stderr=%q", code, out, errb)
	}
	want := []string{"setup: plane status"}
	for _, plane := range supportedPlanes {
		want = append(want, plane+": "+planeStatusState(plane))
	}
	lines := stdoutLines(out)
	if len(lines) < len(want) {
		t.Fatalf("stdout too short:\n%s", out)
	}
	tail := lines[len(lines)-len(want):]
	for i := range want {
		if tail[i] != want[i] {
			t.Fatalf("status tail line %d = %q, want %q; stdout:\n%s", i, tail[i], want[i], out)
		}
	}
}

// recordShutdowns replaces the daemon-shutdown seam and appends "shutdown" to
// events on each call; wrapping submitPlaneRequest appends "submit", so a
// test can assert the order.
func recordShutdowns(t *testing.T, events *[]string) {
	t.Helper()
	origShutdown := setupShutdownDaemon
	origSubmit := submitPlaneRequest
	t.Cleanup(func() {
		setupShutdownDaemon = origShutdown
		submitPlaneRequest = origSubmit
	})
	setupShutdownDaemon = func(string) error {
		*events = append(*events, "shutdown")
		return nil
	}
	inner := submitPlaneRequest
	submitPlaneRequest = func(r approval.Request) (approval.Request, error) {
		*events = append(*events, "submit")
		return inner(r)
	}
}

func TestSetupFailsWhenApprovedMergeDidNotConverge(t *testing.T) {
	driftSandbox(t)
	useInstalledPlanes(t, "claude")
	calls := stubSetupGates(t, false, 0, 0)

	// An approval daemon running another binary: it reports approved but
	// never writes this binary's handlers.
	origSubmit, origQuery := submitPlaneRequest, queryPlaneStatus
	t.Cleanup(func() { submitPlaneRequest, queryPlaneStatus = origSubmit, origQuery })
	submitPlaneRequest = func(r approval.Request) (approval.Request, error) {
		return approval.Request{ID: "stub-request", Status: "pending", ApprovalURL: "http://localhost:39169/approve"}, nil
	}
	queryPlaneStatus = func(socket, id string) (approval.Request, error) {
		return approval.Request{Status: "approved"}, nil
	}
	var events []string
	recordShutdowns(t, &events)

	code, out, errb := runSetup(t)
	if code != 1 {
		t.Fatalf("exit = %d, want 1; stdout=%q stderr=%q", code, out, errb)
	}
	const want = "guardrail: setup: claude: still differs after approval — the approval daemon may be running another binary; run guardrail setup again"
	if !strings.Contains(errb, want) {
		t.Fatalf("stderr = %q, want %q", errb, want)
	}
	if len(events) != 2 || events[0] != "shutdown" || events[1] != "submit" {
		t.Fatalf("events = %q, want [shutdown submit]", events)
	}
	if calls.selftest != 0 {
		t.Fatalf("selftest calls = %d, want 0 after non-convergence", calls.selftest)
	}
}

func TestSetupShutsDownDaemonOnceBeforeSubmit(t *testing.T) {
	driftSandbox(t)
	useInstalledPlanes(t, "claude", "antigravity")
	useTransport(t, []string{"approved"})
	stubSetupGates(t, false, 0, 0)
	var events []string
	recordShutdowns(t, &events)

	code, out, errb := runSetup(t)
	if code != 0 {
		t.Fatalf("exit = %d, want 0; stdout=%q stderr=%q", code, out, errb)
	}
	if len(events) != 2 || events[0] != "shutdown" || events[1] != "submit" {
		t.Fatalf("events = %q, want [shutdown submit]", events)
	}
}

func TestSetupDisableShutsDownDaemonAfterSuccess(t *testing.T) {
	driftSandbox(t)
	enableForDrift(t, "claude")
	useInstalledPlanes(t, "claude")
	useTransport(t, []string{"approved"})
	stubSetupGates(t, false, 0, 0)
	var events []string
	recordShutdowns(t, &events)

	code, out, errb := runSetup(t, "--state", "disabled")
	if code != 0 {
		t.Fatalf("exit = %d, want 0; stdout=%q stderr=%q", code, out, errb)
	}
	if len(events) != 2 || events[0] != "submit" || events[1] != "shutdown" {
		t.Fatalf("events = %q, want [submit shutdown]", events)
	}
}

func TestSetupReenablesOnFloorDrift(t *testing.T) {
	driftSandbox(t)
	enableForDrift(t, "claude")
	useInstalledPlanes(t, "claude")
	useTransport(t, []string{"approved"})
	stubSetupGates(t, false, 0, 0)

	path, err := planeConfigPath("claude")
	if err != nil {
		t.Fatal(err)
	}
	doc, err := genconfig.ReadJSONObject(path)
	if err != nil {
		t.Fatal(err)
	}
	perms, _ := doc["permissions"].(map[string]any)
	deny, _ := perms["deny"].([]any)
	if len(deny) == 0 {
		t.Fatal("enable wrote no permissions.deny entries")
	}
	removed, _ := deny[0].(string)
	perms["deny"] = deny[1:]
	raw, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	writePlaneSettings(t, path, string(raw))

	code, out, errb := runSetup(t)
	if code != 0 {
		t.Fatalf("exit = %d, want 0; stdout=%q stderr=%q", code, out, errb)
	}
	if !strings.Contains(out, "claude: permissions floor drifted (1 entries missing); re-enabling\n") {
		t.Fatalf("stdout missing floor-drift line:\n%s", out)
	}
	if !strings.Contains(out, "approval required") {
		t.Fatalf("floor drift did not prompt:\n%s", out)
	}
	if missing := planeFloorDrift("claude"); missing != 0 {
		t.Fatalf("floor still missing %d entries after setup", missing)
	}
	quoted, _ := json.Marshal(removed)
	if !strings.Contains(readPlaneJSON(t, path), string(quoted)) {
		t.Fatalf("deny entry %s not restored", quoted)
	}
}
