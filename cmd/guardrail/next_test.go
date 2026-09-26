package main

import (
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// After an update or install the operator has to know what is still theirs to
// do, in one place, in order (#364). `guardrail next` computes it from the
// current state and only advises: it never changes anything and never asks for
// an approval. It is silent when nothing applies.

func TestNextStepsAreEmptyWhenEverythingHasConverged(t *testing.T) {
	driftSandbox(t)
	enableForDrift(t, "claude")
	useInstalledPlanes(t, "claude")
	stubOperatorEnrolled(t, true)

	steps, err := nextSteps()
	if err != nil {
		t.Fatal(err)
	}
	if len(steps) != 0 {
		t.Fatalf("steps = %q, want none on a converged machine", steps)
	}
	var out, errb strings.Builder
	if code := cmdNext(nil, &out, &errb); code != 0 || out.String() != "" {
		t.Fatalf("cmdNext = (%d, %q, %q), want (0, no output, no error)", code, out.String(), errb.String())
	}
}

func TestNextStepsNameAPlaneWhoseHandlersDrifted(t *testing.T) {
	_, b := driftSandbox(t)
	enableForDrift(t, "claude")
	useInstalledExecutable(t, b) // the binary moved: the registered handlers now differ
	useInstalledPlanes(t, "claude")
	stubOperatorEnrolled(t, true)

	steps, err := nextSteps()
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(steps, "\n")
	for _, want := range []string{
		"claude: registered handlers differ from this binary",
		"guardrail plane enable claude",
		"passkey",
		"Restart the agents",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("steps missing %q:\n%s", want, joined)
		}
	}
	if strings.Contains(joined, "operator enroll") {
		t.Errorf("an enrolled operator was told to enroll:\n%s", joined)
	}
}

func TestNextStepsMentionTheRetiredFloorAnEnrolledOperatorWillLose(t *testing.T) {
	seedFlooredClaude(t)
	useInstalledPlanes(t, "claude")
	stubOperatorEnrolled(t, true)

	steps, err := nextSteps()
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(steps, "\n")
	if !strings.Contains(joined, "floor entries") || !strings.Contains(joined, "guardrail plane enable claude") {
		t.Fatalf("steps do not offer the floor prune:\n%s", joined)
	}
}

// With no authenticator enrolled, the plane step is `setup` (which arms
// without an approval, ADR-0030), and the one-time enrollment is a step of its
// own. Neither may promise a passkey approval that cannot happen.
func TestNextStepsAskAnUnenrolledOperatorToEnroll(t *testing.T) {
	_, b := driftSandbox(t)
	enableForDrift(t, "claude")
	useInstalledExecutable(t, b)
	useInstalledPlanes(t, "claude")
	stubOperatorEnrolled(t, false)

	steps, err := nextSteps()
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(steps, "\n")
	if !strings.Contains(joined, "guardrail operator enroll") {
		t.Errorf("no enrollment step:\n%s", joined)
	}
	if !strings.Contains(joined, "guardrail setup") {
		t.Errorf("no setup step for the drifted plane:\n%s", joined)
	}
	if strings.Contains(joined, "plane enable claude") {
		t.Errorf("an unenrolled operator was sent to a command that needs a passkey:\n%s", joined)
	}
}

func TestNextPrintsAnOrderedBlockAndChangesNothing(t *testing.T) {
	_, b := driftSandbox(t)
	enableForDrift(t, "claude")
	useInstalledExecutable(t, b)
	useInstalledPlanes(t, "claude")
	stubOperatorEnrolled(t, true)
	refuseSubmits(t) // advice only: it must never open an approval

	before := readPlaneJSON(t, mustPlanePath(t, "claude"))
	var out, errb strings.Builder
	if code := cmdNext(nil, &out, &errb); code != 0 {
		t.Fatalf("cmdNext exit = %d, stderr=%q", code, errb.String())
	}
	if !strings.HasPrefix(out.String(), "next steps:\n  1. ") {
		t.Fatalf("output is not an ordered block:\n%s", out.String())
	}
	if after := readPlaneJSON(t, mustPlanePath(t, "claude")); after != before {
		t.Fatal("cmdNext changed the settings file")
	}
}

func TestNextRejectsArguments(t *testing.T) {
	var out, errb strings.Builder
	if code := cmdNext([]string{"--now"}, &out, &errb); code != 2 {
		t.Fatalf("exit = %d, want 2 for an unknown argument", code)
	}
}

func mustPlanePath(t *testing.T, plane string) string {
	t.Helper()
	path, err := planeConfigPath(plane)
	if err != nil {
		t.Fatal(err)
	}
	return path
}

// setup converged the planes it was asked about; a plane it was not asked
// about may still be owed work, and the operator should see that at the end of
// the run rather than find it in a doctor line later.
func TestSetupClosesWithTheStepsForPlanesItDidNotTouch(t *testing.T) {
	driftSandbox(t)
	useInstalledPlanes(t, "claude", "opencode")
	stubSetupGates(t, false, 0, 0)
	useTransport(t, []string{"approved"})

	code, out, errb := runSetup(t, "--planes", "claude")
	if code != 0 {
		t.Fatalf("exit = %d, want 0; stdout=%q stderr=%q", code, out, errb)
	}
	if !strings.Contains(out, "next steps:") || !strings.Contains(out, "opencode: not registered") {
		t.Fatalf("setup did not close with the steps for opencode:\n%s", out)
	}
	if strings.Index(out, "next steps:") < strings.Index(out, "claude enabled") {
		t.Fatalf("the steps must come last, after the result:\n%s", out)
	}
}

// The first-install bootstrap already prints its own instruction; a second,
// overlapping block would say the same thing twice.
func TestSetupBootstrapDoesNotPrintTheStepsBlockTwice(t *testing.T) {
	driftSandbox(t)
	useInstalledPlanes(t, "claude")
	stubOperatorEnrolled(t, false)
	stubSetupGates(t, false, 0, 0)

	code, out, errb := runSetup(t)
	if code != 0 {
		t.Fatalf("exit = %d; stdout=%q stderr=%q", code, out, errb)
	}
	if strings.Contains(out, "next steps:") {
		t.Fatalf("bootstrap printed the block on top of its own instruction:\n%s", out)
	}
	if !strings.Contains(out, "operator enroll") {
		t.Fatalf("bootstrap lost its enroll instruction:\n%s", out)
	}
}

// `update` is run by the binary being replaced. An updater older than the
// feature never calls `next`, but it always runs the new binary's `doctor`, so
// doctor is the one channel that reaches an operator on that first hop (#374).
func TestDoctorEndsWithTheNextStepsWhenSomethingIsOwed(t *testing.T) {
	_, b := driftSandbox(t)
	enableForDrift(t, "claude")
	useInstalledExecutable(t, b)
	useInstalledPlanes(t, "claude")
	stubOperatorEnrolled(t, true)
	t.Setenv(updateRunEnv, "")

	var out, errb strings.Builder
	if code := cmdDoctor(nil, &out, &errb); code != 0 {
		t.Fatalf("doctor exit = %d, stderr=%q", code, errb.String())
	}
	at := strings.LastIndex(out.String(), "next steps:")
	if at < 0 {
		t.Fatalf("doctor does not end with a steps block:\n%s", out.String())
	}
	block := out.String()[at:]
	if !strings.Contains(block, "guardrail plane enable claude") || strings.Contains(block, "engine health") {
		t.Fatalf("the steps block is not the last thing doctor prints:\n%s", out.String())
	}
	if strings.Count(out.String(), "next steps:") != 1 {
		t.Fatalf("the block appears more than once:\n%s", out.String())
	}
}

func TestDoctorPrintsNoStepsBlockOnAConvergedMachine(t *testing.T) {
	driftSandbox(t)
	enableForDrift(t, "claude")
	useInstalledPlanes(t, "claude")
	stubOperatorEnrolled(t, true)
	t.Setenv(updateRunEnv, "")

	var out, errb strings.Builder
	cmdDoctor(nil, &out, &errb)
	if strings.Contains(out.String(), "next steps:") {
		t.Fatalf("a converged machine printed a steps block:\n%s", out.String())
	}
}

// A current updater prints the block itself, last, after selftest. It marks
// the doctor it runs so the block is not shown twice.
func TestDoctorSkipsTheStepsBlockWhenTheUpdaterWillPrintIt(t *testing.T) {
	_, b := driftSandbox(t)
	enableForDrift(t, "claude")
	useInstalledExecutable(t, b)
	useInstalledPlanes(t, "claude")
	stubOperatorEnrolled(t, true)
	t.Setenv(updateRunEnv, "1")

	var out, errb strings.Builder
	cmdDoctor(nil, &out, &errb)
	if strings.Contains(out.String(), "next steps:") {
		t.Fatalf("doctor printed the block although the updater will:\n%s", out.String())
	}
}

func TestUpdateMarksItsVerificationRunsAndClearsTheMarkAfterwards(t *testing.T) {
	target := filepath.Join(t.TempDir(), "guardrail")
	if err := os.WriteFile(target, []byte("old"), 0o755); err != nil {
		t.Fatal(err)
	}
	stubUpdateSeams(t, target)
	seen := map[string]string{}
	runInstalledBinary = func(exe string, args []string, stdout, stderr io.Writer) int {
		seen[args[0]] = os.Getenv(updateRunEnv)
		return 0
	}
	t.Setenv(updateRunEnv, "")
	binary := "new-binary-bytes"
	server := updateTestServer(t, binary, updateSumsFor(binary, updateAssetName()), http.StatusOK)
	updateReleaseBase = server.URL + "/download"

	var out, errb strings.Builder
	if code := run([]string{"update", "v0.19.2-dev"}, strings.NewReader(""), &out, &errb); code != 0 {
		t.Fatalf("exit = %d, stderr %q", code, errb.String())
	}
	if seen["doctor"] != "1" || seen["selftest"] != "1" {
		t.Fatalf("the verification runs were not marked: %v", seen)
	}
	if got := os.Getenv(updateRunEnv); got != "" {
		t.Fatalf("the mark leaked out of update: %q", got)
	}
}
