package main

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/CtrlCarlitos/agent-guardrails/internal/testenv"
)

// #94: an update keeps the binary it replaced, and `guardrail rollback`
// restores it: checked against the record before anything changes, swapped
// so the rollback can itself be undone, and verified like an update.

// updatedFrom installs "old" at a temp target as release `from`, updates it to
// "new" as v0.19.2-dev, and returns the target.
func updatedFrom(t *testing.T, from string) string {
	t.Helper()
	testenv.SetState(t, t.TempDir())
	target := filepath.Join(t.TempDir(), testenv.ExecutableName("guardrail"))
	if err := os.WriteFile(target, []byte("old"), 0o755); err != nil {
		t.Fatal(err)
	}
	stubUpdateSeams(t, target)
	old := version
	version = from
	t.Cleanup(func() { version = old })
	server := updateTestServer(t, "new", updateSumsFor("new", updateAssetName()), http.StatusOK)
	updateReleaseBase = server.URL + "/download"
	var out, errb strings.Builder
	if code := run([]string{"update", "v0.19.2-dev"}, strings.NewReader(""), &out, &errb); code != 0 {
		t.Fatalf("update: exit %d, stderr %q", code, errb.String())
	}
	return target
}

func read(t *testing.T, path string) string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func TestUpdateRetainsThePreviousBinary(t *testing.T) {
	target := updatedFrom(t, "v0.19.1-dev")
	if got := read(t, previousBinaryPath(target)); got != "old" {
		t.Errorf("previous binary = %q, want the replaced bytes", got)
	}
	rec, err := loadPreviousRecord()
	if err != nil {
		t.Fatal(err)
	}
	if rec.Version != "v0.19.1-dev" || rec.Path != previousBinaryPath(target) || rec.SHA256 == "" {
		t.Errorf("record = %+v", rec)
	}
}

func TestRollbackRestoresThePreviousBinary(t *testing.T) {
	target := updatedFrom(t, "v0.19.1-dev")
	installedRuns = nil
	version = "v0.19.2-dev" // the binary now installed runs the rollback
	var out, errb strings.Builder
	if code := run([]string{"rollback"}, strings.NewReader(""), &out, &errb); code != 0 {
		t.Fatalf("rollback: exit %d, stderr %q", code, errb.String())
	}
	if got := read(t, target); got != "old" {
		t.Errorf("installed binary = %q, want the previous bytes", got)
	}
	// The swap keeps the rolled-back-from binary, so the rollback is reversible.
	if got := read(t, previousBinaryPath(target)); got != "new" {
		t.Errorf("previous binary after rollback = %q, want the binary rolled back from", got)
	}
	if rec, _ := loadPreviousRecord(); rec.Version != "v0.19.2-dev" {
		t.Errorf("record after rollback = %+v, want v0.19.2-dev", rec)
	}
	if want := fmt.Sprint([][]string{{target, "doctor"}, {target, "selftest"}}); !strings.HasPrefix(fmt.Sprint(installedRuns), strings.TrimSuffix(want, "]")) {
		t.Errorf("verification runs = %v, want doctor and selftest on %s", installedRuns, target)
	}
	if !strings.Contains(out.String(), "rolled back to v0.19.1-dev") {
		t.Errorf("stdout lacks the restored version: %q", out.String())
	}
}

func TestRollbackWithoutAPreviousExitsTwo(t *testing.T) {
	testenv.SetState(t, t.TempDir())
	target := filepath.Join(t.TempDir(), testenv.ExecutableName("guardrail"))
	if err := os.WriteFile(target, []byte("current"), 0o755); err != nil {
		t.Fatal(err)
	}
	stubUpdateSeams(t, target)
	var out, errb strings.Builder
	if code := run([]string{"rollback"}, strings.NewReader(""), &out, &errb); code != 2 || !strings.Contains(errb.String(), "no previous binary") {
		t.Fatalf("exit %d, stderr %q; want 2 and 'no previous binary'", code, errb.String())
	}
	if code := run([]string{"rollback", "extra"}, strings.NewReader(""), &out, &errb); code != 2 {
		t.Errorf("rollback with an argument: exit %d, want 2", code)
	}
}

func TestRollbackRefusesATamperedPrevious(t *testing.T) {
	target := updatedFrom(t, "v0.19.1-dev")
	if err := os.WriteFile(previousBinaryPath(target), []byte("tampered"), 0o755); err != nil {
		t.Fatal(err)
	}
	var out, errb strings.Builder
	if code := run([]string{"rollback"}, strings.NewReader(""), &out, &errb); code != 1 || !strings.Contains(errb.String(), "nothing was changed") {
		t.Fatalf("exit %d, stderr %q; want 1 and 'nothing was changed'", code, errb.String())
	}
	if got := read(t, target); got != "new" {
		t.Errorf("installed binary changed to %q after a refused rollback", got)
	}
}

func TestRollbackRefusesAPreviousThatDoesNotRun(t *testing.T) {
	target := updatedFrom(t, "v0.19.1-dev")
	verifyUpdatedBinary = func(path, version string) error { return errors.New("not a guardrail binary") }
	var out, errb strings.Builder
	if code := run([]string{"rollback"}, strings.NewReader(""), &out, &errb); code != 1 || !strings.Contains(errb.String(), "nothing was changed") {
		t.Fatalf("exit %d, stderr %q; want 1 and 'nothing was changed'", code, errb.String())
	}
	if got := read(t, target); got != "new" {
		t.Errorf("installed binary changed to %q after a refused rollback", got)
	}
}

func TestRollbackVerificationFailureSaysItIsAlreadyRestored(t *testing.T) {
	target := updatedFrom(t, "v0.19.1-dev")
	runInstalledBinary = func(exe string, args []string, stdout, stderr io.Writer) int {
		if args[0] == "selftest" {
			return 1
		}
		return 0
	}
	var out, errb strings.Builder
	code := run([]string{"rollback"}, strings.NewReader(""), &out, &errb)
	if code != 1 || !strings.Contains(errb.String(), "already restored") {
		t.Fatalf("exit %d, stderr %q; want 1 and 'already restored'", code, errb.String())
	}
	if got := read(t, target); got != "old" {
		t.Errorf("installed binary = %q, want the restored previous", got)
	}
}

// An update interrupted between moving the running binary aside and moving
// the new one in must not leave the install path empty.
func TestUpdateRestoresTheBinaryWhenTheFinalMoveFails(t *testing.T) {
	testenv.SetState(t, t.TempDir())
	target := filepath.Join(t.TempDir(), testenv.ExecutableName("guardrail"))
	if err := os.WriteFile(target, []byte("old"), 0o755); err != nil {
		t.Fatal(err)
	}
	stubUpdateSeams(t, target)
	server := updateTestServer(t, "new", updateSumsFor("new", updateAssetName()), http.StatusOK)
	updateReleaseBase = server.URL + "/download"
	orig := renameFile
	t.Cleanup(func() { renameFile = orig })
	renameFile = func(from, to string) error {
		if strings.HasSuffix(from, ".guardrail-update") {
			return errors.New("injected: final move failed")
		}
		return os.Rename(from, to)
	}
	var out, errb strings.Builder
	if code := run([]string{"update", "v0.19.2-dev"}, strings.NewReader(""), &out, &errb); code != 1 {
		t.Fatalf("exit %d, want 1; stderr %q", code, errb.String())
	}
	if got := read(t, target); got != "old" {
		t.Errorf("install path holds %q after a failed final move; want the original binary back", got)
	}
}
