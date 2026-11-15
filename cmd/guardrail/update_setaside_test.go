package main

import (
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/CtrlCarlitos/agent-guardrails/internal/testenv"
)

// #522: pre-#94 updates set locked binaries aside as
// `guardrail(.exe).old-<timestamp>`. Nothing produces that name any more,
// and nothing removed the copies it left behind, so machines that updated
// across the scheme carry them forever. An update's pre-cycle cleanup
// already removes the single `.old` slot; it now also sweeps legacy
// `.old-*` siblings. Hand-made backups (`.before-*` and anything else) are
// not guardrail's to delete and stay untouched.
func TestWindowsUpdateSweepsLegacyTimestampedAsides(t *testing.T) {
	target := filepath.Join(t.TempDir(), testenv.ExecutableName("guardrail"))
	if err := os.WriteFile(target, []byte("old"), 0o755); err != nil {
		t.Fatal(err)
	}
	stubUpdateSeams(t, target)
	binary := "new-binary-bytes"
	server := updateTestServer(t, binary, updateSumsFor(binary, updateAssetName()), http.StatusOK)
	updateReleaseBase = server.URL + "/download"

	dir := filepath.Dir(target)
	legacy1 := filepath.Join(dir, testenv.ExecutableName("guardrail")+".old-20261004014348")
	legacy2 := filepath.Join(dir, testenv.ExecutableName("guardrail")+".old-20260911102233")
	handmade := filepath.Join(dir, testenv.ExecutableName("guardrail")+".before-stdin-fix-20260925")
	plain := filepath.Join(dir, testenv.ExecutableName("guardrail")+".old")
	for _, path := range []string{legacy1, legacy2, handmade, plain} {
		if err := os.WriteFile(path, []byte("aside"), 0o755); err != nil {
			t.Fatal(err)
		}
	}

	// Observe stale-file removal before replacement: on Windows the swap
	// deliberately creates a fresh .old slot holding the running image.
	verify := verifyUpdatedBinary
	checkedBeforeSwap := false
	verifyUpdatedBinary = func(path, version string) error {
		checkedBeforeSwap = true
		for _, stale := range []string{legacy1, legacy2, plain} {
			if _, err := os.Stat(stale); !os.IsNotExist(err) {
				t.Errorf("%s survived pre-swap cleanup", filepath.Base(stale))
			}
		}
		return verify(path, version)
	}
	var out, errb strings.Builder
	if code := run([]string{"update", "v0.19.2-dev"}, strings.NewReader(""), &out, &errb); code != 0 {
		t.Fatalf("exit = %d, stderr %q", code, errb.String())
	}
	if !checkedBeforeSwap {
		t.Fatal("staged verification never observed pre-swap cleanup")
	}
	for _, path := range []string{legacy1, legacy2} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Errorf("%s survived the update; guardrail-produced asides must be swept", filepath.Base(path))
		}
	}
	if runtime.GOOS == "windows" {
		if data, err := os.ReadFile(plain); err != nil || string(data) != "old" {
			t.Errorf("fresh Windows aside = %q, %v; want replaced binary, not seeded stale bytes", data, err)
		}
	} else if _, err := os.Stat(plain); !os.IsNotExist(err) {
		t.Errorf("%s survived POSIX replacement: %v", filepath.Base(plain), err)
	}
	if _, err := os.Stat(handmade); err != nil {
		t.Errorf("hand-made backup %s was deleted; only guardrail's own names are swept: %v", filepath.Base(handmade), err)
	}
}
