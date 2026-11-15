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
func TestUpdateSweepsLegacyTimestampedAsides(t *testing.T) {
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

	var out, errb strings.Builder
	if code := run([]string{"update", "v0.19.2-dev"}, strings.NewReader(""), &out, &errb); code != 0 {
		t.Fatalf("exit = %d, stderr %q", code, errb.String())
	}
	// Legacy timestamped asides are swept on every OS.
	for _, path := range []string{legacy1, legacy2} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Errorf("%s survived the update; guardrail-produced asides must be swept", filepath.Base(path))
		}
	}
	if _, err := os.Stat(handmade); err != nil {
		t.Errorf("hand-made backup %s was deleted; only guardrail's own names are swept: %v", filepath.Base(handmade), err)
	}
	// The single .old slot after an update is OS-shaped (#565): POSIX has no
	// rename-aside, so the planted one is simply gone. Windows always renames
	// the target aside — a running image can be renamed but not overwritten —
	// so exactly one .old exists afterwards, and it is THIS update's aside
	// carrying the replaced binary's bytes, not the "aside" bytes the test
	// planted (the retention policy's single-slot design, #522).
	if runtime.GOOS == "windows" {
		raw, err := os.ReadFile(plain)
		if err != nil {
			t.Fatalf("guardrail.exe.old missing after the update; Windows must leave this update's own aside: %v", err)
		}
		if string(raw) != "old" {
			t.Fatalf("guardrail.exe.old = %q; want the replaced binary's bytes, proving it is this update's aside", raw)
		}
	} else if _, err := os.Stat(plain); !os.IsNotExist(err) {
		t.Errorf("%s survived the update; POSIX creates no rename-aside", filepath.Base(plain))
	}
}
