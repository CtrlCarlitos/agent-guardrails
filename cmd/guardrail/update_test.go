package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/CtrlCarlitos/agent-guardrails/internal/approval"
	"github.com/CtrlCarlitos/agent-guardrails/internal/testenv"
)

func updateTestServer(t *testing.T, binary, sums string, status int) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if status != http.StatusOK {
			w.WriteHeader(status)
			return
		}
		switch strings.TrimSuffix(filepath.Base(r.URL.Path), "/") {
		case "SHA256SUMS":
			fmt.Fprint(w, sums)
		default:
			w.Write([]byte(binary))
		}
	})
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	return server
}

func updateAssetName() string {
	asset := fmt.Sprintf("guardrail_%s_%s", runtime.GOOS, runtime.GOARCH)
	if runtime.GOOS == "windows" {
		asset += ".exe"
	}
	return asset
}

func updateSumsFor(binary, asset string) string {
	digest := sha256.Sum256([]byte(binary))
	return hex.EncodeToString(digest[:]) + "  " + asset + "\n"
}

// installedRuns records every post-update verification exec the update
// requested: which binary, with which arguments.
var installedRuns [][]string

func stubUpdateSeams(t *testing.T, target string) {
	t.Helper()
	origBase, origClient, origTarget, origVerify, origRun := updateReleaseBase, updateHTTPClient, updateTargetPath, verifyUpdatedBinary, runInstalledBinary
	installedRuns = nil
	runInstalledBinary = func(exe string, args []string, stdout, stderr io.Writer) int {
		installedRuns = append(installedRuns, append([]string{exe}, args...))
		fmt.Fprintf(stdout, "stub %s %s\n", filepath.Base(exe), strings.Join(args, " "))
		return 0
	}
	updateTargetPath = func() (string, error) { return target, nil }
	verifyUpdatedBinary = func(path, version string) error {
		if path == target || !strings.HasSuffix(path, ".guardrail-update") {
			return fmt.Errorf("verify seam called on wrong path %q", path)
		}
		return nil
	}
	t.Cleanup(func() {
		updateReleaseBase, updateHTTPClient, updateTargetPath, verifyUpdatedBinary, runInstalledBinary = origBase, origClient, origTarget, origVerify, origRun
	})
}

// Post-update verification must run the binary that was just installed —
// in-process doctor/selftest would report on, and record a selftest pass
// for, the superseded release (seen live: v0.20.18 → v0.20.19 wrote the
// marker as v0.20.18 and the next session nudged anyway).
func TestUpdateVerifiesTheInstalledBinaryNotItself(t *testing.T) {
	target := filepath.Join(t.TempDir(), "guardrail")
	if err := os.WriteFile(target, []byte("old"), 0o755); err != nil {
		t.Fatal(err)
	}
	stubUpdateSeams(t, target)
	binary := "new-binary-bytes"
	server := updateTestServer(t, binary, updateSumsFor(binary, updateAssetName()), http.StatusOK)
	updateReleaseBase = server.URL + "/download"

	var out, errb strings.Builder
	if code := run([]string{"update", "v0.19.2-dev"}, strings.NewReader(""), &out, &errb); code != 0 {
		t.Fatalf("exit = %d, stderr %q", code, errb.String())
	}
	// The update closes with the steps still owed to the operator, computed by
	// the installed binary (#364), after its own verification.
	want := [][]string{{target, "doctor"}, {target, "selftest"}, {target, "next"}}
	if fmt.Sprint(installedRuns) != fmt.Sprint(want) {
		t.Fatalf("installed runs = %v, want %v", installedRuns, want)
	}
	if strings.Contains(out.String(), "guardrail "+version+"\n") || strings.Contains(out.String(), "probes pass") {
		t.Fatalf("update ran doctor/selftest in-process:\n%s", out.String())
	}
}

func TestUpdateReportsAFailedSelftestOnTheInstalledBinary(t *testing.T) {
	target := filepath.Join(t.TempDir(), "guardrail")
	if err := os.WriteFile(target, []byte("old"), 0o755); err != nil {
		t.Fatal(err)
	}
	stubUpdateSeams(t, target)
	runInstalledBinary = func(exe string, args []string, stdout, stderr io.Writer) int {
		if args[0] == "selftest" {
			return 1
		}
		return 0
	}
	binary := "new-binary-bytes"
	server := updateTestServer(t, binary, updateSumsFor(binary, updateAssetName()), http.StatusOK)
	updateReleaseBase = server.URL + "/download"

	var out, errb strings.Builder
	run([]string{"update", "v0.19.2-dev"}, strings.NewReader(""), &out, &errb)
	if !strings.Contains(errb.String(), "selftest failed on the new binary") {
		t.Fatalf("stderr = %q, want loud selftest failure", errb.String())
	}
}

func TestUpdateRejectsBadArguments(t *testing.T) {
	stubUpdateSeams(t, filepath.Join(t.TempDir(), "guardrail"))
	var out, errb strings.Builder
	cases := [][]string{
		{},
		{"v0.19.2-dev", "extra"},
		{"latest"},
		{"0.19.2"},
		{"vX.Y.Z"},
	}
	for _, args := range cases {
		if code := run(append([]string{"update"}, args...), strings.NewReader(""), &out, &errb); code != 2 {
			t.Fatalf("update %v exit = %d, stderr %q", args, code, errb.String())
		}
	}
	if !strings.Contains(errb.String(), "exact release version") {
		t.Fatalf("stderr missing version guidance: %q", errb.String())
	}
}

func TestUpdateHappyPathReplacesBinary(t *testing.T) {
	target := filepath.Join(t.TempDir(), testenv.ExecutableName("guardrail"))
	if err := os.WriteFile(target, []byte("old"), 0o755); err != nil {
		t.Fatal(err)
	}
	stubUpdateSeams(t, target)
	binary := "new-binary-bytes"
	server := updateTestServer(t, binary, updateSumsFor(binary, updateAssetName()), http.StatusOK)
	updateReleaseBase = server.URL + "/download"

	var out, errb strings.Builder
	if code := run([]string{"update", "v0.19.2-dev"}, strings.NewReader(""), &out, &errb); code != 0 {
		t.Fatalf("exit = %d, stderr %q", code, errb.String())
	}
	raw, err := os.ReadFile(target)
	if err != nil || string(raw) != binary {
		t.Fatalf("target = %q err=%v, want downloaded bytes", raw, err)
	}
	info, err := os.Stat(target)
	if err != nil || !info.Mode().IsRegular() {
		t.Fatalf("target mode = %v err=%v, want a regular file", info, err)
	}
	// Windows executable permission comes from the .exe shape and ACLs; Go's
	// Chmod only controls the read-only attribute there. The running-.exe
	// replacement path is exercised by TestWindowsUpdateReplacesTheRunningBinary.
	if runtime.GOOS == "windows" {
		if !strings.EqualFold(filepath.Ext(target), ".exe") || info.Mode().Perm()&0o200 == 0 {
			t.Fatalf("Windows target = %q mode %v, want writable .exe", target, info.Mode().Perm())
		}
	} else if info.Mode().Perm() != 0o755 {
		t.Fatalf("target mode = %v, want 0755", info.Mode().Perm())
	}
	if !strings.Contains(out.String(), "v0.19.2-dev") {
		t.Fatalf("stdout missing version: %q", out.String())
	}
}

func TestUpdateRefusesChecksumMismatch(t *testing.T) {
	target := filepath.Join(t.TempDir(), "guardrail")
	if err := os.WriteFile(target, []byte("old"), 0o755); err != nil {
		t.Fatal(err)
	}
	stubUpdateSeams(t, target)
	server := updateTestServer(t, "tampered", updateSumsFor("original", updateAssetName()), http.StatusOK)
	updateReleaseBase = server.URL + "/download"

	var out, errb strings.Builder
	if code := run([]string{"update", "v0.19.2-dev"}, strings.NewReader(""), &out, &errb); code != 1 {
		t.Fatalf("exit = %d, stderr %q", code, errb.String())
	}
	raw, _ := os.ReadFile(target)
	if string(raw) != "old" {
		t.Fatalf("target was replaced despite checksum mismatch: %q", raw)
	}
}

func TestUpdateFailsClosedOnMissingRelease(t *testing.T) {
	target := filepath.Join(t.TempDir(), "guardrail")
	if err := os.WriteFile(target, []byte("old"), 0o755); err != nil {
		t.Fatal(err)
	}
	stubUpdateSeams(t, target)
	server := updateTestServer(t, "", "", http.StatusNotFound)
	updateReleaseBase = server.URL + "/download"

	var out, errb strings.Builder
	if code := run([]string{"update", "v0.19.2-dev"}, strings.NewReader(""), &out, &errb); code != 1 {
		t.Fatalf("exit = %d, stderr %q", code, errb.String())
	}
	raw, _ := os.ReadFile(target)
	if string(raw) != "old" {
		t.Fatalf("target was replaced despite download failure: %q", raw)
	}
}

func TestUpdateSameVersionIsANoOp(t *testing.T) {
	target := filepath.Join(t.TempDir(), "guardrail")
	if err := os.WriteFile(target, []byte("current"), 0o755); err != nil {
		t.Fatal(err)
	}
	origVersion := version
	version = "v0.19.3-dev"
	t.Cleanup(func() { version = origVersion })
	stubUpdateSeams(t, target)
	server := updateTestServer(t, "should-not-download", updateSumsFor("x", updateAssetName()), http.StatusOK)
	updateReleaseBase = server.URL + "/download"
	updateHTTPClient = server.Client() // any request will be recorded by the mux below

	var requested int
	server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requested++
		http.Error(w, "unexpected", http.StatusTeapot)
	})

	var out, errb strings.Builder
	if code := run([]string{"update", "v0.19.3-dev"}, strings.NewReader(""), &out, &errb); code != 0 {
		t.Fatalf("exit = %d, stderr %q", code, errb.String())
	}
	if requested != 0 {
		t.Fatalf("same-version update performed %d network requests", requested)
	}
	raw, _ := os.ReadFile(target)
	if string(raw) != "current" {
		t.Fatalf("binary replaced on no-op: %q", raw)
	}
	if !strings.Contains(out.String(), "already") {
		t.Fatalf("stdout missing no-op notice: %q", out.String())
	}
}

func TestUpdateShutsDownApprovalDaemonAfterReplace(t *testing.T) {
	target := filepath.Join(t.TempDir(), "guardrail")
	if err := os.WriteFile(target, []byte("old"), 0o755); err != nil {
		t.Fatal(err)
	}
	origVersion := version
	version = "v0.19.10-dev"
	t.Cleanup(func() { version = origVersion })
	stubUpdateSeams(t, target)
	binary := "new"
	server := updateTestServer(t, binary, updateSumsFor(binary, updateAssetName()), http.StatusOK)
	updateReleaseBase = server.URL + "/download"

	shutdowns := 0
	origShutdown := shutdownApprovalDaemon
	shutdownApprovalDaemon = func(socket string) error {
		if socket != approval.DefaultSocketPath() {
			t.Errorf("shutdown socket = %q", socket)
		}
		shutdowns++
		return nil
	}
	t.Cleanup(func() { shutdownApprovalDaemon = origShutdown })

	var out, errb strings.Builder
	if code := run([]string{"update", "v0.19.11-dev"}, strings.NewReader(""), &out, &errb); code != 0 {
		t.Fatalf("exit = %d, stderr %q", code, errb.String())
	}
	if shutdowns != 1 {
		t.Fatalf("shutdown called %d times, want 1", shutdowns)
	}
}

func TestUpdateMissingReleaseMessageNamesTheRace(t *testing.T) {
	target := filepath.Join(t.TempDir(), "guardrail")
	if err := os.WriteFile(target, []byte("old"), 0o755); err != nil {
		t.Fatal(err)
	}
	stubUpdateSeams(t, target)
	server := updateTestServer(t, "", "", http.StatusNotFound)
	updateReleaseBase = server.URL + "/download"

	var out, errb strings.Builder
	if code := run([]string{"update", "v0.99.0-dev"}, strings.NewReader(""), &out, &errb); code != 1 {
		t.Fatalf("exit = %d", code)
	}
	if !strings.Contains(errb.String(), "may still be publishing") {
		t.Fatalf("stderr = %q, want the asset-publish race named", errb.String())
	}
}
