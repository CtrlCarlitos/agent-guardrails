package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
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

func stubUpdateSeams(t *testing.T, target string) {
	t.Helper()
	origBase, origClient, origTarget, origVerify := updateReleaseBase, updateHTTPClient, updateTargetPath, verifyUpdatedBinary
	updateTargetPath = func() (string, error) { return target, nil }
	verifyUpdatedBinary = func(path, version string) error {
		if path == target || !strings.HasSuffix(path, ".guardrail-update") {
			return fmt.Errorf("verify seam called on wrong path %q", path)
		}
		return nil
	}
	t.Cleanup(func() {
		updateReleaseBase, updateHTTPClient, updateTargetPath, verifyUpdatedBinary = origBase, origClient, origTarget, origVerify
	})
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
	raw, err := os.ReadFile(target)
	if err != nil || string(raw) != binary {
		t.Fatalf("target = %q err=%v, want downloaded bytes", raw, err)
	}
	if info, err := os.Stat(target); err != nil || info.Mode().Perm() != 0o755 {
		t.Fatalf("target mode = %v err=%v, want 0755", info, err)
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
