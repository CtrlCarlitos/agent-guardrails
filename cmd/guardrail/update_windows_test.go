//go:build windows

package main

import (
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestSpawnedChildSits is the body executed by child processes the update
// tests start from a copied binary: it holds that binary's image open the
// way a real long-running guardrail subcommand would.
func TestSpawnedChildSits(t *testing.T) {
	if os.Getenv("GRD_CHILD_SIT") == "" {
		t.Skip("child only")
	}
	time.Sleep(10 * time.Minute)
}

// startChildFrom copies the test binary to target and starts it in its
// sitting mode, so target is a running executable image for the duration.
func startChildFrom(t *testing.T, target string) *exec.Cmd {
	t.Helper()
	src, err := os.Open(os.Args[0])
	if err != nil {
		t.Fatal(err)
	}
	defer src.Close()
	dst, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o755)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(dst, src); err != nil {
		dst.Close()
		t.Fatal(err)
	}
	if err := dst.Close(); err != nil {
		t.Fatal(err)
	}
	child := exec.Command(target, "-test.run=TestSpawnedChildSits")
	child.Env = append(os.Environ(), "GRD_CHILD_SIT=1")
	if err := child.Start(); err != nil {
		t.Fatalf("start child from %s: %v", target, err)
	}
	t.Cleanup(func() {
		_ = child.Process.Kill()
		_, _ = child.Process.Wait()
	})
	return child
}

// TestWindowsUpdateReplacesTheRunningBinary pins the ADR-0021 step (d) fix:
// the running image cannot be overwritten on Windows, but its path can be
// renamed aside. The child process runs from the copied binary exactly the
// way a deployed guardrail.exe would, so the update must survive it.
func TestWindowsUpdateReplacesTheRunningBinary(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "guardrail.exe")
	startChildFrom(t, target)

	stubUpdateSeams(t, target)
	binary := "new-image-bytes"
	server := updateTestServer(t, binary, updateSumsFor(binary, updateAssetName()), 200)
	updateReleaseBase = server.URL + "/download"

	var out, errb strings.Builder
	if code := run([]string{"update", "v0.19.2-dev"}, strings.NewReader(""), &out, &errb); code != 0 {
		t.Fatalf("exit = %d, stderr %q", code, errb.String())
	}
	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != binary {
		t.Fatalf("target content = %q, want the new binary bytes", got)
	}
}

// TestWindowsUpdateCleansUpTheSupersededImage pins the housekeeping cycle:
// the replaced image is renamed to guardrail.exe.old (it cannot be deleted
// while this process runs from it), the next update removes that leftover
// before creating its own, and repeated updates never proliferate copies.
func TestWindowsUpdateCleansUpTheSupersededImage(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "guardrail.exe")
	if err := os.WriteFile(target, []byte("v1"), 0o755); err != nil {
		t.Fatal(err)
	}

	stubUpdateSeams(t, target)

	binary := []byte("v2")
	server := updateTestServer(t, string(binary), updateSumsFor(string(binary), updateAssetName()), 200)
	updateReleaseBase = server.URL + "/download"

	var out, errb strings.Builder
	if code := run([]string{"update", "v0.19.2-dev"}, strings.NewReader(""), &out, &errb); code != 0 {
		t.Fatalf("first update: exit = %d, stderr %q", code, errb.String())
	}
	superseded := target + ".old"
	got, err := os.ReadFile(superseded)
	if err != nil {
		t.Fatalf("superseded image not set aside: %v", err)
	}
	if string(got) != "v1" {
		t.Fatalf("superseded image = %q, want the replaced v1 bytes", got)
	}

	binary = []byte("v3")
	server2 := updateTestServer(t, string(binary), updateSumsFor(string(binary), updateAssetName()), 200)
	updateReleaseBase = server2.URL + "/download"
	if code := run([]string{"update", "v0.19.3-dev"}, strings.NewReader(""), &out, &errb); code != 0 {
		t.Fatalf("second update: exit = %d, stderr %q", code, errb.String())
	}
	got, err = os.ReadFile(superseded)
	if err != nil {
		t.Fatalf("superseded image after second update: %v", err)
	}
	if string(got) != "v2" {
		t.Fatalf("superseded image = %q, want the second-oldest v2 bytes (no proliferation)", got)
	}
	got, err = os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "v3" {
		t.Fatalf("target = %q, want v3", got)
	}
}
