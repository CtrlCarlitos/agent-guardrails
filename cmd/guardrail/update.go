package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"
)

var (
	updateReleaseBase   = "https://github.com/CtrlCarlitos/agent-guardrails/releases/download"
	updateHTTPClient    = &http.Client{Timeout: 3 * time.Minute}
	updateTargetPath    = os.Executable
	verifyUpdatedBinary = func(path, version string) error {
		out, err := exec.Command(path, "version").Output()
		if err != nil {
			return fmt.Errorf("downloaded binary failed to run: %w", err)
		}
		if strings.TrimSpace(string(out)) != "guardrail "+version {
			return fmt.Errorf("downloaded binary reports %q, want guardrail %s", strings.TrimSpace(string(out)), version)
		}
		return nil
	}
)

var updateVersionPattern = regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$`)

// cmdUpdate self-updates the guardrail binary to an exact release:
// checksum-verified, run-verified, and replaced by same-directory rename.
// Implicit "latest" is deliberately unsupported; version authority stays
// with the operator and the dotfiles pin.
func cmdUpdate(args []string, stdout, stderr io.Writer) int {
	if len(args) != 1 || !updateVersionPattern.MatchString(args[0]) {
		fmt.Fprintln(stderr, "guardrail: update needs one exact release version (e.g. v0.19.2-dev); 'latest' is not supported")
		return 2
	}
	version := args[0]

	exe, err := updateTargetPath()
	if err != nil {
		fmt.Fprintf(stderr, "guardrail: cannot locate running binary: %v\n", err)
		return 1
	}
	exe, err = filepath.Abs(exe)
	if err != nil {
		fmt.Fprintf(stderr, "guardrail: cannot resolve binary path: %v\n", err)
		return 1
	}

	asset := fmt.Sprintf("guardrail_%s_%s", runtime.GOOS, runtime.GOARCH)
	if runtime.GOOS == "windows" {
		asset += ".exe"
	}
	base := strings.TrimSuffix(updateReleaseBase, "/") + "/" + version

	data, err := updateDownload(base + "/" + asset)
	if err != nil {
		fmt.Fprintf(stderr, "guardrail: download %s failed: %v\n", asset, err)
		return 1
	}
	sums, err := updateDownload(base + "/SHA256SUMS")
	if err != nil {
		fmt.Fprintf(stderr, "guardrail: download SHA256SUMS failed: %v\n", err)
		return 1
	}
	if err := verifyChecksum(data, sums, asset); err != nil {
		fmt.Fprintf(stderr, "guardrail: refusing update: %v\n", err)
		return 1
	}

	dir := filepath.Dir(exe)
	staged := filepath.Join(dir, ".guardrail-update")
	_ = os.Remove(staged)
	if err := os.WriteFile(staged, data, 0o755); err != nil {
		fmt.Fprintf(stderr, "guardrail: cannot stage update: %v\n", err)
		return 1
	}
	if err := verifyUpdatedBinary(staged, version); err != nil {
		_ = os.Remove(staged)
		fmt.Fprintf(stderr, "guardrail: refusing update: %v\n", err)
		return 1
	}
	if err := os.Rename(staged, exe); err != nil {
		_ = os.Remove(staged)
		fmt.Fprintf(stderr, "guardrail: cannot replace %s: %v\n", exe, err)
		return 1
	}
	fmt.Fprintf(stdout, "guardrail updated to %s at %s\n", version, exe)
	fmt.Fprintln(stdout, "run `guardrail doctor` to verify plane wiring")
	return 0
}

func updateDownload(url string) ([]byte, error) {
	resp, err := updateHTTPClient.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %s", resp.Status)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 128<<20))
}

func verifyChecksum(data []byte, sums []byte, asset string) error {
	want := sha256.Sum256(data)
	got := hex.EncodeToString(want[:])
	for _, line := range strings.Split(string(sums), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[1] == asset {
			if fields[0] == got {
				return nil
			}
			return fmt.Errorf("checksum mismatch for %s", asset)
		}
	}
	return fmt.Errorf("no checksum entry for %s in SHA256SUMS", asset)
}
