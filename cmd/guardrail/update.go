package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
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

	"github.com/CtrlCarlitos/agent-guardrails/internal/approval"
)

var (
	updateReleaseBase      = "https://github.com/CtrlCarlitos/agent-guardrails/releases/download"
	updateHTTPClient       = &http.Client{Timeout: 3 * time.Minute}
	updateTargetPath       = os.Executable
	shutdownApprovalDaemon = approval.ShutdownDaemon
	verifyUpdatedBinary    = func(path, version string) error {
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

// safeVersionString reports the running binary's version, tolerating a dev
// build whose version string can never match a release tag.
func safeVersionString() string {
	if strings.HasPrefix(version, "v") {
		return version
	}
	return ""
}

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
	if version == safeVersionString() {
		fmt.Fprintf(stdout, "guardrail already at %s; nothing to do\n", version)
		return 0
	}

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
	// A live approval daemon would keep serving superseded code; shut it down
	// so the next approval spawns a daemon from the new binary.
	_ = shutdownApprovalDaemon(approval.DefaultSocketPath())
	fmt.Fprintf(stdout, "guardrail updated to %s at %s\n", version, exe)
	// Update closes with verification instead of suggesting it: drift and
	// wiring problems surface at the moment they can be attributed to the
	// new binary, and a passing selftest here clears the SessionStart nudge
	// before it ever appears (#53). Both must run the binary just installed
	// — this process is still the superseded release, and its in-process
	// doctor and selftest would report on, and record a pass for, the old
	// version.
	_ = runInstalledBinary(exe, []string{"doctor"}, stdout, stderr)
	if selftestCode := runInstalledBinary(exe, []string{"selftest"}, stdout, stderr); selftestCode != 0 {
		fmt.Fprintln(stderr, "guardrail: selftest failed on the new binary; investigate before continuing")
	}
	return 0
}

// runInstalledBinary executes the freshly installed guardrail with the given
// arguments, streaming its output. A binary that cannot be started is
// reported and counts as a failed step; the update itself has already
// succeeded and is never rolled back here.
var runInstalledBinary = func(exe string, args []string, stdout, stderr io.Writer) int {
	cmd := exec.Command(exe, args...)
	cmd.Stdout, cmd.Stderr = stdout, stderr
	if err := cmd.Run(); err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			return exit.ExitCode()
		}
		fmt.Fprintf(stderr, "guardrail: cannot run the installed binary for %s: %v\n", strings.Join(args, " "), err)
		return 1
	}
	return 0
}

func updateDownload(url string) ([]byte, error) {
	resp, err := updateHTTPClient.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		// Freshly tagged releases publish assets asynchronously; an
		// immediate update races the uploader. Name it so the retry is
		// obvious instead of looking like a missing release.
		return nil, fmt.Errorf("HTTP 404 (release assets may still be publishing; retry in a minute)")
	}
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
