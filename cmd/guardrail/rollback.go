package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/CtrlCarlitos/agent-guardrails/internal/approval"
)

// #94: `guardrail update` keeps the binary it replaces, and `guardrail
// rollback` restores it. The kept binary sits next to the installed one
// (guardrail.previous[.exe]); its record (path, release, SHA-256) lives in
// guardrail's state directory, which sessions cannot edit, so a changed or
// swapped file is refused before anything is touched. A rollback swaps, so it
// can itself be undone, and is verified like an update. Sessions cannot run it
// (#512).

// renameFile is os.Rename; a seam so tests can fail the final move.
var renameFile = os.Rename

// verifyBinaryRuns checks a binary of unknown release still runs as guardrail.
var verifyBinaryRuns = func(path string) error {
	out, err := exec.Command(path, "version").Output()
	if err != nil {
		return fmt.Errorf("binary failed to run: %w", err)
	}
	if !strings.HasPrefix(strings.TrimSpace(string(out)), "guardrail ") {
		return fmt.Errorf("binary reports %q, not a guardrail version", strings.TrimSpace(string(out)))
	}
	return nil
}

type previousRecord struct {
	Path    string `json:"path"`
	Version string `json:"version"` // "" when the kept binary was a dev build
	SHA256  string `json:"sha256"`
	SavedAt string `json:"saved_at"`
}

// previousBinaryPath is where the replaced binary is kept, beside the
// installed one. On Windows it keeps the .exe extension so it can run.
func previousBinaryPath(exe string) string {
	if strings.EqualFold(filepath.Ext(exe), ".exe") {
		return strings.TrimSuffix(exe, filepath.Ext(exe)) + ".previous.exe"
	}
	return exe + ".previous"
}

func previousRecordPath() (string, error) {
	base := os.Getenv("XDG_STATE_HOME")
	if base == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		base = filepath.Join(home, ".local", "state")
	}
	return filepath.Join(base, "guardrail", "previous.json"), nil
}

func loadPreviousRecord() (previousRecord, error) {
	path, err := previousRecordPath()
	if err != nil {
		return previousRecord{}, err
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return previousRecord{}, err
	}
	var rec previousRecord
	if err := json.Unmarshal(raw, &rec); err != nil {
		return previousRecord{}, fmt.Errorf("previous-binary record is unreadable: %w", err)
	}
	return rec, nil
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func copyFile(from, to string) error {
	raw, err := os.ReadFile(from)
	if err != nil {
		return err
	}
	return os.WriteFile(to, raw, 0o755)
}

// stagePrevious copies the installed binary aside before it is replaced. The
// copy only becomes the kept previous binary once the replacement succeeded
// (commitPrevious), so a failed swap never loses the older kept one.
func stagePrevious(exe string) (string, error) {
	staged := filepath.Join(filepath.Dir(exe), ".guardrail-previous")
	_ = os.Remove(staged)
	if err := copyFile(exe, staged); err != nil {
		_ = os.Remove(staged)
		return "", err
	}
	return staged, nil
}

func commitPrevious(staged, exe, release string) error {
	sum, err := fileSHA256(staged)
	if err != nil {
		return err
	}
	kept := previousBinaryPath(exe)
	_ = os.Remove(kept)
	if err := renameFile(staged, kept); err != nil {
		return err
	}
	recPath, err := previousRecordPath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(recPath), 0o700); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(previousRecord{Path: kept, Version: release, SHA256: sum, SavedAt: time.Now().UTC().Format(time.RFC3339)}, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(recPath, append(raw, '\n'), 0o600)
}

// replaceInstalledBinary moves staged onto exe. On Windows the running image
// cannot be overwritten, so it is renamed aside first; if the final move then
// fails, the binary is put back rather than leaving the install path empty.
// The rename-aside can transiently fail while a scanner holds the file from a
// prior cycle, hence the bounded retry (#205).
func replaceInstalledBinary(exe, staged string) error {
	superseded := exe + ".old"
	if runtime.GOOS == "windows" {
		var asideErr error
		for attempt := 0; attempt < 3; attempt++ {
			if asideErr = renameFile(exe, superseded); asideErr == nil {
				break
			}
			time.Sleep(time.Duration(250*(attempt+1)) * time.Millisecond)
		}
		if asideErr != nil {
			_ = os.Remove(staged)
			return fmt.Errorf("cannot set aside %s: %w", exe, asideErr)
		}
	}
	if err := renameFile(staged, exe); err != nil {
		_ = os.Remove(staged)
		if runtime.GOOS == "windows" {
			if restoreErr := renameFile(superseded, exe); restoreErr != nil {
				return fmt.Errorf("cannot replace %s (%v), and putting the previous binary back from %s also failed (%v); move it back by hand", exe, err, superseded, restoreErr)
			}
			return fmt.Errorf("cannot replace %s (%v); the binary that was there is back in place", exe, err)
		}
		return fmt.Errorf("cannot replace %s: %w", exe, err)
	}
	return nil
}

func cmdRollback(args []string, stdout, stderr io.Writer) int {
	if len(args) != 0 {
		fmt.Fprintln(stderr, "guardrail: rollback takes no arguments; it restores the binary the last update replaced")
		return 2
	}
	exe, err := updateTargetPath()
	if err == nil {
		exe, err = filepath.Abs(exe)
	}
	if err != nil {
		fmt.Fprintf(stderr, "guardrail: cannot locate running binary: %v\n", err)
		return 1
	}
	rec, err := loadPreviousRecord()
	if errors.Is(err, os.ErrNotExist) {
		fmt.Fprintln(stderr, "guardrail: no previous binary is kept; nothing to roll back to (an update from this release or later keeps one)")
		return 2
	}
	if err != nil {
		fmt.Fprintf(stderr, "guardrail: refusing rollback: %v; nothing was changed\n", err)
		return 1
	}
	refuse := func(why string) int {
		fmt.Fprintf(stderr, "guardrail: refusing rollback: %s; nothing was changed\n", why)
		return 1
	}
	kept := previousBinaryPath(exe)
	if !strings.EqualFold(filepath.Clean(rec.Path), filepath.Clean(kept)) {
		return refuse("the kept binary was recorded for another install (" + rec.Path + ")")
	}
	sum, err := fileSHA256(kept)
	if err != nil {
		return refuse("the kept binary is missing: " + err.Error())
	}
	if sum != rec.SHA256 {
		return refuse("the kept binary changed since it was recorded")
	}

	dir := filepath.Dir(exe)
	staged := filepath.Join(dir, ".guardrail-update")
	_ = os.Remove(staged)
	_ = os.Remove(exe + ".old")
	if err := copyFile(kept, staged); err != nil {
		_ = os.Remove(staged)
		return refuse("cannot stage the kept binary: " + err.Error())
	}
	verify := func() error { return verifyBinaryRuns(staged) }
	if rec.Version != "" {
		verify = func() error { return verifyUpdatedBinary(staged, rec.Version) }
	}
	if err := verify(); err != nil {
		_ = os.Remove(staged)
		return refuse("the kept binary does not run: " + err.Error())
	}
	rolledFrom, err := stagePrevious(exe)
	if err != nil {
		_ = os.Remove(staged)
		return refuse("cannot keep the current binary: " + err.Error())
	}
	if err := replaceInstalledBinary(exe, staged); err != nil {
		_ = os.Remove(rolledFrom)
		return refuse(err.Error())
	}
	if err := commitPrevious(rolledFrom, exe, safeVersionString()); err != nil {
		fmt.Fprintf(stderr, "guardrail: warning: the rolled-back-from binary was not kept (%v); a further rollback is unavailable\n", err)
	}
	_ = shutdownApprovalDaemon(approval.DefaultSocketPath())
	restored := rec.Version
	if restored == "" {
		restored = "the previous binary"
	}
	fmt.Fprintf(stdout, "guardrail rolled back to %s at %s\n", restored, exe)

	var failed []string
	for _, step := range []string{"doctor", "selftest"} {
		if code := runInstalledBinary(exe, []string{step}, stdout, stderr); code != 0 && code != exitOperatorActionPending {
			fmt.Fprintf(stderr, "guardrail: %s failed on the restored binary (exit %d)\n", step, code)
			failed = append(failed, step)
		}
	}
	if len(failed) > 0 {
		fmt.Fprintf(stderr, "guardrail: %s is already restored to %s and post-rollback verification failed (%s); `guardrail rollback` again returns to the binary rolled back from\n",
			exe, restored, strings.Join(failed, ", "))
		return 1
	}
	return 0
}
