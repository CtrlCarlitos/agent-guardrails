//go:build windows

package operatorauth

import (
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
)

// acquireEnrollmentLock holds an exclusive lock through initial-enrollment
// reread and persistence via Windows LockFileEx. The file may remain after a
// crash; the kernel lock is released automatically when its owning handle/process exits.
func acquireEnrollmentLock(dir string) (func(), error) {
	path := filepath.Join(dir, ".enrollment.lock")
	file, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open enrollment lock: %w", err)
	}
	// Use the shared validator (privatefs.ValidateFile → validateACL on Windows)
	// to enforce owner-SID and deny broad-group ACEs, matching lock_unix.go.
	if err := validateRegularFile(path); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("inspect enrollment lock: %w", err)
	}
	handle := windows.Handle(file.Fd())
	var ol windows.Overlapped
	if err := windows.LockFileEx(handle, windows.LOCKFILE_EXCLUSIVE_LOCK, 0, 1, 0, &ol); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("acquire enrollment lock: %w", err)
	}
	return func() {
		_ = windows.UnlockFileEx(handle, 0, 1, 0, &ol)
		_ = file.Close()
	}, nil
}
