//go:build windows

package operatorauth

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
)

func validateLockFile(path string) error {
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect enrollment lock: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("enrollment lock is not a regular file")
	}
	return nil
}

// acquireEnrollmentLock holds an exclusive lock through initial-enrollment
// reread and persistence via Windows LockFileEx. The file may remain after a
// crash; the kernel lock is released automatically when its owning handle/process exits.
func acquireEnrollmentLock(dir string) (func(), error) {
	path := filepath.Join(dir, ".enrollment.lock")
	file, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open enrollment lock: %w", err)
	}
	if err := validateLockFile(path); err != nil {
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
