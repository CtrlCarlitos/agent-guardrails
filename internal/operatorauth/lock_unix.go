//go:build !windows

package operatorauth

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// acquireEnrollmentLock holds an advisory lock through the initial-enrollment
// reread and persistence. The file may remain after a crash; the kernel lock
// is released automatically when its owning process exits.
func acquireEnrollmentLock(dir string) (func(), error) {
	path := filepath.Join(dir, ".enrollment.lock")
	file, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open enrollment lock: %w", err)
	}
	if err := validateRegularFile(path); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("inspect enrollment lock: %w", err)
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("acquire enrollment lock: %w", err)
	}
	return func() {
		_ = syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
		_ = file.Close()
	}, nil
}
