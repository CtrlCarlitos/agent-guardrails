//go:build !windows

package privatefs

import (
	"fmt"
	"os"
	"syscall"
)

func secureDir(path string) error {
	if err := os.Chmod(path, 0o700); err != nil {
		return fmt.Errorf("secure private directory: %w", err)
	}
	return nil
}

func validateACL(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	want := os.FileMode(0o600)
	if info.IsDir() {
		want = 0o700
	}
	if info.Mode().Perm() != want {
		return fmt.Errorf("private path %q has mode %04o, want %04o", path, info.Mode().Perm(), want)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(stat.Uid) != os.Getuid() {
		return fmt.Errorf("private path %q is not owned by the current user", path)
	}
	return nil
}
