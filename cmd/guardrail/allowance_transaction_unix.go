//go:build !windows

package main

import (
	"fmt"
	"os"
	"syscall"
)

func validateAllowanceOwner(info os.FileInfo) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(stat.Uid) != os.Getuid() {
		return fmt.Errorf("allowance path is not owned by the current user")
	}
	return nil
}

// validatePrivateFile enforces the 0600 owner-only invariant of allowance
// artifacts on Unix: a regular file, exactly owner read/write, owned by the
// current user.
func validatePrivateFile(path string, info os.FileInfo) error {
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		return fmt.Errorf("allowance file is not a private regular file")
	}
	return validateAllowanceOwner(info)
}

// validatePrivateDir enforces the 0700 owner-only invariant of the allowance
// journal directory on Unix.
func validatePrivateDir(path string, info os.FileInfo) error {
	if info.Mode().Perm() != 0o700 {
		return fmt.Errorf("allowance directory is not 0700")
	}
	return validateAllowanceOwner(info)
}

// securePrivateDir is a no-op on Unix: MkdirAll's 0700 already carries the
// privacy invariant.
func securePrivateDir(dir string) error { return nil }
