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
