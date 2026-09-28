//go:build !windows

package main

// fileInUseByAnotherProcess is Windows-only: POSIX opens do not fail because
// another process holds the file.
func fileInUseByAnotherProcess(error) bool { return false }
