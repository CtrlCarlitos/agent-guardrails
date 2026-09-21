//go:build !windows

package main

// MkdirAll's requested mode is the creation path on Unix. Existing broad
// permissions must remain visible to validatePrivateDir and fail closed.
func securePrivateDir(string) error { return nil }
