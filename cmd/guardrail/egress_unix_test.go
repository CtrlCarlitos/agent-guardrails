//go:build !windows

package main

// widenArtifactForTest is the Unix no-op: directory mode bits already carry
// the unsafe shape the tests construct.
func widenArtifactForTest(path string) error { return nil }
