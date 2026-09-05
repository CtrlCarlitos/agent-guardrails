package main

import (
	"fmt"
	"os/exec"
	"path/filepath"
)

func resolveBinaryPath(binary string) (string, error) {
	if filepath.IsAbs(binary) {
		return filepath.Clean(binary), nil
	}
	if filepath.Base(binary) != binary {
		absolute, err := filepath.Abs(binary)
		if err != nil {
			return "", fmt.Errorf("cannot make binary path %q absolute: %w", binary, err)
		}
		return filepath.Clean(absolute), nil
	}

	resolved, err := exec.LookPath(binary)
	if err != nil {
		return "", fmt.Errorf("executable %q not found in PATH", binary)
	}
	absolute, err := filepath.Abs(resolved)
	if err != nil {
		return "", fmt.Errorf("cannot make resolved binary path %q absolute: %w", resolved, err)
	}
	return filepath.Clean(absolute), nil
}
