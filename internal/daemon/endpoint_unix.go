//go:build !windows

package daemon

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// DefaultEndpoint derives the per-user socket path on Unix.
func DefaultEndpoint() string {
	runtimeDir := os.Getenv("XDG_RUNTIME_DIR")
	if runtimeDir == "" {
		runtimeDir = filepath.Join(os.TempDir(), fmt.Sprintf("guardrail-%d", os.Getuid()))
	}
	return filepath.Join(runtimeDir, "engine.sock")
}

// TestEndpoint generates a unique socket path for tests.
func TestEndpoint(t *testing.T, dir string) string {
	t.Helper()
	digest := sha256.Sum256([]byte(dir))
	return filepath.Join(dir, fmt.Sprintf("test-engine-%x.sock", digest[:8]))
}
