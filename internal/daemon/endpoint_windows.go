//go:build windows

package daemon

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

const pipePrefix = `\\.\pipe\`

// DefaultEndpoint derives the per-user engine pipe name from LOCALAPPDATA.
func DefaultEndpoint() string {
	stateRoot := filepath.Join(os.Getenv("LOCALAPPDATA"), "guardrail")
	digest := sha256.Sum256([]byte(stateRoot))
	return fmt.Sprintf(`%sguardrail-engine-%x`, pipePrefix, digest[:8])
}

// TestEndpoint generates a unique named pipe path for tests.
func TestEndpoint(t *testing.T, dir string) string {
	t.Helper()
	digest := sha256.Sum256([]byte(dir))
	return fmt.Sprintf(`%stest-guardrail-engine-%x`, pipePrefix, digest[:8])
}
