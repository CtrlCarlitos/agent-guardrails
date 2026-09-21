//go:build !windows

package operatorauth_test

import (
	"os"
	"testing"
)

func widenCredentialDirForTest(t *testing.T, path string) {
	t.Helper()
	if err := os.Chmod(path, 0o755); err != nil {
		t.Fatal(err)
	}
}
