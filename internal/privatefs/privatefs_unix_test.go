//go:build !windows

package privatefs

import (
	"os"
	"path/filepath"
	"testing"
)

func TestValidateDirRejectsGroupOrOtherPermissions(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "broad")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := ValidateDir(dir); err == nil {
		t.Fatal("directory with group/other permissions validated as private")
	}
}
