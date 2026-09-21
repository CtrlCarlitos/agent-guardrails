//go:build windows

package privatefs

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

func TestWindowsValidateDirRejectsBroadGroupACL(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "broad")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	sd, err := windows.SecurityDescriptorFromString("D:P(A;OICI;FA;;;S-1-1-0)")
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, dacl, nil); err != nil {
		t.Fatal(err)
	}
	if err := ValidateDir(dir); err == nil {
		t.Fatal("directory granting Everyone access validated as private")
	}
	if err := SecureDir(dir); err != nil {
		t.Fatal(err)
	}
	if err := ValidateDir(dir); err != nil {
		t.Fatalf("re-secured directory did not validate: %v", err)
	}
}
