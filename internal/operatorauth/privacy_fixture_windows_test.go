//go:build windows

package operatorauth_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/CtrlCarlitos/agent-guardrails/internal/operatorauth"
	"golang.org/x/sys/windows"
)

func TestWindowsCredentialDirectoryRejectsBroadGroupACL(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "operator-auth")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	widenCredentialDirForTest(t, dir)
	credential := operatorauth.Credential{ID: "AQI", PublicKey: "public", Algorithm: -7}
	if err := operatorauth.NewStore(root).Replace([]operatorauth.Credential{credential}); err == nil {
		t.Fatal("Replace succeeded in directory granting Everyone access")
	}
}

func widenCredentialDirForTest(t *testing.T, path string) {
	t.Helper()
	sd, err := windows.SecurityDescriptorFromString("D:P(A;OICI;FA;;;S-1-1-0)")
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, dacl, nil); err != nil {
		t.Fatal(err)
	}
}
