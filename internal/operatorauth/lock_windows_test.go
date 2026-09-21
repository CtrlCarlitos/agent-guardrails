//go:build windows

package operatorauth

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

func TestWindowsEnrollmentLockExclusiveAndReleasable(t *testing.T) {
	dir := t.TempDir()

	release1, err := acquireEnrollmentLock(dir)
	if err != nil {
		t.Fatalf("first acquire failed: %v", err)
	}

	acquired2 := make(chan func(), 1)
	err2 := make(chan error, 1)

	go func() {
		rel, err := acquireEnrollmentLock(dir)
		if err != nil {
			err2 <- err
			return
		}
		acquired2 <- rel
	}()

	select {
	case rel := <-acquired2:
		rel()
		t.Fatal("second acquire succeeded while first was held (expected blocking)")
	case err := <-err2:
		t.Fatalf("second acquire errored prematurely: %v", err)
	case <-time.After(250 * time.Millisecond):
		// Expected: still blocked
	}

	release1()

	var release2 func()
	select {
	case rel := <-acquired2:
		release2 = rel
	case err := <-err2:
		t.Fatalf("second acquire failed after release1: %v", err)
	case <-time.After(2 * time.Second):
		t.Fatal("second acquire timed out waiting for release1")
	}

	release2()

	release3, err := acquireEnrollmentLock(dir)
	if err != nil {
		t.Fatalf("third acquire on leftover lock file failed: %v", err)
	}
	release3()
}

func TestWindowsEnrollmentLockFileShape(t *testing.T) {
	dir := t.TempDir()

	release, err := acquireEnrollmentLock(dir)
	if err != nil {
		t.Fatalf("acquire lock failed: %v", err)
	}
	defer release()

	lockPath := filepath.Join(dir, ".enrollment.lock")
	info, err := os.Lstat(lockPath)
	if err != nil {
		t.Fatalf("stat lock file: %v", err)
	}
	if !info.Mode().IsRegular() {
		t.Fatalf("lock file mode %v is not a regular file", info.Mode())
	}
}

// TestWindowsEnrollmentLockRejectsBroadGroupACE verifies that a lock file
// whose DACL grants Everyone full access is rejected by acquireEnrollmentLock.
// This is the shape produced by directory-ACL inheritance when the parent
// directory has a broad DACL.
func TestWindowsEnrollmentLockRejectsBroadGroupACE(t *testing.T) {
	dir := t.TempDir()

	// Pre-create the lock file so we can manipulate its ACL before acquisition.
	lockPath := filepath.Join(dir, ".enrollment.lock")
	f, err := os.OpenFile(lockPath, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		t.Fatalf("create lock file: %v", err)
	}
	f.Close()

	// Set a protected DACL that grants Everyone (S-1-1-0) full control — the
	// shape that validateACL (via privatefs.ValidateFile) must reject.
	sd, err := windows.SecurityDescriptorFromString("D:P(A;;FA;;;S-1-1-0)")
	if err != nil {
		t.Fatalf("build broad ACL descriptor: %v", err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		t.Fatalf("read DACL: %v", err)
	}
	if err := windows.SetNamedSecurityInfo(lockPath, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, dacl, nil); err != nil {
		t.Fatalf("set broad ACL: %v", err)
	}

	rel, err := acquireEnrollmentLock(dir)
	if err == nil {
		rel() // release so TempDir cleanup can remove the file
		t.Fatal("acquireEnrollmentLock succeeded despite Everyone ACE (expected rejection)")
	}
	if !strings.Contains(err.Error(), "broad group") && !strings.Contains(err.Error(), "private") {
		t.Errorf("unexpected error message %q: expected mention of ACL issue", err.Error())
	}
}

// setFileOwnerForTest replaces the owner of path with NT AUTHORITY\Local Service
// (S-1-5-19), a SID that is neither the current user nor BUILTIN\Administrators.
// It skips the test if the process lacks SeRestorePrivilege, which is required
// to assign ownership to an arbitrary SID.
func setFileOwnerForTest(t *testing.T, path string) {
	t.Helper()
	localServiceSID, err := windows.StringToSid("S-1-5-19")
	if err != nil {
		t.Fatalf("parse Local Service SID: %v", err)
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION,
		localServiceSID, nil, nil, nil); err != nil {
		t.Skipf("cannot change file owner (need SeRestorePrivilege): %v", err)
	}
}

// TestWindowsEnrollmentLockRejectsWrongOwner verifies that a lock file owned
// by an account that is neither the current user nor BUILTIN\Administrators is
// rejected by acquireEnrollmentLock.
func TestWindowsEnrollmentLockRejectsWrongOwner(t *testing.T) {
	dir := t.TempDir()

	lockPath := filepath.Join(dir, ".enrollment.lock")
	f, err := os.OpenFile(lockPath, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		t.Fatalf("create lock file: %v", err)
	}
	f.Close()

	setFileOwnerForTest(t, lockPath)

	rel, err := acquireEnrollmentLock(dir)
	if err == nil {
		rel() // release so TempDir cleanup can remove the file
		t.Fatal("acquireEnrollmentLock succeeded despite wrong-owner file (expected rejection)")
	}
	if !strings.Contains(err.Error(), "owned") && !strings.Contains(err.Error(), "private") {
		t.Errorf("unexpected error message %q: expected mention of ownership", err.Error())
	}
}
