//go:build windows

package operatorauth

import (
	"os"
	"path/filepath"
	"testing"
	"time"
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
