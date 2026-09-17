//go:build !windows

package operatorauth

import (
	"os"
	"os/exec"
	"testing"
)

func TestEnrollmentLockReleasedWhenHolderExits(t *testing.T) {
	dir := os.Getenv("GUARDRAIL_ENROLLMENT_LOCK_DIR")
	if dir == "" {
		dir = t.TempDir()
	}
	if os.Getenv("GUARDRAIL_ENROLLMENT_LOCK_HELPER") == "1" {
		if _, err := acquireEnrollmentLock(dir); err != nil {
			os.Exit(1)
		}
		os.Exit(0) // Simulate process exit without an explicit unlock.
	}

	cmd := exec.Command(os.Args[0], "-test.run=TestEnrollmentLockReleasedWhenHolderExits")
	cmd.Env = append(os.Environ(), "GUARDRAIL_ENROLLMENT_LOCK_HELPER=1", "GUARDRAIL_ENROLLMENT_LOCK_DIR="+dir)
	if err := cmd.Run(); err != nil {
		t.Fatalf("lock-holder helper: %v", err)
	}
	release, err := acquireEnrollmentLock(dir)
	if err != nil {
		t.Fatalf("lock remained held after holder exit: %v", err)
	}
	release()
}
