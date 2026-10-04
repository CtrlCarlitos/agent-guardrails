//go:build windows

package policy

import (
	"os"
	"testing"

	"golang.org/x/sys/windows"
)

// Named TestWindows… so CI's Windows slice runs it.
func TestWindowsOwnershipMatchesGitRule(t *testing.T) {
	dir := t.TempDir()
	// A directory this process just created is owned by the current user, or by
	// Administrators when the process is elevated; either way git accepts it.
	if !ownedByCurrentUserOS(dir) {
		t.Fatalf("%s created by this process must count as owned", dir)
	}
	if ownedByCurrentUserOS(dir + `\does-not-exist`) {
		t.Fatal("a path that cannot be read must not count as owned")
	}
	// A directory owned by another principal is left to git. The system root is owned
	// by TrustedInstaller / SYSTEM, never by the current user or Administrators.
	if root := os.Getenv("SystemRoot"); root != "" && ownedByCurrentUserOS(root) {
		t.Fatalf("%s is system-owned and must go to git", root)
	}
}

func TestWindowsAdministratorsOwnedRepoIsAcceptedForAdminGroupMembers(t *testing.T) {
	token := windows.GetCurrentProcessToken()
	groups, err := token.GetTokenGroups()
	if err != nil {
		t.Skipf("cannot read token groups: %v", err)
	}
	admins, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		t.Fatal(err)
	}
	member := false
	for _, g := range groups.AllGroups() {
		if windows.EqualSid(g.Sid, admins) {
			member = true
		}
	}
	if !member {
		t.Skip("current user is not in Administrators; nothing to prove here")
	}
	// ProgramData\Microsoft\Crypto etc. vary; use a stable Administrators-owned
	// location when present, otherwise skip rather than guess.
	candidate := os.Getenv("ProgramData")
	if candidate == "" {
		t.Skip("ProgramData unavailable")
	}
	sd, err := windows.GetNamedSecurityInfo(candidate, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		t.Skipf("cannot read owner of %s: %v", candidate, err)
	}
	owner, _, err := sd.Owner()
	if err != nil || owner == nil || !windows.EqualSid(owner, admins) {
		t.Skipf("%s is not Administrators-owned on this machine", candidate)
	}
	if !ownedByCurrentUserOS(candidate) {
		t.Fatalf("%s is Administrators-owned and the user is an administrator: git accepts it, so must we", candidate)
	}
}
