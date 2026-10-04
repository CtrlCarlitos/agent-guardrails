//go:build windows

package policy

import "golang.org/x/sys/windows"

// ownedByCurrentUserOS mirrors git for Windows' ownership rule for a repository
// ("dubious ownership"): the owner is the current user, or it is BUILTIN\Administrators
// and the current user belongs to that group. A repository an elevated shell created
// (for example by `dot up`) is owned by Administrators even when a normal session later
// uses it, and git accepts that; refusing it would send every such call back to a
// ~60 ms git spawn. A group present only as "deny-only" in a filtered (non-elevated)
// token still counts, as it does for git. Any other owner returns false and is left
// to git.
func ownedByCurrentUserOS(path string) bool {
	token := windows.GetCurrentProcessToken()
	user, err := token.GetTokenUser()
	if err != nil {
		return false
	}
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return false
	}
	owner, _, err := sd.Owner()
	if err != nil || owner == nil {
		return false
	}
	if windows.EqualSid(owner, user.User.Sid) {
		return true
	}
	admins, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil || !windows.EqualSid(owner, admins) {
		return false
	}
	groups, err := token.GetTokenGroups()
	if err != nil {
		return false
	}
	for _, g := range groups.AllGroups() {
		if windows.EqualSid(g.Sid, admins) {
			return true
		}
	}
	return false
}

// deviceID has no cheap Windows equivalent; git's mount-boundary stop is not applied.
func deviceID(string) (uint64, bool) { return 0, false }
