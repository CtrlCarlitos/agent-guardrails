//go:build windows

package main

import (
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

// ownerSIDString returns the current process user's SID in string form.
func ownerSIDString() (string, error) {
	token, err := windows.OpenCurrentProcessToken()
	if err != nil {
		return "", fmt.Errorf("open process token: %w", err)
	}
	defer token.Close()
	user, err := token.GetTokenUser()
	if err != nil {
		return "", fmt.Errorf("read token user: %w", err)
	}
	return user.User.Sid.String(), nil
}

// broadSIDs name group SIDs that must never hold an allow ACE on a private
// allowance artifact. Administrators and SYSTEM retain access, as root does
// on Unix — the accepted equivalence (ADR-0021 §3).
var broadSIDs = map[string]bool{
	"S-1-1-0":      true, // Everyone
	"S-1-5-32-545": true, // BUILTIN\Users
	"S-1-5-11":     true, // Authenticated Users
}

// validatePrivateACL reads the artifact's security info and requires: owner
// is the current user, a DACL is present, and no allow ACE grants a broad
// group. This replaces the Unix 0600/0700 mode-bit invariant (ADR-0021 §3).
func validatePrivateACL(path string) error {
	wantOwner, err := ownerSIDString()
	if err != nil {
		return err
	}
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return fmt.Errorf("read security info: %w", err)
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return fmt.Errorf("read owner: %w", err)
	}
	if owner == nil || owner.String() != wantOwner {
		return fmt.Errorf("allowance path is not owned by the current user")
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return fmt.Errorf("read DACL: %w", err)
	}
	if dacl == nil {
		return fmt.Errorf("allowance path has no DACL")
	}
	var walk uintptr
	for i := uint16(0); i < dacl.AceCount; i++ {
		header := (*windows.ACE_HEADER)(unsafe.Pointer(uintptr(unsafe.Pointer(dacl)) + 8 + walk))
		if header.AceType == windows.ACCESS_ALLOWED_ACE_TYPE {
			ace := (*windows.ACCESS_ALLOWED_ACE)(unsafe.Pointer(uintptr(unsafe.Pointer(dacl)) + 8 + walk))
			sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
			if broadSIDs[sid.String()] {
				return fmt.Errorf("allowance path grants access to a broad group")
			}
		}
		walk += uintptr(header.AceSize)
	}
	return nil
}

// validatePrivateFile enforces the owner-only invariant of allowance files on
// Windows: a regular file (reparse points report as non-regular) whose ACL
// satisfies validatePrivateACL.
func validatePrivateFile(path string, info os.FileInfo) error {
	if !info.Mode().IsRegular() {
		return fmt.Errorf("allowance file is not a regular file")
	}
	return validatePrivateACL(path)
}

// validatePrivateDir enforces the owner-only invariant of the allowance
// journal directory on Windows via its ACL.
func validatePrivateDir(path string, info os.FileInfo) error {
	if !info.IsDir() {
		return fmt.Errorf("allowance path is not a directory")
	}
	return validatePrivateACL(path)
}

// securePrivateDir stamps the owner-only protected DACL on a private
// directory (ADR-0021 §3): artifacts created inside inherit the owner-only
// grant, which writeSyncedPrivateFile's temp+rename then preserves. The
// creator becomes the owner by default; validatePrivateACL checks it.
func securePrivateDir(dir string) error {
	sid, err := ownerSIDString()
	if err != nil {
		return err
	}
	sd, err := windows.SecurityDescriptorFromString("D:P(A;OICI;FA;;;" + sid + ")")
	if err != nil {
		return fmt.Errorf("build owner-only security descriptor: %w", err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, dacl, nil)
}
