//go:build windows

package privatefs

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

var broadSIDs = map[string]bool{
	"S-1-1-0":      true, // Everyone
	"S-1-5-32-545": true, // BUILTIN\Users
	"S-1-5-11":     true, // Authenticated Users
}

func currentUserSID() (string, error) {
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

func secureDir(path string) error {
	sid, err := currentUserSID()
	if err != nil {
		return err
	}
	sd, err := windows.SecurityDescriptorFromString("D:P(A;OICI;FA;;;" + sid + ")")
	if err != nil {
		return fmt.Errorf("build owner-only security descriptor: %w", err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return fmt.Errorf("read owner-only DACL: %w", err)
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, dacl, nil); err != nil {
		return fmt.Errorf("secure private directory: %w", err)
	}
	return nil
}

func validateACL(path string) error {
	wantOwner, err := currentUserSID()
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
	// Elevated Windows processes create artifacts owned by Administrators,
	// which is the accepted root-equivalent owner. The DACL still must grant
	// no broad group access.
	if owner == nil || (owner.String() != wantOwner && owner.String() != "S-1-5-32-544") {
		return fmt.Errorf("private path %q is not owned by the current principal", path)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return fmt.Errorf("read DACL: %w", err)
	}
	if dacl == nil {
		return fmt.Errorf("private path %q has no DACL", path)
	}
	var offset uintptr
	for i := uint16(0); i < dacl.AceCount; i++ {
		header := (*windows.ACE_HEADER)(unsafe.Pointer(uintptr(unsafe.Pointer(dacl)) + 8 + offset))
		if header.AceType == windows.ACCESS_ALLOWED_ACE_TYPE {
			ace := (*windows.ACCESS_ALLOWED_ACE)(unsafe.Pointer(uintptr(unsafe.Pointer(dacl)) + 8 + offset))
			sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
			if broadSIDs[sid.String()] {
				return fmt.Errorf("private path %q grants access to a broad group", path)
			}
		}
		offset += uintptr(header.AceSize)
	}
	return nil
}
