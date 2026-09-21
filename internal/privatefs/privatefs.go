// Package privatefs enforces the repository's owner-only filesystem invariant
// using Unix mode bits or Windows ownership and DACLs as appropriate.
package privatefs

import (
	"fmt"
	"os"
)

// SecureDir applies the host's owner-only protection to an existing real
// directory and verifies the result.
func SecureDir(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect private directory: %w", err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("private path %q is not a real directory", path)
	}
	if err := secureDir(path); err != nil {
		return err
	}
	return validateACL(path)
}

// ValidateDir requires an existing real directory protected for its owner.
func ValidateDir(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect private directory: %w", err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("private path %q is not a real directory", path)
	}
	return validateACL(path)
}

// ValidateFile requires an existing private regular file, never a symlink or
// another special filesystem object.
func ValidateFile(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect private file: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("private path %q is not a regular file", path)
	}
	return validateACL(path)
}
