//go:build windows

package engine

import "path/filepath"

// hostProbePath reports whether the host OS can probe the existence of path
// using os.Stat, and returns the Win32 host path to probe.
//
// On Windows:
//   - Win32-absolute paths (drive letters such as C:\, UNC paths such as \\server\share)
//     are probeable as-is.
//   - MSYS2 / Git-Bash single-letter drive paths (/c, /c/Users/...) are translated
//     to their Win32 drive forms (C:\, C:\Users\...) via posixDriveToWin32 and can be
//     probed.
//   - Non-drive POSIX-absolute paths (/etc, /usr, /dev/null) cannot be probed and return
//     ("", false).
//
// When hostProbePath returns false, cdDirectoryState must return cdDirectoryUnknown
// (fail-closed) rather than cdDirectoryMissing, preserving the conservative
// both-branches-carried behavior (ADR-0023).
func hostProbePath(path string) (string, bool) {
	if filepath.IsAbs(path) {
		return filepath.Clean(path), true
	}
	if winPath, ok := posixDriveToWin32(path); ok {
		return filepath.Clean(winPath), true
	}
	return "", false
}

// hostCanProbe reports whether the host OS can probe the existence of path
// using os.Stat.
func hostCanProbe(path string) bool {
	_, ok := hostProbePath(path)
	return ok
}
