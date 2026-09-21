//go:build windows

package engine

import "path/filepath"

// hostCanProbe reports whether the host OS can probe the existence of
// path using os.Stat.
//
// On Windows only Win32-absolute paths (drive letters such as C:\,
// UNC paths such as \\server\share) are resolvable through the Win32
// filesystem APIs used by os.Stat.  POSIX-absolute paths (starting
// with '/') — including Git Bash / MSYS2 drive-mapped forms such as
// /c/repo — are not resolvable: os.Stat returns ERROR_FILE_NOT_FOUND
// regardless of whether the mapped directory exists.
//
// When hostCanProbe returns false, cdDirectoryState must return
// cdDirectoryUnknown (fail-closed) rather than cdDirectoryMissing,
// preserving the conservative both-branches-carried behavior.
//
// Note: the failure to probe POSIX-absolute paths on Windows is an
// accepted narrowing (see ADR-0023 §Consequences). Git Bash users whose
// CWD and RepoRoot are supplied as POSIX drive paths (/c/repo) will
// receive conservative ask verdicts for all absolute cd targets.
func hostCanProbe(path string) bool {
	return filepath.IsAbs(path)
}
