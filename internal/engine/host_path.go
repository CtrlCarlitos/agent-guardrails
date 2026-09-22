// Package engine — the seam between POSIX shell coordinates and host ones.
//
// A Bash command's path tokens are written in POSIX shell grammar;
// ToolCall.CWD and ToolCall.RepoRoot are host paths.  On Linux and macOS the
// two dialects coincide and everything here is the identity.  On Windows they
// do not: filepath.IsAbs("/etc") is false, so filepath.Join(`C:\repo`, "/etc")
// is `C:\repo\etc` and every POSIX absolute path silently became
// repo-relative, landed inside the repository, and was authorized (#255).
//
// The translation is lexical, in the spirit of posix_path.go and ADR-0023: no
// probing, no fstab reading, no environment simulation (ADR-0012).  A path
// this host cannot address is reported as such rather than guessed at, which
// routes the token to the rule that owns its risk.
package engine

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// posixTempToHost maps a POSIX /tmp path onto the host's temp root.  Under Git
// Bash /tmp is a real writable directory, so the honest translation is the
// host temp root rather than "nowhere".  Doing it here means the System temp
// write seam then applies to it unchanged: descendants stay an authorized
// write target because os.TempDir() is already an authorized root, while the
// root itself and any escape out of it (/tmp/../etc) are protected by the same
// containment logic that already protects os.TempDir() — filepath.Join cleans
// the escape back out of the root, so no separate check is needed.
//
// On POSIX hosts /tmp needs no mapping: it is already a host path, and
// systemTempRoots names it directly.
func posixTempToHost(p string) (string, bool) {
	if runtime.GOOS != "windows" {
		return "", false
	}
	rest, ok := strings.CutPrefix(p, "/tmp")
	if !ok || (rest != "" && rest[0] != '/') {
		return "", false
	}
	if rest = strings.TrimPrefix(rest, "/"); rest == "" {
		return filepath.Clean(os.TempDir()), true
	}
	return filepath.Join(os.TempDir(), filepath.FromSlash(rest)), true
}

// hostPathForPosix translates a POSIX path token into host coordinates,
// reporting whether this host can address it at all.
//
// A relative token is left alone for the caller to join against its cwd.  An
// absolute one is mappable when the host dialect is POSIX (Linux, macOS), when
// it names a drive the MSYS convention spells out (/c/repo/x -> C:\repo\x), or
// when it is under /tmp.  Anything else — "/etc", "/", "/dev/null/child" — is
// genuinely not a location on a Win32 host, and saying so is what lets
// containment give the answer it gives on Linux.
func hostPathForPosix(p string) (host string, mapped bool) {
	if !posixIsAbs(p) || filepath.IsAbs(p) {
		return p, true
	}
	if host, ok := posixTempToHost(p); ok {
		return host, true
	}
	if host, ok := posixDriveToWin32(p); ok {
		return filepath.Clean(host), true
	}
	return "", false
}

// unmappablePosixAbsolute reports whether p is absolute in POSIX shell grammar
// and names no location this host can address.  Such a path is outside every
// root by construction; it must never be folded into one by a dialect
// mismatch.  Always false on POSIX hosts, where the dialects coincide.
func unmappablePosixAbsolute(p string) bool {
	_, mapped := hostPathForPosix(p)
	return !mapped
}
