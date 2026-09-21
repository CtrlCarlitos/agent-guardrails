// Package engine — shell-lexical POSIX path helpers.
//
// These functions reason about POSIX Bash shell grammar, not the host
// filesystem.  They must never call filepath.* or os.*; they are
// intentionally host-independent so they produce the same result on
// Linux, macOS, and Windows.
package engine

import (
	"path"
	"strings"
)

// posixIsAbs reports whether p is absolute in POSIX shell grammar: a
// leading '/' is the only absolute indicator.  This is intentionally
// different from filepath.IsAbs, which uses Win32 semantics on Windows
// and does not recognize '/' as absolute.
func posixIsAbs(p string) bool {
	return len(p) > 0 && p[0] == '/'
}

// posixClean returns the shortest POSIX lexical form of p.  It
// delegates to path.Clean (the standard-library POSIX-only cleaner)
// rather than filepath.Clean, which would rewrite separators on Windows.
func posixClean(p string) string {
	return path.Clean(p)
}

// posixJoin joins the path elements using '/' as separator.  Unlike
// filepath.Join it never uses the host separator.
func posixJoin(elem ...string) string {
	return path.Join(elem...)
}

// posixSplitList splits a POSIX-style path list on ':'.  It is the
// POSIX equivalent of filepath.SplitList, which uses ';' on Windows.
func posixSplitList(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(s, ":")
}

// posixStandardDevice reports whether p is one of the four POSIX
// standard output/error devices recognized by the redirect-only
// exemption in the Bash analysis.  The check uses POSIX lexical
// normalization (posixClean) so /dev/./null also matches.
//
// The exemption is intentionally narrow:
//   - redirect-only context (enforced by the caller)
//   - exact path (no child paths, no /proc/self/fd/N aliases)
//   - no volume names or Win32 spellings (NUL is not in this list)
func posixStandardDevice(p string) bool {
	switch posixClean(p) {
	case "/dev/null", "/dev/stdout", "/dev/stderr", "/dev/tty":
		return true
	}
	return false
}
