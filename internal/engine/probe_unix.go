//go:build !windows

package engine

// hostCanProbe reports whether the host OS can probe the existence of
// path using os.Stat.  On Unix the host is POSIX, so all paths are
// probeable.
func hostCanProbe(_ string) bool { return true }
