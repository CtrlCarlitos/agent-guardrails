//go:build !windows

package engine

// hostProbePath reports whether the host OS can probe the existence of path
// using os.Stat, and returns the path to probe.  On Unix the host is POSIX,
// so all paths are probeable as-is.
func hostProbePath(path string) (string, bool) {
	return path, true
}

// hostCanProbe reports whether the host OS can probe the existence of path
// using os.Stat.  On Unix the host is POSIX, so all paths are probeable.
func hostCanProbe(_ string) bool { return true }
