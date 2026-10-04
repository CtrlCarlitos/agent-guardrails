//go:build !windows

package policy

import (
	"os"
	"syscall"
)

// ownedByCurrentUserOS reports whether path is owned by the effective user. Only an
// exact match counts: a root-owned or foreign-owned path is left to git.
func ownedByCurrentUserOS(path string) bool {
	fi, err := os.Lstat(path)
	if err != nil {
		return false
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	return ok && int(st.Uid) == os.Geteuid()
}

// deviceID identifies the filesystem holding path, for git's mount-boundary stop.
func deviceID(path string) (uint64, bool) {
	fi, err := os.Stat(path)
	if err != nil {
		return 0, false
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return uint64(st.Dev), true //nolint:unconvert // Dev is int32 on darwin, uint64 on linux
}
