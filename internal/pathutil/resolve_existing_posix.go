//go:build !windows

package pathutil

import "path/filepath"

// ResolveExisting resolves symlinks in an existing path.
func ResolveExisting(path string) (string, error) {
	return filepath.EvalSymlinks(path)
}
