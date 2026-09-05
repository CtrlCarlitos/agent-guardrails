package pathutil

import (
	"os"
	"path/filepath"
)

// ResolveThroughExistingAncestor resolves symlinks in the nearest existing
// ancestor, then appends and cleans any missing path suffix.
func ResolveThroughExistingAncestor(path string) (string, error) {
	current := filepath.Clean(path)
	var missing []string
	for {
		if _, err := os.Lstat(current); err == nil {
			resolved, err := filepath.EvalSymlinks(current)
			if err != nil {
				return "", err
			}
			for i := len(missing) - 1; i >= 0; i-- {
				resolved = filepath.Join(resolved, missing[i])
			}
			return filepath.Clean(resolved), nil
		} else if !os.IsNotExist(err) {
			return "", err
		} else {
			parent := filepath.Dir(current)
			if parent == current {
				return "", err
			}
			missing = append(missing, filepath.Base(current))
			current = parent
		}
	}
}
