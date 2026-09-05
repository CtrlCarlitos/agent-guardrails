package pathutil

import (
	"os"
	"path/filepath"
)

// ResolveThroughExistingAncestor resolves symlinks in the nearest existing
// ancestor, then appends and cleans any missing path suffix.
func ResolveThroughExistingAncestor(path string) (string, error) {
	current := path
	if current == "" {
		current = "."
	}
	var missing []string
	for {
		if _, err := os.Lstat(current); err == nil {
			resolved, err := filepath.EvalSymlinks(current)
			if err != nil {
				return "", err
			}
			for i := len(missing) - 1; i >= 0; i-- {
				if len(resolved) > 0 && !os.IsPathSeparator(resolved[len(resolved)-1]) {
					resolved += string(filepath.Separator)
				}
				resolved += missing[i]
			}
			return filepath.Clean(resolved), nil
		} else if !os.IsNotExist(err) {
			return "", err
		} else {
			parent, component, ok := peelTrailingComponent(current)
			if !ok {
				return "", err
			}
			missing = append(missing, component)
			current = parent
		}
	}
}

func peelTrailingComponent(path string) (string, string, bool) {
	volumeLen := len(filepath.VolumeName(path))
	end := len(path)
	for end > volumeLen && os.IsPathSeparator(path[end-1]) {
		end--
	}
	if end == volumeLen {
		return "", "", false
	}
	start := end
	for start > volumeLen && !os.IsPathSeparator(path[start-1]) {
		start--
	}
	parent := path[:start]
	if parent == "" {
		parent = "."
	}
	return parent, path[start:end], true
}
