package adapter

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
)

// applyPatchPaths returns the files an apply_patch envelope touches, for Codex
// (tool_input.command) and OpenCode (arguments.patchText, #480). The envelope
// must open with "*** Begin Patch", close with "*** End Patch" and name at
// least one file operation; anything else is an error and the call fails
// closed. Move destinations are included as well as sources. Relative paths
// resolve against cwd. Deleted files are evaluated before execution but
// omitted after it, and a move's source is replaced by its destination, so
// recipes never format a file that no longer exists. CRLF line endings are
// accepted.
func applyPatchPaths(patch, cwd string, post bool) ([]string, error) {
	lines := strings.Split(strings.TrimSpace(strings.ReplaceAll(patch, "\r\n", "\n")), "\n")
	if len(lines) < 3 || lines[0] != "*** Begin Patch" || lines[len(lines)-1] != "*** End Patch" {
		return nil, errors.New("invalid apply_patch envelope")
	}
	var paths []string
	headers := 0
	for _, line := range lines[1 : len(lines)-1] {
		for _, header := range []string{"*** Add File: ", "*** Update File: ", "*** Delete File: ", "*** Move to: "} {
			if !strings.HasPrefix(line, header) {
				continue
			}
			headers++
			path := strings.TrimPrefix(line, header)
			if strings.TrimSpace(path) == "" {
				return nil, errors.New("empty apply_patch path")
			}
			if post && header == "*** Delete File: " {
				continue
			}
			if post && header == "*** Move to: " && len(paths) > 0 {
				paths = paths[:len(paths)-1]
			}
			if !rootedPath(path) {
				path = filepath.Join(cwd, path)
			}
			paths = append(paths, path)
		}
	}
	if headers == 0 {
		return nil, errors.New("apply_patch has no file operations")
	}
	return paths, nil
}

// rootedPath reports a path that must not be joined to the cwd. On Windows
// that is more than filepath.IsAbs: `\Users\me\.ssh\id_rsa` and `C:x` name a
// file on a drive, not under the cwd, and joining them would hand the Engine
// an innocent in-repo path for a secret one. The Engine resolves them itself.
func rootedPath(path string) bool {
	return filepath.IsAbs(path) || filepath.VolumeName(path) != "" || os.IsPathSeparator(path[0])
}
