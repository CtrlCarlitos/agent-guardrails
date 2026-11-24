package pathutil

import (
	"errors"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
)

// ResolveExisting resolves symlinks in an existing path.
func ResolveExisting(path string) (string, error) {
	resolved, err := filepath.EvalSymlinks(path)
	if !errors.Is(err, os.ErrPermission) {
		return resolved, err
	}
	// Opening a path through the Windows API can collapse ".." before
	// traversing a link. Only the component-wise resolver can prove that case.
	for _, part := range strings.FieldsFunc(path, func(c rune) bool { return c == '/' || c == '\\' }) {
		if part == ".." {
			return "", err
		}
	}
	// A sandbox may allow opening the target while blocking traversal of
	// an ancestor during EvalSymlinks. Verify the physical target by handle.
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return "", err
	}
	handle, err := windows.CreateFile(name, windows.FILE_READ_ATTRIBUTES,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		return "", err
	}
	defer windows.CloseHandle(handle)
	buf := make([]uint16, 32768)
	n, err := windows.GetFinalPathNameByHandle(handle, &buf[0], uint32(len(buf)), 0)
	if err != nil {
		return "", err
	}
	if n == 0 || n >= uint32(len(buf)) {
		return "", &os.PathError{Op: "resolve", Path: path, Err: windows.ERROR_BAD_PATHNAME}
	}
	resolved = windows.UTF16ToString(buf[:n])
	if unc, ok := strings.CutPrefix(resolved, `\\?\UNC\`); ok {
		resolved = `\\` + unc
	} else {
		resolved = strings.TrimPrefix(resolved, `\\?\`)
	}
	if !filepath.IsAbs(resolved) {
		return "", &os.PathError{Op: "resolve", Path: path, Err: windows.ERROR_BAD_PATHNAME}
	}
	return resolved, nil
}
