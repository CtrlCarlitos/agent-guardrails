//go:build windows

package genconfig

import (
	"syscall"
	"unsafe"
)

var procGetShortPathName = syscall.NewLazyDLL("kernel32.dll").NewProc("GetShortPathNameW")

// resolveShortPath asks Windows for a path's 8.3 name. It needs the file to
// exist, so it fails for a binary path emitted for another host; the caller
// then keeps the quoted spelling. It returns the long name unchanged when the
// volume has 8.3 creation off, which the caller checks for.
func resolveShortPath(path string) (string, bool) {
	in, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return "", false
	}
	buf := make([]uint16, syscall.MAX_PATH)
	for range 2 {
		n, _, _ := procGetShortPathName.Call(uintptr(unsafe.Pointer(in)), uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
		switch {
		case n == 0:
			return "", false
		case int(n) > len(buf):
			buf = make([]uint16, n)
		default:
			return syscall.UTF16ToString(buf[:n]), true
		}
	}
	return "", false
}
