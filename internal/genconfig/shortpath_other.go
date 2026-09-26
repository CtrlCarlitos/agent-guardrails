//go:build !windows

package genconfig

// resolveShortPath has no 8.3 names to offer off Windows: a Windows-shaped
// binary path emitted from another host is never shortened, so the quoted
// spelling stays.
func resolveShortPath(string) (string, bool) { return "", false }
