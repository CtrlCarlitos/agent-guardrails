//go:build windows

package operatorauth

// Windows does not support the Unix directory-fsync durability step through
// os.File.Sync. Credential files themselves are still synced before rename.
func syncDir(string) error { return nil }
