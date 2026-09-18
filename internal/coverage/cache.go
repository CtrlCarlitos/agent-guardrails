package coverage

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"
)

// cacheKey admits plane and version keys that are safe as a file-name
// component: no separators, no traversal, nothing empty.
var cacheKey = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

// CacheDir is $XDG_STATE_HOME/guardrail/coverage (or the ~/.local/state
// default): scan results keyed on the runtime's own version, so a plane's
// session-start check pays for one scan per release rather than one per
// session.
func CacheDir() (string, error) {
	base := os.Getenv("XDG_STATE_HOME")
	if base == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		base = filepath.Join(home, ".local", "state")
	}
	return filepath.Join(base, "guardrail", "coverage"), nil
}

func cachePath(plane, version string) (string, error) {
	if !cacheKey.MatchString(plane) || !cacheKey.MatchString(version) {
		return "", errors.New("coverage cache: unsafe plane or version key")
	}
	dir, err := CacheDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, plane+"-"+version+".json"), nil
}

// LoadCached fills out from the cached entry for plane and version. Any
// failure — no entry, unsafe key, unreadable or corrupt file — is a miss,
// never an error: callers rescan.
func LoadCached(plane, version string, out any) bool {
	path, err := cachePath(plane, version)
	if err != nil {
		return false
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	return json.Unmarshal(raw, out) == nil
}

// StoreCached writes entry as the cached result for plane and version,
// private to the user and atomically replaced.
func StoreCached(plane, version string, entry any) error {
	path, err := cachePath(plane, version)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	raw, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".coverage-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(raw); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
