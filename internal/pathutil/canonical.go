package pathutil

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// Canonical returns the canonical path identity for p: absolute (preserving
// symlink/.. order), symlinks and Windows 8.3 short names resolved through the
// deepest existing ancestor, cleaned, slash-normalized, and case-folded on
// case-insensitive hosts (Windows and macOS).
func Canonical(p string) (string, error) {
	if p == "" {
		return "", errors.New("pathutil: empty path")
	}
	if strings.IndexByte(p, 0) >= 0 {
		return "", errors.New("pathutil: invalid NUL byte in path")
	}
	target := p
	if !filepath.IsAbs(target) {
		if filepath.VolumeName(target) != "" || os.IsPathSeparator(target[0]) {
			abs, err := filepath.Abs(target)
			if err != nil {
				return "", err
			}
			target = abs
		} else {
			wd, err := os.Getwd()
			if err != nil {
				return "", err
			}
			if len(wd) > 0 && os.IsPathSeparator(wd[len(wd)-1]) {
				target = wd + target
			} else {
				target = wd + string(filepath.Separator) + target
			}
		}
	}
	resolved, err := ResolveThroughExistingAncestor(target)
	if err != nil {
		return "", err
	}
	return normalizeSlashAndCase(resolved), nil
}

// Same reports whether a and b resolve to the same canonical path identity.
// Fails closed (false) if either path cannot be canonicalized.
func Same(a, b string) bool {
	ca, err := Canonical(a)
	if err != nil {
		return false
	}
	cb, err := Canonical(b)
	if err != nil {
		return false
	}
	return ca == cb
}

// Within reports whether target is equal to or inside root by canonical path identity.
func Within(target, root string) (bool, error) {
	ct, err := Canonical(target)
	if err != nil {
		return false, err
	}
	cr, err := Canonical(root)
	if err != nil {
		return false, err
	}
	return CanonicalWithin(ct, cr), nil
}

// WithinStrict reports whether target is a strict descendant of root (never
// equal to root itself) by canonical path identity.
func WithinStrict(target, root string) (bool, error) {
	ct, err := Canonical(target)
	if err != nil {
		return false, err
	}
	cr, err := Canonical(root)
	if err != nil {
		return false, err
	}
	return ct != cr && CanonicalWithin(ct, cr), nil
}

// CanonicalWithin reports whether canonTarget is equal to or inside canonRoot,
// where both arguments are already canonicalized slash-separated paths.
func CanonicalWithin(canonTarget, canonRoot string) bool {
	if canonTarget == "" || canonRoot == "" {
		return false
	}
	if canonTarget == canonRoot {
		return true
	}
	if strings.HasSuffix(canonRoot, "/") {
		return strings.HasPrefix(canonTarget, canonRoot)
	}
	return strings.HasPrefix(canonTarget, canonRoot+"/")
}

// NormalizeLexical returns a cleaned, slash-normalized, host-case-folded spelling
// without consulting the filesystem. Use only as a fallback when Canonical fails
// on a synthetic or unmounted path.
func NormalizeLexical(p string) string {
	return normalizeSlashAndCase(p)
}

func normalizeSlashAndCase(p string) string {
	s := filepath.ToSlash(filepath.Clean(p))
	if caseInsensitiveHost() {
		return strings.ToLower(s)
	}
	return s
}

func caseInsensitiveHost() bool {
	return runtime.GOOS == "windows" || runtime.GOOS == "darwin"
}
