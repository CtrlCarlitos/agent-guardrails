//go:build windows

package pathutil

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

func shortPathForTest(t *testing.T, longPath string) string {
	t.Helper()
	longUTF16, err := windows.UTF16PtrFromString(longPath)
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]uint16, len(longPath)+64)
	n, err := windows.GetShortPathName(longUTF16, &buf[0], uint32(len(buf)))
	if err != nil {
		t.Fatalf("GetShortPathName(%q): %v", longPath, err)
	}
	if int(n) >= len(buf) {
		buf = make([]uint16, n+1)
		n, err = windows.GetShortPathName(longUTF16, &buf[0], uint32(len(buf)))
		if err != nil {
			t.Fatalf("GetShortPathName(%q) retry: %v", longPath, err)
		}
	}
	return windows.UTF16ToString(buf[:n])
}

func TestWindowsCanonicalShortLongCaseAndSlashes(t *testing.T) {
	base := t.TempDir()
	longDir := filepath.Join(base, "LongDirectoryNameForCanonical83Test")
	if err := os.MkdirAll(longDir, 0o700); err != nil {
		t.Fatal(err)
	}
	shortDir := shortPathForTest(t, longDir)

	// Sow a stray .git at the temp root to ensure Canonical handles it cleanly.
	if err := os.MkdirAll(filepath.Join(base, ".git"), 0o700); err != nil {
		t.Fatal(err)
	}

	wantLong, err := Canonical(longDir)
	if err != nil {
		t.Fatalf("Canonical(longDir): %v", err)
	}
	if strings.Contains(wantLong, `\`) {
		t.Fatalf("Canonical(%q) = %q contains backslash", longDir, wantLong)
	}
	if wantLong != strings.ToLower(wantLong) {
		t.Fatalf("Canonical(%q) = %q is not lowercased on Windows", longDir, wantLong)
	}

	variants := []struct {
		name string
		path string
	}{
		{"8.3 short form", shortDir},
		{"uppercase", strings.ToUpper(longDir)},
		{"lowercase", strings.ToLower(longDir)},
		{"forward slashes", filepath.ToSlash(longDir)},
		{"lowercase drive + forward slashes", strings.ToLower(filepath.ToSlash(longDir))},
		{"short form + trailing slash", shortDir + `\`},
	}

	for _, v := range variants {
		t.Run(v.name, func(t *testing.T) {
			got, err := Canonical(v.path)
			if err != nil {
				t.Fatalf("Canonical(%q) error: %v", v.path, err)
			}
			if got != wantLong {
				t.Fatalf("Canonical(%q) = %q, want %q", v.path, got, wantLong)
			}
			if !Same(v.path, longDir) {
				t.Fatalf("Same(%q, %q) = false, want true", v.path, longDir)
			}
		})
	}

	// Missing descendants under short vs long + mixed case must match and be within.
	shortFuture := filepath.Join(shortDir, "FutureSub", "File.Go")
	longFuture := filepath.Join(strings.ToUpper(longDir), "futuresub", "file.go")
	if !Same(shortFuture, longFuture) {
		t.Fatalf("Same(%q, %q) = false, want true", shortFuture, longFuture)
	}
	within, err := WithinStrict(shortFuture, strings.ToUpper(longDir))
	if err != nil || !within {
		t.Fatalf("WithinStrict(%q, %q) = (%v, %v), want (true, nil)", shortFuture, longDir, within, err)
	}
	sibling := filepath.Join(base, "LongDirectoryNameForCanonical83Test-Other", "File.Go")
	withinSibling, err := Within(sibling, shortDir)
	if err != nil || withinSibling {
		t.Fatalf("Within(%q, %q) = (%v, %v), want (false, nil)", sibling, shortDir, withinSibling, err)
	}
}
