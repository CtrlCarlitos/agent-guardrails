//go:build windows

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

func TestWindowsSameWorktreePathMatchesShortAndLongForms(t *testing.T) {
	base := t.TempDir()
	wt := filepath.Join(base, "LongWorktreeDirectoryNameForProvenance")
	if err := os.MkdirAll(wt, 0o700); err != nil {
		t.Fatal(err)
	}
	wide, err := windows.UTF16PtrFromString(wt)
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]uint16, len(wt)+64)
	n, err := windows.GetShortPathName(wide, &buf[0], uint32(len(buf)))
	if err != nil {
		t.Fatalf("GetShortPathName: %v", err)
	}
	shortWT := windows.UTF16ToString(buf[:n])
	if strings.EqualFold(shortWT, wt) {
		t.Skip("8.3 short names are disabled on this volume")
	}
	if !sameWorktreePath(shortWT, wt, base) {
		t.Fatalf("sameWorktreePath(%q, %q) = false, want true", shortWT, wt)
	}
}
