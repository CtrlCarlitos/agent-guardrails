package pathutil

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestCanonicalTable(t *testing.T) {
	base := t.TempDir()
	existing := filepath.Join(base, "ExistingDir")
	if err := os.MkdirAll(existing, 0o700); err != nil {
		t.Fatal(err)
	}
	existingFile := filepath.Join(existing, "Notes.txt")
	if err := os.WriteFile(existingFile, []byte("ok"), 0o600); err != nil {
		t.Fatal(err)
	}

	resolvedBase, err := filepath.EvalSymlinks(base)
	if err != nil {
		t.Fatal(err)
	}
	wantNorm := func(p string) string {
		s := filepath.ToSlash(filepath.Clean(p))
		if runtime.GOOS == "windows" || runtime.GOOS == "darwin" {
			return strings.ToLower(s)
		}
		return s
	}

	tests := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "existing directory with trailing separator",
			in:   existing + string(filepath.Separator),
			want: wantNorm(filepath.Join(resolvedBase, "ExistingDir")),
		},
		{
			name: "existing file with redundant dot and double slash",
			in:   existing + string(filepath.Separator) + "." + string(filepath.Separator) + string(filepath.Separator) + "Notes.txt",
			want: wantNorm(filepath.Join(resolvedBase, "ExistingDir", "Notes.txt")),
		},
		{
			name: "missing nested suffix under existing ancestor",
			in:   filepath.Join(existing, "future", "nested", "file.go"),
			want: wantNorm(filepath.Join(resolvedBase, "ExistingDir", "future", "nested", "file.go")),
		},
		{
			name: "forward slash spelling on every OS",
			in:   filepath.ToSlash(existingFile),
			want: wantNorm(filepath.Join(resolvedBase, "ExistingDir", "Notes.txt")),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Canonical(tc.in)
			if err != nil {
				t.Fatalf("Canonical(%q) unexpected error: %v", tc.in, err)
			}
			if got != tc.want {
				t.Fatalf("Canonical(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestCanonicalCaseSensitivityByHost(t *testing.T) {
	base := t.TempDir()
	mixed := filepath.Join(base, "CaseDir", "FutureFile.txt")
	upper := filepath.Join(base, "CASEDIR", "FUTUREFILE.TXT")
	lower := filepath.Join(base, "casedir", "futurefile.txt")

	gotMixed, err := Canonical(mixed)
	if err != nil {
		t.Fatal(err)
	}
	gotUpper, err := Canonical(upper)
	if err != nil {
		t.Fatal(err)
	}
	gotLower, err := Canonical(lower)
	if err != nil {
		t.Fatal(err)
	}

	if runtime.GOOS == "windows" || runtime.GOOS == "darwin" {
		if gotMixed != gotUpper || gotMixed != gotLower {
			t.Fatalf("case-insensitive host did not fold case: mixed=%q upper=%q lower=%q", gotMixed, gotUpper, gotLower)
		}
	} else {
		if gotMixed == gotUpper || gotMixed == gotLower {
			t.Fatalf("case-sensitive host folded case unexpectedly: mixed=%q upper=%q lower=%q", gotMixed, gotUpper, gotLower)
		}
	}
}

func TestCanonicalSymlinkedTempRootAndDotDotOrder(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation is privileged on Windows")
	}
	targetParent := t.TempDir()
	targetSub := filepath.Join(targetParent, "sub")
	if err := os.MkdirAll(targetSub, 0o700); err != nil {
		t.Fatal(err)
	}
	// Sow a stray .git at the temp root to verify Canonical stays unaffected.
	strayGit := filepath.Join(targetParent, ".git")
	if err := os.MkdirAll(strayGit, 0o700); err != nil {
		t.Fatal(err)
	}

	aliasParent := t.TempDir()
	alias := filepath.Join(aliasParent, "alias")
	if err := os.Symlink(targetSub, alias); err != nil {
		t.Fatal(err)
	}

	gotAlias, err := Canonical(filepath.Join(alias, "missing.txt"))
	if err != nil {
		t.Fatal(err)
	}
	gotTarget, err := Canonical(filepath.Join(targetSub, "missing.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if gotAlias != gotTarget {
		t.Fatalf("symlinked root mismatch: alias=%q target=%q", gotAlias, gotTarget)
	}

	// Symlink-before-dotdot order must be preserved, not collapsed lexically first.
	dotdot := alias + string(filepath.Separator) + ".." + string(filepath.Separator) + "sibling.txt"
	gotDotDot, err := Canonical(dotdot)
	if err != nil {
		t.Fatal(err)
	}
	wantDotDot, err := Canonical(filepath.Join(targetParent, "sibling.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if gotDotDot != wantDotDot {
		t.Fatalf("symlink/.. mismatch: got=%q want=%q", gotDotDot, wantDotDot)
	}
}

func TestCanonicalRelativePath(t *testing.T) {
	dir := t.TempDir()
	sub := filepath.Join(dir, "sub")
	if err := os.MkdirAll(sub, 0o700); err != nil {
		t.Fatal(err)
	}
	oldWD, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.Chdir(oldWD); err != nil {
			t.Errorf("restore wd: %v", err)
		}
	})

	gotRel, err := Canonical(filepath.Join("sub", "future.go"))
	if err != nil {
		t.Fatal(err)
	}
	gotAbs, err := Canonical(filepath.Join(sub, "future.go"))
	if err != nil {
		t.Fatal(err)
	}
	if gotRel != gotAbs {
		t.Fatalf("relative Canonical = %q, want %q", gotRel, gotAbs)
	}
}

func TestCanonicalErrors(t *testing.T) {
	if _, err := Canonical(""); err == nil {
		t.Fatal("Canonical accepted empty path")
	}
	if _, err := Canonical("bad\x00path"); err == nil {
		t.Fatal("Canonical accepted NUL byte path")
	}
	if runtime.GOOS != "windows" {
		dir := t.TempDir()
		a := filepath.Join(dir, "a")
		b := filepath.Join(dir, "b")
		if err := os.Symlink(b, a); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(a, b); err != nil {
			t.Fatal(err)
		}
		if _, err := Canonical(a); err == nil {
			t.Fatal("Canonical accepted symlink cycle")
		}
	}
}

func TestSameAndWithin(t *testing.T) {
	base := t.TempDir()
	repo := filepath.Join(base, "repo")
	sibling := filepath.Join(base, "repo-other")
	nested := filepath.Join(repo, "pkg", "a.go")
	if err := os.MkdirAll(filepath.Dir(nested), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(sibling, 0o700); err != nil {
		t.Fatal(err)
	}

	if !Same(repo, repo+string(filepath.Separator)+".") {
		t.Fatal("Same returned false for cleaned equivalent path")
	}
	if Same(repo, sibling) {
		t.Fatal("Same returned true for distinct sibling")
	}
	if Same("", "") || Same("bad\x00a", "bad\x00a") {
		t.Fatal("Same accepted invalid paths")
	}

	root := filepath.VolumeName(base) + string(filepath.Separator)

	withinCases := []struct {
		name       string
		target     string
		root       string
		wantWithin bool
		wantStrict bool
	}{
		{"equal", repo, repo, true, false},
		{"nested descendant", nested, repo, true, true},
		{"missing descendant", filepath.Join(repo, "new", "file.go"), repo, true, true},
		{"sibling prefix collision", filepath.Join(sibling, "a.go"), repo, false, false},
		{"parent outside child", base, repo, false, false},
		{"filesystem root contains repo", repo, root, true, true},
		{"filesystem root equals itself", root, root, true, false},
	}

	for _, tc := range withinCases {
		t.Run(tc.name, func(t *testing.T) {
			gotWithin, err := Within(tc.target, tc.root)
			if err != nil {
				t.Fatalf("Within(%q, %q) err = %v", tc.target, tc.root, err)
			}
			if gotWithin != tc.wantWithin {
				t.Fatalf("Within(%q, %q) = %v, want %v", tc.target, tc.root, gotWithin, tc.wantWithin)
			}
			gotStrict, err := WithinStrict(tc.target, tc.root)
			if err != nil {
				t.Fatalf("WithinStrict(%q, %q) err = %v", tc.target, tc.root, err)
			}
			if gotStrict != tc.wantStrict {
				t.Fatalf("WithinStrict(%q, %q) = %v, want %v", tc.target, tc.root, gotStrict, tc.wantStrict)
			}
		})
	}
}
