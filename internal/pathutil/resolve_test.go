package pathutil

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestResolveThroughExistingAncestorMissingSuffixes(t *testing.T) {
	base := t.TempDir()
	tests := []struct {
		name      string
		candidate string
		want      string
	}{
		{"plain missing suffix", filepath.Join(base, "future"), filepath.Join(base, "future")},
		{"multi-part missing suffix", filepath.Join(base, "future", "nested"), filepath.Join(base, "future", "nested")},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := ResolveThroughExistingAncestor(test.candidate)
			if err != nil {
				t.Fatal(err)
			}
			if got != test.want {
				t.Fatalf("ResolveThroughExistingAncestor(%q) = %q, want %q", test.candidate, got, test.want)
			}
		})
	}
}

func TestEvalSymlinksFollowsSymlinkBeforeDotDot(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation is privileged on Windows")
	}
	targetParent := t.TempDir()
	targetDir := filepath.Join(targetParent, "subdir")
	if err := os.Mkdir(targetDir, 0o700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(targetParent, "target.txt")
	if err := os.WriteFile(target, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(t.TempDir(), "alias")
	if err := os.Symlink(targetDir, alias); err != nil {
		t.Fatal(err)
	}
	candidate := alias + string(filepath.Separator) + ".." + string(filepath.Separator) + "target.txt"

	got, err := filepath.EvalSymlinks(candidate)
	if err != nil {
		t.Fatal(err)
	}
	if got != target {
		t.Fatalf("EvalSymlinks(%q) = %q, want %q", candidate, got, target)
	}
}

func TestResolveThroughExistingAncestorSymlinkParent(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation is privileged on Windows")
	}
	targetDir := t.TempDir()
	alias := filepath.Join(t.TempDir(), "alias")
	if err := os.Symlink(targetDir, alias); err != nil {
		t.Fatal(err)
	}

	got, err := ResolveThroughExistingAncestor(filepath.Join(alias, "future"))
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(targetDir, "future")
	if got != want {
		t.Fatalf("resolved path = %q, want %q", got, want)
	}
}

func TestResolveThroughExistingAncestorPreservesSymlinkDotDotOrder(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation is privileged on Windows")
	}
	targetParent := t.TempDir()
	targetDir := filepath.Join(targetParent, "subdir")
	if err := os.Mkdir(targetDir, 0o700); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(t.TempDir(), "alias")
	if err := os.Symlink(targetDir, alias); err != nil {
		t.Fatal(err)
	}
	candidate := alias + string(filepath.Separator) + ".." + string(filepath.Separator) + "future.txt"

	got, err := ResolveThroughExistingAncestor(candidate)
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(targetParent, "future.txt")
	if got != want {
		t.Fatalf("resolved path = %q, want %q", got, want)
	}
}

func TestResolveThroughExistingAncestorExistingBenignTarget(t *testing.T) {
	target := filepath.Join(t.TempDir(), "notes.txt")
	if err := os.WriteFile(target, nil, 0o600); err != nil {
		t.Fatal(err)
	}

	got, err := ResolveThroughExistingAncestor(target)
	if err != nil {
		t.Fatal(err)
	}
	if got != target {
		t.Fatalf("resolved path = %q, want %q", got, target)
	}
}

func TestResolveThroughExistingAncestorRootAndRelativePath(t *testing.T) {
	root := filepath.VolumeName(t.TempDir()) + string(filepath.Separator)
	got, err := ResolveThroughExistingAncestor(root)
	if err != nil {
		t.Fatal(err)
	}
	if got != filepath.Clean(root) {
		t.Fatalf("resolved root = %q, want %q", got, filepath.Clean(root))
	}

	workingDir := t.TempDir()
	oldWorkingDir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(workingDir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.Chdir(oldWorkingDir); err != nil {
			t.Errorf("restore working directory: %v", err)
		}
	})
	if err := os.Mkdir("existing", 0o700); err != nil {
		t.Fatal(err)
	}

	got, err = ResolveThroughExistingAncestor("existing" + string(filepath.Separator) + "future")
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join("existing", "future")
	if got != want {
		t.Fatalf("resolved relative path = %q, want %q", got, want)
	}
}

func TestResolveThroughExistingAncestorInvalidPath(t *testing.T) {
	if _, err := ResolveThroughExistingAncestor("bad\x00path"); err == nil {
		t.Fatal("ResolveThroughExistingAncestor accepted an invalid path")
	}
}

func TestResolveThroughExistingAncestorSymlinkCycle(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation is privileged on Windows")
	}
	dir := t.TempDir()
	first := filepath.Join(dir, "first")
	second := filepath.Join(dir, "second")
	if err := os.Symlink(second, first); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(first, second); err != nil {
		t.Fatal(err)
	}

	if _, err := ResolveThroughExistingAncestor(first); err == nil {
		t.Fatal("ResolveThroughExistingAncestor accepted a symlink cycle")
	}
}
