package genconfig

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Package-level state isolation (#310).
//
// MergePlaneInto writes an ownership manifest to the state root (#309). Tests
// that merge without redirecting that root wrote manifests into the real state
// directory of whatever machine ran them -- three showed up on a developer host
// with `t.TempDir()` targets, found while capturing the phase-1 baseline.
//
// Nothing was mis-enforced: a manifest whose recorded target is not the file
// being operated on is rejected, so `doctor` still reported no manifest for the
// real settings files and removal still used the documented fallback. The guard
// held. The suite simply should not be writing outside its own temp space.
//
// The fix is structural rather than per-test. The manifest tests already
// isolate through manifestEnv; the merge tests predate manifests and had no
// reason to, and any test added later would have the same no reason. Setting
// the root once for the package means hermeticity is not something a future
// test has to remember.
//
// TestMain, not t.Setenv: the root has to be in place before any test runs,
// and t.Setenv is per-test by construction.
func TestMain(m *testing.M) {
	root, err := os.MkdirTemp("", "guardrail-genconfig-state-")
	if err != nil {
		panic("isolating the genconfig state root: " + err.Error())
	}
	// Both spellings: ManifestDir reads LOCALAPPDATA on Windows and
	// XDG_STATE_HOME elsewhere, and a test binary cross-compiled or run under
	// either shape must land in the same place.
	os.Setenv("LOCALAPPDATA", root)
	os.Setenv("XDG_STATE_HOME", root)

	code := m.Run()

	os.RemoveAll(root)
	os.Exit(code)
}

// The guard on the guard. If ManifestDir ever stops honouring the redirected
// root -- a new lookup order, a cached path, a platform branch -- this fails
// here rather than by leaving files on someone's machine, which is how the
// original defect escaped notice.
func TestManifestDirStaysInsideTheIsolatedRoot(t *testing.T) {
	dir, err := ManifestDir()
	if err != nil {
		t.Fatal(err)
	}
	for _, env := range []string{"LOCALAPPDATA", "XDG_STATE_HOME"} {
		root := os.Getenv(env)
		if root == "" {
			continue
		}
		rel, err := filepath.Rel(root, dir)
		if err == nil && !strings.HasPrefix(rel, "..") {
			return
		}
	}
	t.Fatalf("ManifestDir() = %q, which is outside the isolated state root; tests would write to the real machine", dir)
}

// A merge must not reach outside the isolated root either. This asserts the
// property the defect actually violated, rather than only the directory
// helper's arithmetic.
func TestMergeWritesItsManifestInsideTheIsolatedRoot(t *testing.T) {
	dir, err := ManifestDir()
	if err != nil {
		t.Fatal(err)
	}
	before := manifestFileCount(t, dir)

	path := filepath.Join(t.TempDir(), "hooks.json")
	if err := os.WriteFile(path, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := MergePlaneInto(path, "antigravity", AntigravityConfig("guardrail")); err != nil {
		t.Fatal(err)
	}

	if got := manifestFileCount(t, dir); got <= before {
		t.Fatalf("the merge wrote no manifest inside the isolated root (%d -> %d); it went somewhere else", before, got)
	}
}

func manifestFileCount(t *testing.T, dir string) int {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return 0
	}
	if err != nil {
		t.Fatal(err)
	}
	return len(entries)
}
