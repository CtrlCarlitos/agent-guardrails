package adversarial

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// removeBuildDir removes the directory the suite built its binary into. It
// retries, because Windows releases a running image a moment after the process
// exits, and it says so when it still cannot: the error used to be discarded,
// which is how 133 directories (2.7 GB) piled up in %TEMP% unnoticed (#367).
func removeBuildDir() {
	if adversarialBuildDir == "" {
		return
	}
	var err error
	for attempt := 0; attempt < 10; attempt++ {
		if err = os.RemoveAll(adversarialBuildDir); err == nil {
			return
		}
		time.Sleep(300 * time.Millisecond)
	}
	fmt.Fprintf(os.Stderr, "adversarial: could not remove %s: %v (a process may still hold its binary open)\n", adversarialBuildDir, err)
}

// sweepStaleBuildDirs removes build directories a killed run left behind (a
// Stop-hook timeout, Ctrl-C, an agent tearing down): TestMain's cleanup never
// ran for them. It removes only a `guardrail-adversarial-*` directory older
// than olderThan that holds nothing but a built binary, and skips anything it
// cannot remove (another run may still be using it). Best effort: it never fails
// a run.
func sweepStaleBuildDirs(root string, olderThan time.Duration) {
	matches, err := filepath.Glob(filepath.Join(root, "guardrail-adversarial-*"))
	if err != nil {
		return
	}
	cutoff := time.Now().Add(-olderThan)
	for _, dir := range matches {
		info, err := os.Stat(dir)
		if err != nil || !info.IsDir() || info.ModTime().After(cutoff) {
			continue
		}
		entries, err := os.ReadDir(dir)
		if err != nil || len(entries) == 0 {
			continue
		}
		onlyBinary := true
		for _, entry := range entries {
			if entry.IsDir() || (entry.Name() != "guardrail" && entry.Name() != "guardrail.exe") {
				onlyBinary = false
				break
			}
		}
		if onlyBinary {
			_ = os.RemoveAll(dir)
		}
	}
}

func TestSweepRemovesOnlyStaleBinaryOnlyBuildDirs(t *testing.T) {
	root := t.TempDir()
	old := time.Now().Add(-48 * time.Hour)
	mk := func(name string, files map[string]string, mtime time.Time) string {
		dir := filepath.Join(root, name)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		for file, content := range files {
			if err := os.WriteFile(filepath.Join(dir, file), []byte(content), 0o755); err != nil {
				t.Fatal(err)
			}
		}
		if err := os.Chtimes(dir, mtime, mtime); err != nil {
			t.Fatal(err)
		}
		return dir
	}
	staleExe := mk("guardrail-adversarial-1", map[string]string{"guardrail.exe": "x"}, old)
	staleUnix := mk("guardrail-adversarial-2", map[string]string{"guardrail": "x"}, old)
	fresh := mk("guardrail-adversarial-3", map[string]string{"guardrail.exe": "x"}, time.Now())
	withExtra := mk("guardrail-adversarial-4", map[string]string{"guardrail.exe": "x", "notes.txt": "keep me"}, old)
	unrelated := mk("something-else", map[string]string{"guardrail.exe": "x"}, old)
	empty := mk("guardrail-adversarial-5", nil, old)

	sweepStaleBuildDirs(root, 24*time.Hour)

	for _, gone := range []string{staleExe, staleUnix} {
		if _, err := os.Stat(gone); !os.IsNotExist(err) {
			t.Errorf("stale build directory %s was not removed", gone)
		}
	}
	for name, kept := range map[string]string{
		"a recent run":                      fresh,
		"a directory with another file":     withExtra,
		"a directory with another name":     unrelated,
		"an empty directory (not ours yet)": empty,
	} {
		if _, err := os.Stat(kept); err != nil {
			t.Errorf("%s was removed: %v", name, err)
		}
	}
}
