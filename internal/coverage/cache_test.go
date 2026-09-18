package coverage

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type sampleEntry struct {
	Uncontracted []string `json:"uncontracted"`
	Note         string   `json:"note"`
}

func TestCacheRoundTripIsKeyedOnPlaneAndVersion(t *testing.T) {
	state := t.TempDir()
	t.Setenv("XDG_STATE_HOME", state)

	var got sampleEntry
	if LoadCached("claude", "2.1.275", &got) {
		t.Fatal("cache hit before any store")
	}
	if err := StoreCached("claude", "2.1.275", sampleEntry{Uncontracted: []string{"Foo"}, Note: "n"}); err != nil {
		t.Fatal(err)
	}
	if !LoadCached("claude", "2.1.275", &got) || len(got.Uncontracted) != 1 || got.Uncontracted[0] != "Foo" || got.Note != "n" {
		t.Fatalf("cache miss or wrong entry: %+v", got)
	}
	if LoadCached("claude", "2.1.280", &got) {
		t.Fatal("a different version must miss")
	}
	if LoadCached("antigravity", "2.1.275", &got) {
		t.Fatal("a different plane must miss")
	}
	want := filepath.Join(state, "guardrail", "coverage", "claude-2.1.275.json")
	if _, err := os.Stat(want); err != nil {
		t.Fatalf("cache file not at %s: %v", want, err)
	}
	if info, _ := os.Stat(want); info.Mode().Perm() != 0o600 {
		t.Fatalf("cache mode = %v, want 0600", info.Mode().Perm())
	}
}

func TestCacheRejectsUnsafeKeys(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	var got sampleEntry
	for _, key := range []string{"", "../x", "2.1/275", "a b"} {
		if err := StoreCached("claude", key, sampleEntry{}); err == nil {
			t.Fatalf("store accepted unsafe version %q", key)
		}
		if LoadCached("claude", key, &got) {
			t.Fatalf("load accepted unsafe version %q", key)
		}
	}
}

func TestCacheCorruptEntryIsAMiss(t *testing.T) {
	state := t.TempDir()
	t.Setenv("XDG_STATE_HOME", state)
	dir := filepath.Join(state, "guardrail", "coverage")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "claude-2.1.275.json"), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	var got sampleEntry
	if LoadCached("claude", "2.1.275", &got) {
		t.Fatal("corrupt cache must miss")
	}
}

func TestClaudeBundleVersionIsFoundDeepInACompiledBundle(t *testing.T) {
	dir := t.TempDir()
	bundle := filepath.Join(dir, "claude")
	// Native code first, JavaScript (with the version line) 9 MB in — across
	// several 4 MB read windows, straddling one boundary.
	body := strings.Repeat("\x00binary", 9<<20/7) + syntheticBundle + strings.Repeat("x", 1<<20)
	if err := os.WriteFile(bundle, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	v, err := ClaudeBundleVersion(bundle)
	if err != nil || v != "2.1.275" {
		t.Fatalf("version = %q, %v", v, err)
	}
	if err := os.WriteFile(bundle, []byte("no version here"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := ClaudeBundleVersion(bundle); err == nil {
		t.Fatal("expected an error without a version line")
	}
}

// ClaudeDrift is the session-start entry point: first call after a bump
// scans and caches; later calls answer from the cache even if the bundle
// bytes changed under the same version; a guardrail release with a
// different contract invalidates the entry.
func TestClaudeDriftScansOnceThenAnswersFromCache(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	dir := t.TempDir()
	bundle := filepath.Join(dir, "claude")
	if err := os.WriteFile(bundle, []byte(syntheticBundle), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)

	d, err := ClaudeDrift(contracted, "v1")
	if err != nil {
		t.Fatal(err)
	}
	if d.Version != "2.1.275" || strings.Join(d.Uncontracted, ",") != "FutureToolA,FutureToolB" || d.FromCache {
		t.Fatalf("first drift = %+v", d)
	}

	// Same version, different bytes: cache answers, no rescan.
	if err := os.WriteFile(bundle, []byte(`// Version: 2.1.275`+"\n"+`var tools=["Bash","Read","Write","Edit","Glob"];`), 0o755); err != nil {
		t.Fatal(err)
	}
	d, err = ClaudeDrift(contracted, "v1")
	if err != nil || !d.FromCache || strings.Join(d.Uncontracted, ",") != "FutureToolA,FutureToolB" {
		t.Fatalf("second drift = %+v, %v", d, err)
	}

	// A different guardrail version (contract may differ) rescans.
	d, err = ClaudeDrift(contracted, "v2")
	if err != nil || d.FromCache || len(d.Uncontracted) != 0 {
		t.Fatalf("after guardrail bump = %+v, %v", d, err)
	}
}

func TestClaudeDriftWithoutBundleIsAnError(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	t.Setenv("PATH", t.TempDir())
	if _, err := ClaudeDrift(contracted, "v1"); err == nil {
		t.Fatal("expected an error without claude on PATH")
	}
}
