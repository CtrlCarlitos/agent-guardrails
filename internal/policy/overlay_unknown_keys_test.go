package policy

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func writeOverlay(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "guardrail.toml")
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// A mistyped key used to vanish without a word (#397). It still loads, so an
// existing or newer overlay keeps working, but each unknown key is a warning
// naming the key and the file.
func TestLoadOverlayWarnsOnUnknownKeys(t *testing.T) {
	p := writeOverlay(t, `
waiver = ["P6.curl-egress"]
engine_min_verison = "1.0"

[slot]
safe_roots = ["./tmp"]

[slots]
safe_root = ["./tmp"]
secret_dirs = ["**/.vault/**"]

[[rules]]
id = "proj.tf"
pattern = "terraform apply*"
decision = "ask"
desicion = "deny"
`)
	ov, err := LoadOverlay(p)
	if err != nil {
		t.Fatalf("an unknown key must not fail the load: %v", err)
	}
	if !slices.Equal(ov.SecretDirs, []string{"**/.vault/**"}) || len(ov.Rules) != 1 {
		t.Fatalf("known keys were not loaded alongside the unknown ones: %+v", ov)
	}
	var keys []string
	for _, w := range ov.Warnings {
		if !strings.Contains(w, p) {
			t.Errorf("warning does not name the overlay file %s: %q", p, w)
		}
		keys = append(keys, w)
	}
	for _, want := range []string{"waiver", "engine_min_verison", "slot", "slots.safe_root", "rules.desicion"} {
		found := false
		for _, w := range ov.Warnings {
			if strings.Contains(w, "unknown key "+want+" ") {
				found = true
			}
		}
		if !found {
			t.Errorf("no warning for unknown key %q; warnings: %q", want, keys)
		}
	}
	// An unknown table is one warning, not one per key inside it.
	if len(ov.Warnings) != 5 {
		t.Errorf("got %d warnings, want 5: %q", len(ov.Warnings), ov.Warnings)
	}
}

// A repository cannot flood the bounded warning list with key names: past the
// cap the rest are one counted warning.
func TestLoadOverlayCapsUnknownKeyWarnings(t *testing.T) {
	var body strings.Builder
	for i := range 9 {
		body.WriteString("junk" + string(rune('a'+i)) + " = 1\n")
	}
	ov, err := LoadOverlay(writeOverlay(t, body.String()))
	if err != nil {
		t.Fatal(err)
	}
	if len(ov.Warnings) != maxUnknownKeyWarnings+1 {
		t.Fatalf("got %d warnings, want %d named plus one summary: %q", len(ov.Warnings), maxUnknownKeyWarnings, ov.Warnings)
	}
	if last := ov.Warnings[len(ov.Warnings)-1]; !strings.Contains(last, "4 more unknown keys") {
		t.Fatalf("summary warning = %q, want it to count the 4 not named", last)
	}
}

// Unknown-key warnings come after Merge's own warnings, so a waiver or DROPPED
// notice is never the one cut from the bounded model-facing list.
func TestMergePutsUnknownKeyWarningsLast(t *testing.T) {
	p := writeOverlay(t, "junk = 1\nwaive = [\"P6.curl-egress\"]\n")
	ov, err := LoadOverlay(p)
	if err != nil {
		t.Fatal(err)
	}
	base, err := LoadBase()
	if err != nil {
		t.Fatal(err)
	}
	_, warns, err := Merge(base, ov, "dev", nil, filepath.Dir(p))
	if err != nil {
		t.Fatal(err)
	}
	if len(warns) < 2 || !strings.Contains(warns[len(warns)-1], "unknown key junk ") {
		t.Fatalf("unknown-key warning is not last: %q", warns)
	}
}

func TestLoadOverlayKnownKeysWarnNothing(t *testing.T) {
	_, examplePath := shippedOverlayExamplePath(t)
	ov, err := LoadOverlay(examplePath)
	if err != nil {
		t.Fatal(err)
	}
	if len(ov.Warnings) != 0 {
		t.Fatalf("the shipped example uses only known keys, got warnings: %q", ov.Warnings)
	}
}

// Merge is where every consumer (doctor, sync, hook) reads overlay warnings,
// so the unknown-key warning has to come out of it.
func TestMergeCarriesOverlayUnknownKeyWarnings(t *testing.T) {
	p := writeOverlay(t, "waiver = [\"P6.curl-egress\"]\n")
	ov, err := LoadOverlay(p)
	if err != nil {
		t.Fatal(err)
	}
	base, err := LoadBase()
	if err != nil {
		t.Fatal(err)
	}
	_, warns, err := Merge(base, ov, "dev", nil, filepath.Dir(p))
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, w := range warns {
		if strings.Contains(w, "unknown key waiver ") {
			found = true
		}
	}
	if !found {
		t.Fatalf("Merge warnings do not carry the unknown key: %q", warns)
	}
}
