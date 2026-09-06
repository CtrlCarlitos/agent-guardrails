package policy

import (
	"slices"
	"strings"
	"testing"
)

func TestLoadBase(t *testing.T) {
	p, err := LoadBase()
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Slots.SecretGlobs) < 12 {
		t.Errorf("SecretGlobs = %d entries, want >= 12", len(p.Slots.SecretGlobs))
	}
	// Full-path globs only: the bare ".env.example" duplicate went with the
	// basename fallback (review M-2/M-4/M-5).
	if !slices.Contains(p.Slots.SecretAllow, "**/.env.example") {
		t.Errorf("SecretAllow missing **/.env.example: %v", p.Slots.SecretAllow)
	}
	for _, g := range append(p.Slots.SecretGlobs, p.Slots.SecretAllow...) {
		if !strings.Contains(g, "/") {
			t.Errorf("bare glob %q would match only a path that is exactly that name; prefix it with **/", g)
		}
	}
	if p.Waived == nil {
		t.Error("Waived must be a non-nil map")
	}
}
