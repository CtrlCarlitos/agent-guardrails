package policy

import (
	"slices"
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
	if !slices.Contains(p.Slots.SecretAllow, ".env.example") {
		t.Errorf("SecretAllow missing .env.example: %v", p.Slots.SecretAllow)
	}
	if p.Waived == nil {
		t.Error("Waived must be a non-nil map")
	}
}
