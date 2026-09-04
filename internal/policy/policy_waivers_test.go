package policy

import (
	"slices"
	"testing"
)

func TestSortedWaivers(t *testing.T) {
	p := &Policy{Waived: map[string]bool{"P6": true, "P1.rm-rf": true, "P2": false}}
	got := SortedWaivers(p)
	want := []string{"P1.rm-rf", "P6"}
	if !slices.Equal(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	if SortedWaivers(nil) != nil {
		t.Error("nil policy should give nil")
	}
	if SortedWaivers(&Policy{}) != nil {
		t.Error("nil Waived map should give nil")
	}
}
