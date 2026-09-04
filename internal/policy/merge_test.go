package policy

import (
	"slices"
	"strings"
	"testing"
)

func TestMergeAppendsSlots(t *testing.T) {
	base := &Policy{Slots: Slots{SafeRoots: []string{"/repo"}, SecretGlobs: []string{"**/.env"}}, Waived: map[string]bool{}}
	ov := &Overlay{SafeRoots: []string{"./tmp"}, SecretGlobs: []string{"*.p12"}}
	m, _, err := Merge(base, ov, "1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(m.Slots.SafeRoots, []string{"/repo", "./tmp"}) {
		t.Errorf("SafeRoots = %v", m.Slots.SafeRoots)
	}
	if !slices.Equal(m.Slots.SecretGlobs, []string{"**/.env", "*.p12"}) {
		t.Errorf("SecretGlobs = %v", m.Slots.SecretGlobs)
	}
}

func TestMergeWaivers(t *testing.T) {
	base := &Policy{Waived: map[string]bool{}}
	ov := &Overlay{Waive: []string{"P6.curl-egress"}}
	m, warns, err := Merge(base, ov, "1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	if !m.Waived["P6.curl-egress"] {
		t.Error("waiver not recorded")
	}
	if !slices.ContainsFunc(warns, func(s string) bool { return strings.Contains(s, "P6.curl-egress") }) {
		t.Errorf("no warning for active waiver: %v", warns)
	}
}

func TestMergeRejectsAllowRule(t *testing.T) {
	base := &Policy{Waived: map[string]bool{}}
	ov := &Overlay{Rules: []Rule{{ID: "x", Decision: Allow, Pattern: "curl *"}}}
	if _, _, err := Merge(base, ov, "1.0.0"); err == nil {
		t.Fatal("want error for an overlay allow rule")
	}
}

func TestMergeMinVersionWarning(t *testing.T) {
	base := &Policy{Waived: map[string]bool{}}
	ov := &Overlay{EngineMinVersion: "2.5.0"}
	_, warns, err := Merge(base, ov, "1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	if !slices.ContainsFunc(warns, func(s string) bool { return strings.Contains(s, "2.5.0") }) {
		t.Errorf("no min-version warning: %v", warns)
	}
}

func TestVersionOlder(t *testing.T) {
	if !versionOlder("1.0.0", "1.2.0") {
		t.Error("1.0.0 < 1.2.0")
	}
	if versionOlder("2.0.0", "1.9.9") {
		t.Error("2.0.0 !< 1.9.9")
	}
	if versionOlder("dev", "1.0.0") {
		t.Error("non-numeric never warns")
	}
}
