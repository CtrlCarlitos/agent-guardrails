package policy

import (
	"os"
	"path/filepath"
	"testing"
)

func TestBaseDefaultsUnknownToolsToAudit(t *testing.T) {
	p, err := LoadBase()
	if err != nil {
		t.Fatal(err)
	}
	if p.UnknownToolPosture != UnknownAudit {
		t.Fatalf("UnknownToolPosture = %q, want %q", p.UnknownToolPosture, UnknownAudit)
	}
}

func TestUnknownPostureRejectsOtherValues(t *testing.T) {
	if _, err := ParseUnknownToolPosture("allow"); err == nil {
		t.Fatal("ParseUnknownToolPosture(allow) succeeded, want error")
	}
}

func TestLoadOverlayRejectsInvalidUnknownToolPosture(t *testing.T) {
	path := filepath.Join(t.TempDir(), "guardrail.toml")
	if err := os.WriteFile(path, []byte("unknown_tool_posture = \"allow\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	if _, err := LoadOverlay(path); err == nil {
		t.Fatal("LoadOverlay accepted invalid unknown_tool_posture")
	}
}

func TestMergeRejectsInvalidUnknownToolPosture(t *testing.T) {
	base := &Policy{UnknownToolPosture: UnknownAudit, Waived: map[string]bool{}}
	overlay := &Overlay{UnknownToolPosture: UnknownToolPosture("allow")}

	if _, _, err := Merge(base, overlay, "1.0.0", nil, "/repo"); err == nil {
		t.Fatal("Merge accepted invalid unknown_tool_posture")
	}
}
