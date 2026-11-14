package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/CtrlCarlitos/agent-guardrails/internal/genconfig"
)

// #521: an installation whose entries predate the ownership manifest never
// gets one — setupEnableReason treats "no manifest" as consistent, so setup
// answers "already enabled" forever while doctor keeps saying the removal
// would fall back. A registered plane with no manifest is a state the
// ordinary operator path can fix: re-enable reconciles, and reconcile mode
// adopts entries that exactly match current generated output.
func TestSetupReEnablesToAdoptMissingManifest(t *testing.T) {
	a, _ := driftSandbox(t)
	reconcilePlanes(t, filepath.Dir(filepath.Dir(a)), "codex")

	// Simulate the pre-manifest install: same settings, record gone.
	dir, err := genconfig.ManifestDir()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(dir, "codex.json")); err != nil {
		t.Fatalf("removing the manifest: %v", err)
	}

	reason, err := setupEnableReason("codex")
	if err != nil {
		t.Fatal(err)
	}
	if reason == "" || !strings.Contains(reason, "manifest") {
		t.Fatalf("setupEnableReason(codex) = %q, want a reason that adopts the missing manifest", reason)
	}

	// The ordinary re-enable (reconcile, as both lifecycle paths compute for
	// a registered plane) writes the manifest and converges doctor.
	if err := enablePlaneIntegrationMode("codex", true, false); err != nil {
		t.Fatal(err)
	}
	report, err := planeOwnershipDrift("codex")
	if err != nil {
		t.Fatal(err)
	}
	if report.NoManifest {
		t.Fatalf("manifest still missing after re-enable: %+v", report)
	}
	if !report.Clean() {
		t.Fatalf("ownership not clean after adoption: %+v", report)
	}
	if reason, err := setupEnableReason("codex"); err != nil || reason != "" {
		t.Fatalf("after adoption setupEnableReason = %q, %v; want nothing left to do", reason, err)
	}
}

// A clean manifest state stays "already enabled": the adoption reason fires
// only when the record is actually missing.
func TestSetupStaysQuietWhenManifestExists(t *testing.T) {
	a, _ := driftSandbox(t)
	reconcilePlanes(t, filepath.Dir(filepath.Dir(a)), "codex")
	reason, err := setupEnableReason("codex")
	if err != nil {
		t.Fatal(err)
	}
	if reason != "" {
		t.Fatalf("setupEnableReason(codex) = %q, want \"\"", reason)
	}
}
