//go:build windows

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
	"golang.org/x/sys/windows"
)

// widenArtifactForTest stamps a DACL with an Everyone allow ACE, mirroring
// the adversarial shape from ADR-0021 §6 for files and directories alike.
func widenArtifactForTest(path string) error {
	sd, err := windows.SecurityDescriptorFromString("D:P(A;;FA;;;S-1-1-0)")
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, dacl, nil)
}

// TestWindowsEgressArtifactsAreOwnerOnly asserts the ADR-0021 §3 creation
// invariant from the outside: after a terminal grant, the allowance journal
// directory and the operator config it wrote carry an owner-only DACL — no
// allow ACE for Everyone, BUILTIN\Users, or Authenticated Users — and the
// owner is the current user.
func TestWindowsEgressArtifactsAreOwnerOnly(t *testing.T) {
	setOperatorEnv(t)
	var out, errb bytes.Buffer
	if code := cmdEgress([]string{"grant", "--scope", "global", "--host", "acl.example.test"}, true, t.TempDir(), &out, &errb); code != 0 {
		t.Fatalf("grant code=%d stderr=%q", code, errb.String())
	}
	dir, err := allowanceJournalDir()
	if err != nil {
		t.Fatal(err)
	}
	configPath := policy.OperatorConfigPath()
	if _, err := os.Stat(configPath); err != nil {
		t.Fatalf("operator config: %v", err)
	}
	for _, artifact := range []string{dir, configPath} {
		if err := validatePrivateACL(artifact); err != nil {
			t.Fatalf("%s: %v", artifact, err)
		}
	}
}

// TestWindowsBroadGroupACEFailsValidation pins the fail-closed direction: a
// file whose DACL grants Everyone is rejected as a private artifact even
// though its owner is correct.
func TestWindowsBroadGroupACEFailsValidation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "journal.json")
	if err := securePrivateDir(dir); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := widenArtifactForTest(path); err != nil {
		t.Fatal(err)
	}
	err := validatePrivateACL(path)
	if err == nil {
		t.Fatal("Everyone-granting DACL passed private-artifact validation")
	}
	if !strings.Contains(err.Error(), "broad group") {
		t.Fatalf("error = %v, want broad-group rejection", err)
	}
}
