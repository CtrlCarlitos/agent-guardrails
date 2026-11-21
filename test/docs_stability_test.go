package test

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
)

// TestWindowsAndPOSIXStabilityPolicyMatchesCode mechanically verifies that
// docs/stability-policy.md stays in step with the shipped Operator config
// schema, Overlay schema, additive stable CLI commands, and ADR-0035 posture
// rules (#103).
func TestWindowsAndPOSIXStabilityPolicyMatchesCode(t *testing.T) {
	root := docsRepoRoot(t)
	raw, err := os.ReadFile(filepath.Join(root, "docs", "stability-policy.md"))
	if err != nil {
		t.Fatalf("read docs/stability-policy.md: %v", err)
	}
	doc := string(raw)

	// Every TOML key on policy.RepoGrant must be named in the Operator config section.
	grantType := reflect.TypeOf(policy.RepoGrant{})
	for i := 0; i < grantType.NumField(); i++ {
		tag := grantType.Field(i).Tag.Get("toml")
		key := strings.Split(tag, ",")[0]
		if key == "" || key == "-" {
			continue
		}
		if !strings.Contains(doc, key) {
			t.Errorf("docs/stability-policy.md does not document RepoGrant key %q", key)
		}
	}

	// Required additive stable surfaces and ADR-0035 / non-stable clarifications.
	requiredClauses := []string{
		"guardrail status",
		"guardrail tail",
		"audit --follow",
		"guardrail report",
		"guardrail delivery",
		"operator trust",
		"night on",
		"--scope",
		"--major",
		"ADR-0035",
		"proof.json",
		"explain",
		"2026-11-21",
	}
	for _, want := range requiredClauses {
		if !strings.Contains(doc, want) {
			t.Errorf("docs/stability-policy.md missing %q", want)
		}
	}
}
