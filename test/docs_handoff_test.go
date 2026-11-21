package test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestWindowsAndPOSIXHandoffProtocolDocs pins the multi-agent handoff and
// review-closure protocol deliverables (#96) so the contributor map, operations
// runbook, PR template, and handoff guide cannot silently drift apart.
func TestWindowsAndPOSIXHandoffProtocolDocs(t *testing.T) {
	root := docsRepoRoot(t)

	guidePath := filepath.Join(root, "docs", "multi-agent-handoff.md")
	guideRaw, err := os.ReadFile(guidePath)
	if err != nil {
		t.Fatalf("read %s: %v", guidePath, err)
	}
	guide := string(guideRaw)

	requiredHeadingsAndClauses := []string{
		"## Required vs optional handoff fields",
		"Base SHA",
		"Branch / worktree",
		"Owned files or seams",
		"Checks actually run",
		"Unresolved limitations",
		"Next responsible owner",
		"## Conflict ownership",
		"## Explicit-file staging",
		"## Review-closure protocol",
		"originating reviewer",
		"## Copyable handoff template",
		"## Finding-to-resolution example",
		"## PR and handoff checklist",
	}
	for _, want := range requiredHeadingsAndClauses {
		if !strings.Contains(guide, want) {
			t.Errorf("docs/multi-agent-handoff.md missing required clause %q", want)
		}
	}

	// CONTRIBUTING.md and docs/OPERATIONS.md must link to the protocol without
	// duplicating competing rules.
	for _, rel := range []string{"CONTRIBUTING.md", filepath.Join("docs", "OPERATIONS.md")} {
		raw, err := os.ReadFile(filepath.Join(root, rel))
		if err != nil {
			t.Fatalf("read %s: %v", rel, err)
		}
		if !strings.Contains(string(raw), "multi-agent-handoff.md") {
			t.Errorf("%s must reference multi-agent-handoff.md", rel)
		}
	}

	// PR template must exist and include the concise verification/handoff prompts.
	prTemplatePath := filepath.Join(root, ".github", "pull_request_template.md")
	prRaw, err := os.ReadFile(prTemplatePath)
	if err != nil {
		t.Fatalf("read %s: %v", prTemplatePath, err)
	}
	prText := string(prRaw)
	for _, want := range []string{
		"Root cause",
		"Verification",
		"multi-agent-handoff.md",
	} {
		if !strings.Contains(prText, want) {
			t.Errorf(".github/pull_request_template.md missing %q", want)
		}
	}
}
