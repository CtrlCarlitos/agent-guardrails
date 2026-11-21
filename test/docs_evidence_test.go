package test

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

var evidenceFilenamePattern = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}-[a-z0-9-]+\.md$`)

// TestWindowsAndPOSIXEvidenceDocsShape enforces the docs/evidence/ contract (#114):
// every empirical finding uses YYYY-MM-DD-slug.md naming, carries the six fixed
// sections in order with non-empty content, is indexed in docs/evidence/README.md,
// and ADR-0019 links out to its extracted REPL probe evidence file.
func TestWindowsAndPOSIXEvidenceDocsShape(t *testing.T) {
	root := docsRepoRoot(t)
	evidenceDir := filepath.Join(root, "docs", "evidence")

	readmeBytes, err := os.ReadFile(filepath.Join(evidenceDir, "README.md"))
	if err != nil {
		t.Fatalf("read docs/evidence/README.md: %v", err)
	}
	readme := string(readmeBytes)

	entries, err := os.ReadDir(evidenceDir)
	if err != nil {
		t.Fatalf("readdir docs/evidence: %v", err)
	}

	requiredHeadings := []string{
		"## Claim",
		"## Context",
		"## Method",
		"## Observation",
		"## Consequence",
		"## Links",
	}

	count := 0
	for _, entry := range entries {
		if entry.IsDir() || entry.Name() == "README.md" {
			continue
		}
		name := entry.Name()
		if !evidenceFilenamePattern.MatchString(name) {
			t.Errorf("docs/evidence/%s does not match YYYY-MM-DD-slug.md", name)
			continue
		}
		count++
		if !strings.Contains(readme, name) {
			t.Errorf("docs/evidence/README.md does not index %s", name)
		}
		raw, err := os.ReadFile(filepath.Join(evidenceDir, name))
		if err != nil {
			t.Fatalf("read docs/evidence/%s: %v", name, err)
		}
		text := strings.ReplaceAll(string(raw), "\r\n", "\n")
		prevIdx := -1
		for i, heading := range requiredHeadings {
			idx := strings.Index(text, "\n"+heading+"\n")
			if idx < 0 {
				t.Errorf("docs/evidence/%s missing required heading %q", name, heading)
				continue
			}
			if idx <= prevIdx {
				t.Errorf("docs/evidence/%s heading %q is out of order", name, heading)
			}
			// Verify non-empty body before the next heading (or EOF).
			bodyStart := idx + len("\n"+heading+"\n")
			bodyEnd := len(text)
			if i+1 < len(requiredHeadings) {
				if next := strings.Index(text[bodyStart:], "\n"+requiredHeadings[i+1]+"\n"); next >= 0 {
					bodyEnd = bodyStart + next
				}
			}
			if strings.TrimSpace(text[bodyStart:bodyEnd]) == "" {
				t.Errorf("docs/evidence/%s has empty section %q", name, heading)
			}
			prevIdx = idx
		}
	}
	if count < 6 {
		t.Errorf("docs/evidence/ has %d seeded findings, want at least 6", count)
	}

	adr19, err := os.ReadFile(filepath.Join(root, "docs", "adr", "0019-static-boundary-verification-vs-dynamic-meta-dispatch.md"))
	if err != nil {
		t.Fatalf("read ADR-0019: %v", err)
	}
	if !strings.Contains(string(adr19), "../evidence/2026-09-18-claude-repl-mediation-probe.md") {
		t.Errorf("ADR-0019 must link to ../evidence/2026-09-18-claude-repl-mediation-probe.md")
	}
}
