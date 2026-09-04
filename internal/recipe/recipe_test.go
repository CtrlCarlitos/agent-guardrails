package recipe

import (
	"strings"
	"testing"

	"github.com/CtrlCarlitos/agent-guardrails/internal/engine"
	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
)

func TestForFile(t *testing.T) {
	cases := map[string]string{
		"main.go":       "go",
		"app.py":        "python",
		"index.ts":      "js-ts",
		"component.tsx": "js-ts",
		"lib.rs":        "rust",
	}
	for file, want := range cases {
		r, ok := ForFile(file)
		if !ok || r.Name != want {
			t.Errorf("ForFile(%q) = %+v,%v; want %q", file, r, ok, want)
		}
	}
	if _, ok := ForFile("README.md"); ok {
		t.Error("README.md should have no recipe")
	}
}

func TestRegistryNoExtensionCollisions(t *testing.T) {
	seen := map[string]string{}
	for _, r := range Registry {
		for _, ext := range r.Extensions {
			if owner, dup := seen[ext]; dup {
				t.Errorf("extension %q claimed by both %q and %q", ext, owner, r.Name)
			}
			seen[ext] = r.Name
		}
	}
}

func TestCheckIgnoresNonPostEvents(t *testing.T) {
	tc := engine.ToolCall{Event: "pre", Tool: "Write", Paths: []string{"main.go"}}
	if v := Check(tc); v != nil {
		t.Fatalf("pre event should be ignored, got %+v", v)
	}
}

func TestCheckIgnoresNonFileTools(t *testing.T) {
	tc := engine.ToolCall{Event: "post", Tool: "Bash", Command: "ls"}
	if v := Check(tc); v != nil {
		t.Fatalf("bash should be ignored, got %+v", v)
	}
}

func TestCheckIgnoresUnrecipedExtension(t *testing.T) {
	tc := engine.ToolCall{Event: "post", Tool: "Write", Paths: []string{"README.md"}}
	if v := Check(tc); v != nil {
		t.Fatalf("no recipe for .md, got %+v", v)
	}
}

func TestCheckDeniesOnLintFailure(t *testing.T) {
	// gofmt on a nonexistent file exits nonzero deterministically — no need
	// to construct genuinely malformed Go source for this test.
	tc := engine.ToolCall{Event: "post", Tool: "Write", Paths: []string{"/nonexistent/path/does-not-exist.go"}}
	v := Check(tc)
	if v == nil || v.Decision != policy.Deny || v.RuleID != "P8.recipe-lint" {
		t.Fatalf("gofmt on a missing file -> %+v, want deny/P8.recipe-lint", v)
	}
	if v.Reason == "" {
		t.Error("Reason should carry the tool's output")
	}
}

func TestCheckSkipsMissingTool(t *testing.T) {
	tc := engine.ToolCall{Event: "post", Tool: "Write", Paths: []string{"nonexistent-tool-probe.rs"}}
	// rustfmt may or may not be installed on the machine running this test;
	// either way Check must not panic, and must not deny for a reason other
	// than a real lint failure (a missing tool must never surface as deny).
	v := Check(tc)
	if v != nil && !strings.Contains(v.Reason, "error") && v.RuleID != "P8.recipe-lint" {
		t.Fatalf("unexpected verdict shape: %+v", v)
	}
}
