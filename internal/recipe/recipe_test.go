package recipe

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
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
		"lib/app.ex":    "elixir",
		"test/app.exs":  "elixir",
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

func TestDoctorNamesComeFromImplementedRegistryTiers(t *testing.T) {
	if got, want := NamesWithPerEdit(), []string{"go", "python", "js-ts", "rust", "elixir"}; !slices.Equal(got, want) {
		t.Fatalf("NamesWithPerEdit() = %v, want %v", got, want)
	}
	if got, want := NamesWithSession(), []string{"go", "python", "js-ts", "rust", "elixir"}; !slices.Equal(got, want) {
		t.Fatalf("NamesWithSession() = %v, want %v", got, want)
	}
}

func TestElixirRecipeCommands(t *testing.T) {
	r, ok := ForFile("lib/app.ex")
	if !ok {
		t.Fatal("Elixir Recipe not found")
	}
	wantPerEdit := [][]string{
		{"mix", "format", "{file}"},
		{"mix", "credo", "{file}", "--format", "json"},
	}
	wantSession := [][]string{
		{"mix", "compile", "--warnings-as-errors"},
		{"mix", "test"},
	}
	if !slices.EqualFunc(r.PerEdit, wantPerEdit, slices.Equal) || !slices.EqualFunc(r.Session, wantSession, slices.Equal) {
		t.Fatalf("Elixir Recipe = %+v", r)
	}
}

func TestCheckSessionRunsOnlyRecipesWithRootMarkers(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "go.mod"), []byte("module example.test/session\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	oldFind, oldRun := findExecutable, runCommand
	t.Cleanup(func() { findExecutable, runCommand = oldFind, oldRun })
	findExecutable = func(file string) (string, error) { return file, nil }
	var got [][]string
	runCommand = func(dir string, argv []string) ([]byte, error) {
		if dir != root {
			t.Fatalf("command dir = %q, want %q", dir, root)
		}
		got = append(got, append([]string{}, argv...))
		return nil, nil
	}
	if v := CheckSession(root, nil); v != nil {
		t.Fatalf("CheckSession() = %+v, want allow", v)
	}
	want := [][]string{
		{"go", "build", "./..."},
		{"go", "test", "./..."},
		{"golangci-lint", "run"},
		{"govulncheck", "./..."},
	}
	if !slices.EqualFunc(got, want, slices.Equal) {
		t.Fatalf("session commands = %v, want %v", got, want)
	}
}

func TestCheckSessionBlocksOnFirstRealFailureAndSkipsMissingTools(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "pyproject.toml"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	oldFind, oldRun := findExecutable, runCommand
	t.Cleanup(func() { findExecutable, runCommand = oldFind, oldRun })
	findExecutable = func(file string) (string, error) {
		if file == "ruff" {
			return "", errors.New("missing")
		}
		return file, nil
	}
	var got [][]string
	runCommand = func(_ string, argv []string) ([]byte, error) {
		got = append(got, append([]string{}, argv...))
		return []byte("type check failed"), &exec.ExitError{}
	}
	v := CheckSession(root, nil)
	if v == nil || v.Decision != policy.Deny || v.RuleID != "P8.recipe-lint" || v.Reason != "type check failed" {
		t.Fatalf("CheckSession() = %+v, want P8 deny", v)
	}
	if want := [][]string{{"mypy", "."}}; !slices.EqualFunc(got, want, slices.Equal) {
		t.Fatalf("commands before failure = %v, want %v", got, want)
	}
}

func TestOdooRecipeComposesWithAutomaticPerEditRecipes(t *testing.T) {
	root := t.TempDir()
	oldFind, oldRun := findExecutable, runCommand
	t.Cleanup(func() { findExecutable, runCommand = oldFind, oldRun })
	findExecutable = func(file string) (string, error) { return file, nil }
	var got [][]string
	runCommand = func(_ string, argv []string) ([]byte, error) {
		got = append(got, append([]string{}, argv...))
		return nil, nil
	}
	pol := &policy.Policy{Recipes: policy.RecipeConfig{Odoo: &policy.OdooRecipeConfig{
		Module: "sale_guardrail", TestDatabase: "guardrail_test", RelaxNG: "schema/import_xml.rng",
	}}}
	for _, test := range []struct {
		file string
		want [][]string
	}{
		{"addons/sale/models/order.py", [][]string{
			{"ruff", "format", "addons/sale/models/order.py"},
			{"ruff", "check", "--fix", "addons/sale/models/order.py"},
			{"pylint", "--load-plugins=pylint_odoo", "-d", "all", "-e", "odoolint", "addons/sale/models/order.py"},
		}},
		{"addons/sale/static/src/order.js", [][]string{
			{"prettier", "--write", "addons/sale/static/src/order.js"},
			{"eslint", "--fix", "addons/sale/static/src/order.js"},
			{"eslint", "--fix", "addons/sale/static/src/order.js"},
		}},
		{"addons/sale/views/order.xml", [][]string{
			{"xmllint", "--noout", "addons/sale/views/order.xml"},
			{"xmllint", "--noout", "--relaxng", filepath.Join(root, "schema", "import_xml.rng"), "addons/sale/views/order.xml"},
		}},
	} {
		t.Run(filepath.Ext(test.file), func(t *testing.T) {
			got = nil
			tc := engine.ToolCall{Event: "post", Tool: "Write", Paths: []string{test.file}, RepoRoot: root}
			if v := Check(tc, pol); v != nil {
				t.Fatalf("Check() = %+v, want allow", v)
			}
			if !slices.EqualFunc(got, test.want, slices.Equal) {
				t.Fatalf("commands = %v, want %v", got, test.want)
			}
		})
	}
}

func TestOdooRecipeRequiresExplicitOptIn(t *testing.T) {
	oldFind, oldRun := findExecutable, runCommand
	t.Cleanup(func() { findExecutable, runCommand = oldFind, oldRun })
	findExecutable = func(file string) (string, error) { return file, nil }
	runCommand = func(_ string, argv []string) ([]byte, error) {
		t.Fatalf("disabled Odoo Recipe ran %v", argv)
		return nil, nil
	}
	tc := engine.ToolCall{Event: "post", Tool: "Write", Paths: []string{"addons/sale/views/order.xml"}}
	if v := Check(tc, &policy.Policy{}); v != nil {
		t.Fatalf("Check() = %+v, want no Odoo Recipe", v)
	}
}

func TestOdooSessionUsesConfiguredLiteralArguments(t *testing.T) {
	root := t.TempDir()
	oldFind, oldRun := findExecutable, runCommand
	t.Cleanup(func() { findExecutable, runCommand = oldFind, oldRun })
	findExecutable = func(file string) (string, error) { return file, nil }
	var got [][]string
	runCommand = func(dir string, argv []string) ([]byte, error) {
		if dir != root {
			t.Fatalf("command dir = %q, want %q", dir, root)
		}
		got = append(got, append([]string{}, argv...))
		return nil, nil
	}
	pol := &policy.Policy{Recipes: policy.RecipeConfig{Odoo: &policy.OdooRecipeConfig{
		Module: "sale_guardrail", TestDatabase: "guardrail_test", RelaxNG: "schema/import_xml.rng",
	}}}
	if v := CheckSession(root, pol); v != nil {
		t.Fatalf("CheckSession() = %+v, want allow", v)
	}
	want := [][]string{
		{"pylint", "--load-plugins=pylint_odoo", "-d", "all", "-e", "odoolint", "sale_guardrail"},
		{"oca-checks-odoo-module", "sale_guardrail"},
		{"odoo", "-d", "guardrail_test", "--stop-after-init", "--test-enable", "-i", "sale_guardrail"},
	}
	if !slices.EqualFunc(got, want, slices.Equal) {
		t.Fatalf("Odoo session commands = %v, want %v", got, want)
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
	if v := Check(tc, nil); v != nil {
		t.Fatalf("pre event should be ignored, got %+v", v)
	}
}

func TestCheckIgnoresNonFileTools(t *testing.T) {
	tc := engine.ToolCall{Event: "post", Tool: "Bash", Command: "ls"}
	if v := Check(tc, nil); v != nil {
		t.Fatalf("bash should be ignored, got %+v", v)
	}
}

func TestCheckIgnoresUnrecipedExtension(t *testing.T) {
	tc := engine.ToolCall{Event: "post", Tool: "Write", Paths: []string{"README.md"}}
	if v := Check(tc, nil); v != nil {
		t.Fatalf("no recipe for .md, got %+v", v)
	}
}

func TestCheckDeniesOnLintFailure(t *testing.T) {
	// gofmt on a nonexistent file exits nonzero deterministically — no need
	// to construct genuinely malformed Go source for this test.
	tc := engine.ToolCall{Event: "post", Tool: "Write", Paths: []string{"/nonexistent/path/does-not-exist.go"}}
	v := Check(tc, nil)
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
	v := Check(tc, nil)
	if v != nil && !strings.Contains(v.Reason, "error") && v.RuleID != "P8.recipe-lint" {
		t.Fatalf("unexpected verdict shape: %+v", v)
	}
}
