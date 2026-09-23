// Package recipe runs the per-edit and session-completion tiers of P8 Recipes.
package recipe

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/CtrlCarlitos/agent-guardrails/internal/engine"
	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
)

type Recipe struct {
	Name             string
	Extensions       []string
	PerEdit          [][]string
	PerExtensionEdit map[string][][]string
	Session          [][]string
	RootMarkers      []string
}

var Registry = []Recipe{
	{
		Name:       "go",
		Extensions: []string{".go"},
		PerEdit:    [][]string{{"gofmt", "-w", "{file}"}},
		Session: [][]string{
			{"go", "build", "./..."},
			{"go", "test", "./..."},
			{"golangci-lint", "run"},
			{"govulncheck", "./..."},
		},
		RootMarkers: []string{"go.mod", "go.work"},
	},
	{
		Name:       "python",
		Extensions: []string{".py"},
		PerEdit: [][]string{
			{"ruff", "format", "{file}"},
			{"ruff", "check", "--fix", "{file}"},
		},
		Session: [][]string{
			{"ruff", "check", "."},
			{"mypy", "."},
			{"pytest"},
		},
		RootMarkers: []string{"pyproject.toml", "setup.py", "setup.cfg", "requirements.txt"},
	},
	{
		Name:       "js-ts",
		Extensions: []string{".js", ".jsx", ".ts", ".tsx"},
		PerEdit: [][]string{
			{"prettier", "--write", "{file}"},
			{"eslint", "--fix", "{file}"},
		},
		Session: [][]string{
			{"tsc", "--noEmit"},
			{"eslint", "."},
			{"npm", "test", "--if-present"},
		},
		RootMarkers: []string{"package.json", "tsconfig.json", "jsconfig.json"},
	},
	{
		Name:       "rust",
		Extensions: []string{".rs"},
		PerEdit:    [][]string{{"rustfmt", "{file}"}},
		Session: [][]string{
			{"cargo", "fmt", "--all", "--", "--check"},
			{"cargo", "clippy", "--all-targets", "--", "-D", "warnings"},
			{"cargo", "test"},
		},
		RootMarkers: []string{"Cargo.toml"},
	},
	{
		Name:       "elixir",
		Extensions: []string{".ex", ".exs"},
		PerEdit: [][]string{
			{"mix", "format", "{file}"},
			{"mix", "credo", "{file}", "--format", "json"},
		},
		Session: [][]string{
			{"mix", "compile", "--warnings-as-errors"},
			{"mix", "test"},
		},
		RootMarkers: []string{"mix.exs"},
	},
}

var (
	findExecutable = exec.LookPath
	runCommand     = func(dir string, argv []string) ([]byte, error) {
		cmd := exec.Command(argv[0], argv[1:]...)
		cmd.Dir = dir
		return cmd.CombinedOutput()
	}
)

// NamesWithPerEdit returns the Recipes whose per-edit tier is implemented.
// Doctor uses the registry itself so an implementation cannot silently exist
// without appearing in operator-visible diagnostics.
func NamesWithPerEdit() []string {
	var names []string
	for _, r := range Registry {
		if len(r.PerEdit) > 0 {
			names = append(names, r.Name)
		}
	}
	return names
}

// NamesWithSession returns the Recipes whose session-completion tier is
// implemented. Execution remains Claude-only at the plane seam.
func NamesWithSession() []string {
	var names []string
	for _, r := range Registry {
		if len(r.Session) > 0 {
			names = append(names, r.Name)
		}
	}
	return names
}

func ForFile(path string) (Recipe, bool) {
	ext := filepath.Ext(path)
	for _, r := range Registry {
		for _, e := range r.Extensions {
			if e == ext {
				return r, true
			}
		}
	}
	return Recipe{}, false
}

func Check(tc engine.ToolCall, pol *policy.Policy) *policy.Verdict {
	if tc.Event != "post" || !isWriteTool(tc.Tool) {
		return nil
	}
	for _, p := range tc.Paths {
		var applicable []Recipe
		if r, ok := ForFile(p); ok {
			applicable = append(applicable, r)
		}
		if pol != nil && pol.Recipes.Odoo != nil {
			odoo := odooRecipe(*pol.Recipes.Odoo, tc.RepoRoot)
			if recipeMatchesExtension(odoo, filepath.Ext(p)) {
				applicable = append(applicable, odoo)
			}
		}
		for _, r := range applicable {
			if v := runRecipe(r, p); v != nil {
				return v
			}
		}
	}
	return nil
}

// CheckSession runs every installed session tier whose project marker exists
// at the repository root. The hook pipeline invokes it only for Claude
// Stop/SubagentStop events.
func CheckSession(root string, pol *policy.Policy) *policy.Verdict {
	configured := append([]Recipe{}, Registry...)
	if pol != nil && pol.Recipes.Odoo != nil {
		configured = append(configured, odooRecipe(*pol.Recipes.Odoo, root))
	}
	for _, r := range configured {
		if len(r.Session) == 0 || (len(r.RootMarkers) > 0 && !hasRootMarker(root, r.RootMarkers)) {
			continue
		}
		if v := runCommands(r.Session, root, "", r.Name+" session checks"); v != nil {
			return v
		}
	}
	return nil
}

func hasRootMarker(root string, markers []string) bool {
	if root == "" {
		return false
	}
	for _, marker := range markers {
		if info, err := os.Stat(filepath.Join(root, marker)); err == nil && !info.IsDir() {
			return true
		}
	}
	return false
}

func isWriteTool(tool string) bool {
	switch strings.ToLower(tool) {
	case "write", "edit", "multiedit":
		return true
	}
	return false
}

func runRecipe(r Recipe, file string) *policy.Verdict {
	commands := append([][]string{}, r.PerEdit...)
	commands = append(commands, r.PerExtensionEdit[filepath.Ext(file)]...)
	return runCommands(commands, "", file, "file "+file)
}

func recipeMatchesExtension(r Recipe, extension string) bool {
	for _, candidate := range r.Extensions {
		if candidate == extension {
			return true
		}
	}
	return false
}

func odooRecipe(config policy.OdooRecipeConfig, root string) Recipe {
	relaxNG := config.RelaxNG
	if root != "" {
		relaxNG = filepath.Join(root, strings.ReplaceAll(config.RelaxNG, "\\", string(filepath.Separator)))
	}
	return Recipe{
		Name:       "odoo",
		Extensions: []string{".py", ".js", ".xml"},
		PerExtensionEdit: map[string][][]string{
			".py": {
				{"pylint", "--load-plugins=pylint_odoo", "-d", "all", "-e", "odoolint", "{file}"},
			},
			".js": {
				{"eslint", "--fix", "{file}"},
			},
			".xml": {
				{"xmllint", "--noout", "{file}"},
				{"xmllint", "--noout", "--relaxng", relaxNG, "{file}"},
			},
		},
		Session: [][]string{
			{"pylint", "--load-plugins=pylint_odoo", "-d", "all", "-e", "odoolint", config.Module},
			{"oca-checks-odoo-module", config.Module},
			{"odoo", "-d", config.TestDatabase, "--stop-after-init", "--test-enable", "-i", config.Module},
		},
	}
}

func runCommands(commands [][]string, dir, file, target string) *policy.Verdict {
	for _, cmdTemplate := range commands {
		argv := make([]string, len(cmdTemplate))
		for i, a := range cmdTemplate {
			if a == "{file}" {
				a = file
			}
			argv[i] = a
		}
		if _, err := findExecutable(argv[0]); err != nil {
			continue // tool not installed: skip silently
		}
		out, err := runCommand(dir, argv)
		if err == nil {
			continue
		}
		if _, isExit := err.(*exec.ExitError); isExit {
			reason := strings.TrimSpace(string(out))
			if reason == "" {
				reason = argv[0] + " failed on " + target
			}
			return &policy.Verdict{Decision: policy.Deny, RuleID: "P8.recipe-lint", Reason: reason}
		}
		// spawn error other than a nonzero exit (e.g. a race where LookPath
		// succeeded but the binary vanished): skip, don't block on infra flakiness.
	}
	return nil
}
