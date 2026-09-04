// Package recipe runs per-language format+lint commands after an edit. See
// docs/adr/0009-recipe-scope.md for why only four languages, per-edit only.
package recipe

import (
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/CtrlCarlitos/agent-guardrails/internal/engine"
	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
)

type Recipe struct {
	Name       string
	Extensions []string
	PerEdit    [][]string
}

var Registry = []Recipe{
	{
		Name:       "go",
		Extensions: []string{".go"},
		PerEdit:    [][]string{{"gofmt", "-w", "{file}"}},
	},
	{
		Name:       "python",
		Extensions: []string{".py"},
		PerEdit: [][]string{
			{"ruff", "format", "{file}"},
			{"ruff", "check", "--fix", "{file}"},
		},
	},
	{
		Name:       "js-ts",
		Extensions: []string{".js", ".jsx", ".ts", ".tsx"},
		PerEdit: [][]string{
			{"prettier", "--write", "{file}"},
			{"eslint", "--fix", "{file}"},
		},
	},
	{
		Name:       "rust",
		Extensions: []string{".rs"},
		PerEdit:    [][]string{{"rustfmt", "{file}"}},
	},
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

func Check(tc engine.ToolCall) *policy.Verdict {
	if tc.Event != "post" || !isWriteTool(tc.Tool) {
		return nil
	}
	for _, p := range tc.Paths {
		r, ok := ForFile(p)
		if !ok {
			continue
		}
		if v := runRecipe(r, p); v != nil {
			return v
		}
	}
	return nil
}

func isWriteTool(tool string) bool {
	switch strings.ToLower(tool) {
	case "write", "edit", "multiedit":
		return true
	}
	return false
}

func runRecipe(r Recipe, file string) *policy.Verdict {
	for _, cmdTemplate := range r.PerEdit {
		argv := make([]string, len(cmdTemplate))
		for i, a := range cmdTemplate {
			if a == "{file}" {
				a = file
			}
			argv[i] = a
		}
		if _, err := exec.LookPath(argv[0]); err != nil {
			continue // tool not installed: skip silently
		}
		out, err := exec.Command(argv[0], argv[1:]...).CombinedOutput()
		if err == nil {
			continue
		}
		if _, isExit := err.(*exec.ExitError); isExit {
			reason := strings.TrimSpace(string(out))
			if reason == "" {
				reason = argv[0] + " failed on " + file
			}
			return &policy.Verdict{Decision: policy.Deny, RuleID: "P8.recipe-lint", Reason: reason}
		}
		// spawn error other than a nonzero exit (e.g. a race where LookPath
		// succeeded but the binary vanished): skip, don't block on infra flakiness.
	}
	return nil
}
