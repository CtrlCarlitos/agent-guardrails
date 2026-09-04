// Package recipe runs per-language format+lint commands after an edit. See
// docs/adr/0009-recipe-scope.md for why only four languages, per-edit only.
package recipe

import "path/filepath"

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
