package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"regexp"
	"sort"
	"strconv"
	"testing"
)

// hiddenSubcommands are dispatched by run() but deliberately absent from the
// usage text. Every entry needs a reason; an entry that run() no longer
// dispatches fails the test so the list cannot rot (#395).
var hiddenSubcommands = map[string]string{
	"-h":     "alias of help",
	"--help": "alias of help",
}

// dispatchedSubcommands reads the case labels of the switch on args[0] in
// run() from run.go, so the test follows the dispatcher rather than a copy.
func dispatchedSubcommands(t *testing.T) []string {
	t.Helper()
	file, err := parser.ParseFile(token.NewFileSet(), "run.go", nil, 0)
	if err != nil {
		t.Fatalf("parse run.go: %v", err)
	}
	var names []string
	ast.Inspect(file, func(n ast.Node) bool {
		fn, ok := n.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "run" || fn.Recv != nil {
			return true
		}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			sw, ok := n.(*ast.SwitchStmt)
			if !ok {
				return true
			}
			idx, ok := sw.Tag.(*ast.IndexExpr)
			if !ok {
				return true
			}
			if id, ok := idx.X.(*ast.Ident); !ok || id.Name != "args" {
				return true
			}
			for _, stmt := range sw.Body.List {
				for _, expr := range stmt.(*ast.CaseClause).List {
					lit, ok := expr.(*ast.BasicLit)
					if !ok || lit.Kind != token.STRING {
						t.Fatalf("run() dispatches on a non-literal case %T; teach this test to read it", expr)
					}
					name, err := strconv.Unquote(lit.Value)
					if err != nil {
						t.Fatalf("unquote %s: %v", lit.Value, err)
					}
					names = append(names, name)
				}
			}
			return false
		})
		return false
	})
	if len(names) == 0 {
		t.Fatal("found no dispatched subcommands in run.go; the dispatcher changed shape")
	}
	sort.Strings(names)
	return names
}

// TestHelpListsEveryDispatchedSubcommand keeps `guardrail help` and the
// dispatcher in step: a subcommand run() accepts is either documented at the
// start of a usage line or listed in hiddenSubcommands with a reason (#395).
func TestHelpListsEveryDispatchedSubcommand(t *testing.T) {
	dispatched := dispatchedSubcommands(t)
	seen := map[string]bool{}
	for _, name := range dispatched {
		seen[name] = true
		if reason, hidden := hiddenSubcommands[name]; hidden {
			if reason == "" {
				t.Errorf("hidden subcommand %q has no reason", name)
			}
			continue
		}
		line := regexp.MustCompile(`(?m)^  ` + regexp.QuoteMeta(name) + `(\s|$)`)
		if !line.MatchString(usage) {
			t.Errorf("run() dispatches %q but `guardrail help` does not list it; add a usage line or a hiddenSubcommands entry with a reason", name)
		}
	}
	for name := range hiddenSubcommands {
		if !seen[name] {
			t.Errorf("hiddenSubcommands lists %q, which run() no longer dispatches; remove it", name)
		}
	}
}
