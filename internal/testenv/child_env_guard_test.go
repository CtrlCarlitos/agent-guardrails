package testenv

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWindowsChildProcessRootEnvUsesSharedHelper(t *testing.T) {
	repoRoot := filepath.Join("..", "..")
	rootAssignments := []string{
		"XDG_CONFIG_HOME=", "XDG_STATE_HOME=", "USERPROFILE=", "LOCALAPPDATA=", "APPDATA=", "HOME=",
	}
	err := filepath.WalkDir(repoRoot, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			if entry.Name() == ".git" || entry.Name() == ".worktrees" || entry.Name() == "vendor" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, "_test.go") || filepath.Base(path) == "child_env_guard_test.go" {
			return nil
		}
		source, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		files := token.NewFileSet()
		parsed, err := parser.ParseFile(files, path, source, 0)
		if err != nil {
			return err
		}
		ast.Inspect(parsed, func(node ast.Node) bool {
			assignment, ok := node.(*ast.AssignStmt)
			if !ok || !assignsCommandEnv(assignment) {
				return true
			}
			start := files.Position(assignment.Pos()).Offset
			end := files.Position(assignment.End()).Offset
			text := string(source[start:end])
			for _, root := range rootAssignments {
				if strings.Contains(text, root) {
					t.Errorf("%s:%d sets %s directly on a child environment; use testenv.ChildProcessEnv so Unix and Windows roots stay paired", filepath.ToSlash(path), files.Position(assignment.Pos()).Line, root)
					break
				}
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func assignsCommandEnv(assignment *ast.AssignStmt) bool {
	for _, target := range assignment.Lhs {
		selector, ok := target.(*ast.SelectorExpr)
		if ok && selector.Sel.Name == "Env" {
			return true
		}
	}
	return false
}
