package engine

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
)

// path_spelling_sim: local regression pins for darwin's /var ->
// /private/var divergence, simulated with a symlinked ancestor so the
// behavior is testable on every OS, not just macos-latest.
func symlinkedTempTree(t *testing.T) (raw string) {
	t.Helper()
	real := t.TempDir()
	parent := filepath.Dir(real)
	rawRoot := filepath.Join(parent, "darwinlink")
	if err := os.Symlink(real, rawRoot); err != nil {
		t.Skipf("symlink: %v", err)
	}
	t.Cleanup(func() { os.Remove(rawRoot) })
	return rawRoot
}

func TestSimWaivedLexicalDenyKeepsResolvedAsk(t *testing.T) {
	root := symlinkedTempTree(t)
	cert := filepath.Join(root, "cert.pem")
	if err := os.WriteFile(cert, []byte("c"), 0o600); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(root, ".env")
	if err := os.Symlink(cert, alias); err != nil {
		t.Fatal(err)
	}
	p := fullPol()
	p.Waived["P4.secret-path"] = true
	tc := ToolCall{Tool: "Read", Paths: []string{alias}, CWD: root, RepoRoot: root}
	v := Evaluate(tc, p)
	if v.Decision != policy.Ask || v.RuleID != "P4.secret-path-ambiguous" {
		t.Fatalf("sim -> %+v, want ask/ambiguous", v)
	}
}

func TestSimRepoRelativeToleratesSpelling(t *testing.T) {
	root := symlinkedTempTree(t)
	if err := os.WriteFile(filepath.Join(root, "cert.pem"), []byte("c"), 0o600); err != nil {
		t.Fatal(err)
	}
	resolvedAlias, err := filepath.EvalSymlinks(filepath.Join(root, "cert.pem"))
	if err != nil {
		t.Fatal(err)
	}
	if _, inside := repoRelative(resolvedAlias, root, root); !inside {
		t.Fatalf("repoRelative(%q, root=%q) not inside", resolvedAlias, root)
	}
}

// Git can report the physical repository root while a native tool still uses
// its symlinked spelling. A secret allowance must not hide an actual escape.
func TestSymlinkEscapeWithPhysicalRootAndAliasedCandidate(t *testing.T) {
	alias := symlinkedTempTree(t)
	physical, err := filepath.EvalSymlinks(alias)
	if err != nil {
		t.Fatal(err)
	}
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "note.txt"), []byte("fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(alias, "escape")); err != nil {
		t.Fatal(err)
	}
	pol := fullPol()
	pol.Slots.SecretAllow = []string{"**/note.txt"}
	for _, roots := range [][2]string{{alias, physical}, {physical, alias}} {
		for _, file := range []string{"note.txt", "not-created-yet.txt"} {
			tc := ToolCall{Tool: "Write", Paths: []string{filepath.Join(roots[0], "escape", file)}, CWD: roots[0], RepoRoot: roots[1]}
			v := Evaluate(tc, pol)
			if v.Decision != policy.Deny || v.RuleID != "P4.symlink-escape" {
				t.Fatalf("candidate %q root %q: %+v, want deny/P4.symlink-escape", tc.Paths[0], tc.RepoRoot, v)
			}
		}
	}
}

func TestAmbiguousSecretWithDifferentRepositorySpellings(t *testing.T) {
	alias := symlinkedTempTree(t)
	physical, err := filepath.EvalSymlinks(alias)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(alias, "cert.pem"), []byte("fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, roots := range [][2]string{{alias, physical}, {physical, alias}} {
		v := Evaluate(ToolCall{Tool: "Read", Paths: []string{filepath.Join(roots[0], "cert.pem")}, CWD: roots[0], RepoRoot: roots[1]}, fullPol())
		if v.Decision != policy.Ask || v.RuleID != "P4.secret-path-ambiguous" {
			t.Fatalf("path spelling %q repository %q: %+v", roots[0], roots[1], v)
		}
	}
}
