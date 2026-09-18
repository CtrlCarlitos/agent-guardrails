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
