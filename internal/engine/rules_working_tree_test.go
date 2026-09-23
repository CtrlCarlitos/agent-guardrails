package engine

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
)

// TestWorkingTreeDeletionFloorCorpusSpellingVariants verifies that all 8 spelling
// variants from the Claude/OpenCode/Codex declarative floor corpus targeting cwd (.)
// and its parent (..) deny under M1 (P1.rm-rf).
func TestWorkingTreeDeletionFloorCorpusSpellingVariants(t *testing.T) {
	repo := t.TempDir()
	sub := filepath.Join(repo, "sub")
	if err := os.Mkdir(sub, 0o755); err != nil {
		t.Fatal(err)
	}

	variants := []string{
		"rm -rf",
		"rm -fr",
		"rm -r -f",
		"rm -f -r",
	}

	for _, v := range variants {
		// Target cwd (.)
		cmdDot := fmt.Sprintf("%s .", v)
		tcDot := ToolCall{Tool: "Bash", Command: cmdDot, CWD: repo, RepoRoot: repo}
		verdictDot := checkBash(tcDot, bashPol())
		if verdictDot == nil || verdictDot.Decision != policy.Deny || verdictDot.RuleID != "P1.rm-rf" {
			t.Errorf("%q at repo root -> %+v, want deny/P1.rm-rf", cmdDot, verdictDot)
		}

		// Target parent (..) from subdirectory
		cmdDotDot := fmt.Sprintf("%s ..", v)
		tcDotDot := ToolCall{Tool: "Bash", Command: cmdDotDot, CWD: sub, RepoRoot: repo}
		verdictDotDot := checkBash(tcDotDot, bashPol())
		if verdictDotDot == nil || verdictDotDot.Decision != policy.Deny || verdictDotDot.RuleID != "P1.rm-rf" {
			t.Errorf("%q at nested cwd -> %+v, want deny/P1.rm-rf", cmdDotDot, verdictDotDot)
		}
	}
}

// TestWorkingTreeDeletionExtendedFlagVariants tests long flags, uppercase -R,
// single-flag variants (-r, -f), and operand terminator (--).
func TestWorkingTreeDeletionExtendedFlagVariants(t *testing.T) {
	repo := t.TempDir()
	sub := filepath.Join(repo, "sub")
	if err := os.Mkdir(sub, 0o755); err != nil {
		t.Fatal(err)
	}

	commands := []struct {
		cmd string
		cwd string
	}{
		{"rm -r .", repo},
		{"rm -R .", repo},
		{"rm --recursive .", repo},
		{"rm -f .", repo},
		{"rm --force .", repo},
		{"rm -rf -- .", repo},
		{"rm -rf -- ..", sub},
		{"rm --recursive --force .", repo},
		{"rm -rf ./.", repo},
		{"rm -rf ./..", sub},
	}

	for _, tt := range commands {
		tc := ToolCall{Tool: "Bash", Command: tt.cmd, CWD: tt.cwd, RepoRoot: repo}
		v := checkBash(tc, bashPol())
		if v == nil || v.Decision != policy.Deny || v.RuleID != "P1.rm-rf" {
			t.Errorf("%q (cwd %q) -> %+v, want deny/P1.rm-rf", tt.cmd, tt.cwd, v)
		}
	}
}

// TestWorkingTreeDeletionPWDAndResolvedAbsoluteForms tests $PWD expansion and
// explicit resolved-absolute path targets.
func TestWorkingTreeDeletionPWDAndResolvedAbsoluteForms(t *testing.T) {
	repo := t.TempDir()
	sub := filepath.Join(repo, "sub")
	deep := filepath.Join(sub, "deep")
	if err := os.MkdirAll(deep, 0o755); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name string
		cmd  string
		cwd  string
	}{
		{"quoted $PWD at repo root", `rm -rf "$PWD"`, repo},
		{"unquoted $PWD at repo root", `rm -rf $PWD`, repo},
		{"quoted $PWD in nested cwd", `rm -rf "$PWD"`, sub},
		{"resolved absolute repo root from repo root", fmt.Sprintf("rm -rf %q", repo), repo},
		{"resolved absolute repo root from nested cwd", fmt.Sprintf("rm -rf %q", repo), sub},
		{"resolved absolute nested cwd", fmt.Sprintf("rm -rf %q", sub), sub},
		{"resolved absolute ancestor of nested cwd", fmt.Sprintf("rm -rf %q", sub), deep},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			tc := ToolCall{Tool: "Bash", Command: tt.cmd, CWD: tt.cwd, RepoRoot: repo}
			v := checkBash(tc, bashPol())
			if v == nil || v.Decision != policy.Deny || v.RuleID != "P1.rm-rf" {
				t.Fatalf("%q (cwd %q) -> %+v, want deny/P1.rm-rf", tt.cmd, tt.cwd, v)
			}
		})
	}
}

// TestWorkingTreeDeletionUnresolvablePWDFailsClosed verifies that when state is
// unseeded (CWD is empty), $PWD cannot be resolved and routes to P3.unresolved.
func TestWorkingTreeDeletionUnresolvablePWDFailsClosed(t *testing.T) {
	cases := []string{
		`rm -rf "$PWD"`,
		`rm -rf $PWD`,
	}
	for _, cmd := range cases {
		tc := ToolCall{Tool: "Bash", Command: cmd, CWD: "", RepoRoot: "/repo"}
		v := checkBash(tc, bashPol())
		if v == nil || v.Decision != policy.Ask || v.RuleID != "P3.unresolved" {
			t.Errorf("unseeded %q -> %+v, want ask/P3.unresolved", cmd, v)
		}
	}
}

// TestWorkingTreeDeletionNonRecursiveAndAlternativeCommands documents and verifies
// our decision on non-recursive rm, rmdir, and unlink:
// - Non-recursive/non-forced `rm .` cannot delete directory trees (fails at runtime in POSIX).
// - `rmdir .` routes to existing ask/P1.rmdir (POSIX rmdir removes one empty directory).
// - `unlink .` routes to normal destination policy (POSIX unlink cannot unlink directories).
func TestWorkingTreeDeletionNonRecursiveAndAlternativeCommands(t *testing.T) {
	repo := t.TempDir()

	// rmdir . routes to P1.rmdir (Ask)
	tcRmdir := ToolCall{Tool: "Bash", Command: "rmdir .", CWD: repo, RepoRoot: repo}
	vRmdir := checkBash(tcRmdir, bashPol())
	if vRmdir == nil || vRmdir.Decision != policy.Ask || vRmdir.RuleID != "P1.rmdir" {
		t.Errorf("rmdir . -> %+v, want ask/P1.rmdir", vRmdir)
	}

	// unlink . in repo is allowed by static policy (runtime fails safely with EISDIR/EPERM)
	tcUnlink := ToolCall{Tool: "Bash", Command: "unlink .", CWD: repo, RepoRoot: repo}
	vUnlink := checkBash(tcUnlink, bashPol())
	if vUnlink != nil {
		t.Errorf("unlink . -> %+v, want allow", vUnlink)
	}

	// rm . without recursive/force flags does not trigger P1.rm-rf
	tcBareRm := ToolCall{Tool: "Bash", Command: "rm .", CWD: repo, RepoRoot: repo}
	vBareRm := checkBash(tcBareRm, bashPol())
	if vBareRm != nil && vBareRm.RuleID == "P1.rm-rf" {
		t.Errorf("bare rm . -> %+v, want no P1.rm-rf", vBareRm)
	}
}

// TestWorkingTreeDeletionBoundaries verifies that deleting legitimate subdirectories
// of cwd or configured safe-root siblings remains allowed under normal policy.
func TestWorkingTreeDeletionBoundaries(t *testing.T) {
	repo := t.TempDir()
	sub := filepath.Join(repo, "sub")
	nested := filepath.Join(sub, "nested")
	sibling := filepath.Join(repo, "sibling")
	safeRoot := t.TempDir()
	if err := os.MkdirAll(nested, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(sibling, 0o755); err != nil {
		t.Fatal(err)
	}

	pol := &policy.Policy{
		Slots:  policy.Slots{SafeRoots: []string{safeRoot}},
		Waived: map[string]bool{},
	}

	cases := []struct {
		name string
		cmd  string
		cwd  string
	}{
		{"subdirectory relative", "rm -rf build", repo},
		{"subdirectory with dot-slash", "rm -rf ./build", repo},
		{"nested subdirectory", "rm -rf sub/nested", repo},
		{"sibling directory inside repo from nested cwd", "rm -rf ../sibling", sub},
		{"safe-root sibling of repo", fmt.Sprintf("rm -rf %q", filepath.Join(safeRoot, "scratch")), repo},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			tc := ToolCall{Tool: "Bash", Command: tt.cmd, CWD: tt.cwd, RepoRoot: repo}
			v := checkBash(tc, pol)
			if v != nil {
				t.Fatalf("%q (cwd %q) -> %+v, want allow", tt.cmd, tt.cwd, v)
			}
		})
	}
}

// TestWorkingTreeDeletionWaivablePerADR0003 verifies that an operator waiver for
// P1.rm-rf permits deleting cwd per ADR-0003.
func TestWorkingTreeDeletionWaivablePerADR0003(t *testing.T) {
	repo := t.TempDir()
	pol := &policy.Policy{
		Waived: map[string]bool{"P1.rm-rf": true},
	}
	tc := ToolCall{Tool: "Bash", Command: "rm -rf .", CWD: repo, RepoRoot: repo}
	v := checkBash(tc, pol)
	if v != nil {
		t.Fatalf("waived rm -rf . -> %+v, want allow", v)
	}
}
