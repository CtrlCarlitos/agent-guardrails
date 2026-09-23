package genconfig

import (
	"strings"
	"testing"
)

// M4 and C1 from the #282 four-seat gap analysis, retired by operator ruling.
//
// Both floor classes are prefix matches that block a flag which does nothing.
// `Bash(dd *)` blocks `dd if=a.img of=b.img`, an ordinary file copy;
// `Bash(git clean -fd*)` blocks `git clean -fd --dry-run`, which by definition
// deletes nothing. Neither is a safety gap the Engine left open -- measured,
// the Engine denies every destructive member of both families
// (`P1.dd` for device targets, `P1.git-clean` for every forced/recursive
// clean) and deliberately allows the harmless ones.
//
// So the floor was contributing false positives only. Retiring them is the
// operator's ruling on #282, and this test is here so a later "the floor
// should cover dd, surely" does not quietly restore them.

func TestNoOpFloorClassesStayRetiredFromClaudeAndOpenCode(t *testing.T) {
	// One source: opencode.go builds its permission map from bashDenyGlobs()
	// too, so both planes retire together and cannot drift apart.
	for _, glob := range bashDenyGlobs() {
		if strings.HasPrefix(glob, "Bash(dd") {
			t.Errorf("%q is back on the floor: the Engine denies dd to a device (P1.dd) and deliberately allows dd between regular files, so this entry only blocks ordinary copies", glob)
		}
		if strings.Contains(glob, "git clean") {
			t.Errorf("%q is back on the floor: the Engine denies every destructive git clean (P1.git-clean), so this entry only blocks --dry-run and -n", glob)
		}
	}
	for _, glob := range bashAskGlobs() {
		if strings.HasPrefix(glob, "Bash(dd") || strings.Contains(glob, "git clean") {
			t.Errorf("%q moved to the ask tier instead of retiring; the ruling was to retire the class, not to soften it", glob)
		}
	}
}

// ADR-0028's carve-out, pinned in code rather than left to memory.
//
// Codex is the exception plane: its pre-hooks do not dispatch on Windows
// (openai/codex#24453), so its native floor is not a backstop behind the
// Engine -- it is the only enforcement there is. Removing a blanket rule from
// CodexRules() would not retire a false positive, it would remove the gate.
//
// This is exactly the kind of thing a later cleanup pass "makes consistent",
// so the asymmetry is asserted rather than explained in a comment alone.
func TestCodexKeepsTheClassesItIsTheOnlyGateFor(t *testing.T) {
	rules := string(CodexRules())
	for _, want := range []string{
		`pattern = ["dd"]`,
		`pattern = ["git","clean","-fd"]`,
		`pattern = ["git","clean","-df"]`,
	} {
		if !strings.Contains(rules, want) {
			t.Errorf("CodexRules() no longer carries %s.\n"+
				"Codex is ADR-0028's exception plane: its hooks do not dispatch, so this native rule is its only enforcement. "+
				"It retires when doctor observes hook dispatch, not when the other planes retire theirs.", want)
		}
	}
}
