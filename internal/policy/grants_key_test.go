package policy

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// symlinkedSpelling returns a second path that reaches dir through a symlink,
// skipping when the host will not create one (Windows without the privilege).
func symlinkedSpelling(t *testing.T, dir string) string {
	t.Helper()
	alias := filepath.Join(t.TempDir(), "alias")
	if err := os.Symlink(dir, alias); err != nil {
		t.Skipf("symlinks unavailable here: %v", err)
	}
	return alias
}

// Matching and writing must agree on which entry a repository's grants live
// in.
//
// Matching already resolves symlinks before declaring no grant, because on
// Darwin git reports the physical repo root while a grant may be keyed by the
// symlinked spelling. A writer that cleaned the path and indexed the map
// directly would touch a different entry than the matcher read -- and the
// failure that produces is not a missed match but an unspendable one: the
// grant keeps matching, consumption keeps finding nothing to spend, and a
// single-use grant silently becomes unlimited.
func TestGrantKeyAgreesWithMatchingAcrossEquivalentSpellings(t *testing.T) {
	physical := t.TempDir()
	alias := symlinkedSpelling(t, physical)
	now := time.Now()

	o := &OperatorConfig{Repos: map[string]RepoGrant{
		alias: {Commands: []CommandGrant{{
			RuleID: "P2.git-push-protected", Command: "git push origin main",
			Uses: 1, ExpiresAt: now.Add(time.Minute),
		}}},
	}}

	// The matcher finds it through the other spelling.
	if !o.AllowsCommand(physical, "P2.git-push-protected", "git push origin main", now) {
		t.Fatal("matching did not resolve the equivalent spelling; the fixture no longer reproduces the split")
	}
	// A writer must land on the same entry rather than creating a second one.
	key := o.GrantKey(physical)
	if len(o.Repos[key].Commands) != 1 {
		t.Fatalf("GrantKey(%q) = %q, which holds %d grants; want the entry matching read",
			physical, key, len(o.Repos[key].Commands))
	}
	// Spending through the writer's key must actually stop the matcher.
	entry := o.Repos[key]
	entry.Commands[0].Uses = 0
	o.Repos[key] = entry
	if o.AllowsCommand(physical, "P2.git-push-protected", "git push origin main", now) {
		t.Error("the grant still matches after its use was spent: matching and writing disagree on the key")
	}
}

// A repository with no entry yet still gets a stable key to write under.
func TestGrantKeyFallsBackToTheCleanedPath(t *testing.T) {
	o := &OperatorConfig{Repos: map[string]RepoGrant{}}
	repo := operatorRepo("fresh")
	if got := o.GrantKey(repo); got != filepath.Clean(repo) {
		t.Errorf("GrantKey(%q) = %q, want the cleaned path", repo, got)
	}
	var nilConfig *OperatorConfig
	if got := nilConfig.GrantKey(repo); got != filepath.Clean(repo) {
		t.Errorf("nil config GrantKey = %q, want the cleaned path", got)
	}
}
