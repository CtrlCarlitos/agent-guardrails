package policy

import (
	"testing"
	"time"
)

// A grant is night mode with a smaller blast radius: an operator-issued,
// time-boxed relaxation of Ask to Allow. These tests pin the three properties
// that keep the blast radius small -- exact matching, inherited exclusions,
// and a bounded number of uses -- because each of them is the kind of thing
// that reads correctly while being wrong.

func grantRepo() string { return operatorRepo("repo") }

func configWithGrant(t *testing.T, g CommandGrant) *OperatorConfig {
	t.Helper()
	return &OperatorConfig{Repos: map[string]RepoGrant{
		grantRepo(): {Commands: []CommandGrant{g}},
	}}
}

func pushCommand() CommandGrant {
	return CommandGrant{RuleID: "P2.git-push-protected", Command: "git push origin main", Uses: 1}
}

// Exact (repo, rule ID, command). No wildcards, no globbing, no prefix match:
// the operator authorizes the command that was actually refused, and "exact"
// has to mean exact or the guarantee is "whatever the matcher happened to do".
func TestCommandGrantRequiresTheWholeTripleToMatch(t *testing.T) {
	o := configWithGrant(t, pushCommand())
	now := time.Now()
	if !o.AllowsCommand(grantRepo(), "P2.git-push-protected", "git push origin main", now) {
		t.Fatal("the exact triple must match, or nothing else here means anything")
	}
	for _, c := range []struct {
		name              string
		repo, rule, given string
	}{
		{"another repository", operatorRepo("other"), "P2.git-push-protected", "git push origin main"},
		{"another rule", grantRepo(), "P2.git-push-delete", "git push origin main"},
		{"another command", grantRepo(), "P2.git-push-protected", "git push origin release"},
		{"a longer command with the granted one as its prefix", grantRepo(), "P2.git-push-protected", "git push origin main --force"},
		{"a chained command", grantRepo(), "P2.git-push-protected", "git push origin main; rm -rf ."},
		{"trailing whitespace", grantRepo(), "P2.git-push-protected", "git push origin main "},
		{"different spacing", grantRepo(), "P2.git-push-protected", "git  push origin main"},
	} {
		if o.AllowsCommand(c.repo, c.rule, c.given, now) {
			t.Errorf("%s matched; a grant authorizes one command, not a family", c.name)
		}
	}
}

// The agent is the party that asks the operator to issue the grant, so a
// grant that reads like a pattern must not behave like one: the stored text is
// compared literally, and a glob in it authorizes only a command containing
// that glob verbatim.
func TestGrantTextIsNeverInterpretedAsAPattern(t *testing.T) {
	o := configWithGrant(t, CommandGrant{RuleID: "P2.git-push-protected", Command: "git push *", Uses: 1})
	now := time.Now()
	if o.AllowsCommand(grantRepo(), "P2.git-push-protected", "git push origin main", now) {
		t.Error(`"git push *" authorized "git push origin main"; the grant language has no wildcards`)
	}
	if !o.AllowsCommand(grantRepo(), "P2.git-push-protected", "git push *", now) {
		t.Error("the literal text must still match itself")
	}
}

// ADR-0018 took the External tier back from night mode because it had silently
// widened into outward reach. A grant is the same kind of relaxation through a
// new door, and it looks narrower at the point of issue, so it must inherit
// the same exclusions. The fail-closed backstops are excluded for the same
// reason they can never be waived: relaxing one converts a fail-closed design
// into a fail-open one.
func TestNeverGrantableCoversOutwardReachAndTheFailClosedBackstops(t *testing.T) {
	for _, ruleID := range []string{
		"capability-external", "capability-web-search", "unknown-native-tool",
		"tokenize-failed", "panic-recovered", "P3.unresolved",
	} {
		if !NeverGrantable(ruleID) {
			t.Errorf("%s is grantable; it must not be", ruleID)
		}
		o := configWithGrant(t, CommandGrant{RuleID: ruleID, Command: "npx some-tool", Uses: 1})
		if o.AllowsCommand(grantRepo(), ruleID, "npx some-tool", time.Now()) {
			t.Errorf("a recorded grant for %s still matched; the exclusion must hold at match time too", ruleID)
		}
	}
	if NeverGrantable("P2.git-push-protected") {
		t.Error("an ordinary ask must stay grantable, or the mechanism has no purpose")
	}
}

// One use by default. Every case in the filing needed exactly one successful
// pass; a window alone authorizes an unbounded number of them.
func TestGrantUsesAreBoundedAndExhaustible(t *testing.T) {
	now := time.Now()
	spent := configWithGrant(t, CommandGrant{RuleID: "P2.git-push-protected", Command: "git push origin main", Uses: 0})
	if spent.AllowsCommand(grantRepo(), "P2.git-push-protected", "git push origin main", now) {
		t.Error("a grant with no uses left still matched")
	}
	// Absent and exhausted are the same value once a grant has been through
	// TOML, and consumption writes the count back. Reading an absent count as
	// "one use" would therefore hand a spent grant a fresh use on every
	// reload, which is the one direction this must never fail in. So absent
	// means none, issuance always writes the count, and a hand-edited entry
	// that omits it is inert rather than generous.
	unset := configWithGrant(t, CommandGrant{RuleID: "P2.git-push-protected", Command: "git push origin main"})
	if unset.AllowsCommand(grantRepo(), "P2.git-push-protected", "git push origin main", now) {
		t.Error("an entry with no recorded use count matched; absent must not mean available")
	}
	if got := IssuedUses(0); got != 1 {
		t.Errorf("issued default uses = %d, want 1: one pass is what every case in the filing needed", got)
	}
	if got := IssuedUses(3); got != 3 {
		t.Errorf("issued explicit uses = %d, want 3", got)
	}
}

// The TTL is an upper bound, not the only bound.
func TestGrantExpiryIsAnUpperBound(t *testing.T) {
	now := time.Now()
	expired := configWithGrant(t, CommandGrant{
		RuleID: "P2.git-push-protected", Command: "git push origin main", Uses: 5,
		ExpiresAt: now.Add(-time.Second),
	})
	if expired.AllowsCommand(grantRepo(), "P2.git-push-protected", "git push origin main", now) {
		t.Error("an expired grant matched even with uses remaining")
	}
	live := configWithGrant(t, CommandGrant{
		RuleID: "P2.git-push-protected", Command: "git push origin main", Uses: 1,
		ExpiresAt: now.Add(time.Minute),
	})
	if !live.AllowsCommand(grantRepo(), "P2.git-push-protected", "git push origin main", now) {
		t.Error("an unexpired grant with a use left must match")
	}
}

// An issued grant is bounded even when the operator asks for longer, and a
// grant with no recorded expiry is not an open-ended one.
func TestIssuedExpiryIsClampedToTheMaximum(t *testing.T) {
	now := time.Now()
	if got := BoundedGrantExpiry(now, 0); got != now.Add(DefaultGrantExpiry) {
		t.Errorf("unset duration -> %v, want the %v default", got, DefaultGrantExpiry)
	}
	if got := BoundedGrantExpiry(now, 10*time.Minute); got != now.Add(10*time.Minute) {
		t.Errorf("in-range duration -> %v, want it honoured", got)
	}
	if got := BoundedGrantExpiry(now, 30*24*time.Hour); got != now.Add(MaxGrantExpiry) {
		t.Errorf("over-long duration -> %v, want clamping to %v", got, MaxGrantExpiry)
	}
	// Expiry is the optional bound; the use count is the one that is always
	// present. An entry with no recorded expiry is therefore still bounded --
	// by its uses -- rather than unbounded.
	zero := configWithGrant(t, CommandGrant{RuleID: "P2.git-push-protected", Command: "git push origin main", Uses: 1})
	if !zero.AllowsCommand(grantRepo(), "P2.git-push-protected", "git push origin main", now.Add(MaxGrantExpiry+time.Second)) {
		t.Error("an entry with no recorded expiry must remain use-bounded, not time-expired")
	}
}
