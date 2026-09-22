package policy

import "testing"

// The two operator-issued relaxations must share one exclusion list.
//
// ADR-0018's decision is about the External tier -- it is a per-call operator
// decision -- not about which mechanism is asking to relax it. A command grant
// built against its own copy of the list would reintroduce the identical hole
// through a new door, and more quietly than the overnight relaxation did,
// because a grant looks narrow at the point of issue.
//
// This test exists so the two cannot drift apart: a rule added to the
// exclusion set must become both un-relaxable and un-grantable at once, and a
// rule removed from one cannot silently stay in the other.
func TestBothRelaxationsShareOneExclusionList(t *testing.T) {
	if len(outwardReachAsks) == 0 {
		t.Fatal("the exclusion set is empty; ADR-0018 has been emptied out")
	}
	for ruleID := range outwardReachAsks {
		if !NeverRelaxable(ruleID) {
			t.Errorf("%s is relaxable overnight but is in the exclusion set", ruleID)
		}
		if !NeverGrantable(ruleID) {
			t.Errorf("%s is grantable but is in the exclusion set", ruleID)
		}
	}
	// Grants exclude strictly more than the overnight relaxation does: the
	// fail-closed backstops are un-waivable for the same reason they must be
	// un-grantable, and a grant is a relaxation like any other.
	for ruleID := range neverWaivable {
		if !NeverGrantable(ruleID) {
			t.Errorf("fail-closed backstop %s is grantable", ruleID)
		}
	}
	// An ordinary ask stays available to both, or neither mechanism has a
	// purpose.
	for _, ruleID := range []string{"P5.out-of-repo", "P2.git-push-protected", "P5.ci-infra-lockfile"} {
		if NeverRelaxable(ruleID) || NeverGrantable(ruleID) {
			t.Errorf("%s is excluded from relaxation; only outward reach and the backstops are", ruleID)
		}
	}
}
