package policy

import "testing"

func TestDecisionSeverity(t *testing.T) {
	cases := map[Decision]int{Allow: 0, Ask: 1, Deny: 2, Decision("x"): -1}
	for d, want := range cases {
		if got := d.Severity(); got != want {
			t.Errorf("%q.Severity() = %d, want %d", d, got, want)
		}
	}
}

func TestDecisionBlocks(t *testing.T) {
	if !Deny.Blocks() {
		t.Error("Deny should block")
	}
	if Ask.Blocks() || Allow.Blocks() {
		t.Error("only Deny blocks")
	}
}

func TestVerdictIsZero(t *testing.T) {
	if !(Verdict{}).IsZero() {
		t.Error("empty Verdict should be zero")
	}
	if (Verdict{Decision: Allow}).IsZero() {
		t.Error("Verdict with a decision is not zero")
	}
}
