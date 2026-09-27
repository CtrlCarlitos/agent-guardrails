package policy

import (
	"strings"
	"testing"
)

// #413 / ADR-0033: operator approvals default to a prompt for everyone; the
// passkey broker is an opt-in written in Operator config.
func TestApprovalModeDefaultsToPrompt(t *testing.T) {
	writeOperatorConfig(t, "")
	op, err := LoadOperatorConfig()
	if err != nil {
		t.Fatal(err)
	}
	if got := op.ApprovalMode(); got != ApprovalPrompt {
		t.Fatalf("empty operator config approval mode = %q, want %q", got, ApprovalPrompt)
	}
	var missing *OperatorConfig
	if got := missing.ApprovalMode(); got != ApprovalPrompt {
		t.Fatalf("nil operator config approval mode = %q, want %q", got, ApprovalPrompt)
	}
}

func TestApprovalModeReadsTopLevelKeyAlongsideRepoTables(t *testing.T) {
	repo := operatorRepo("trusted")
	for _, mode := range []string{ApprovalPrompt, ApprovalPasskey} {
		writeOperatorConfig(t, "approval = \""+mode+"\"\n\n[web_research]\nenforcement = \"off\"\n\n"+tomlRepoKey(repo)+"\nwaive = [\"P6.egress\"]\n")
		op, err := LoadOperatorConfig()
		if err != nil {
			t.Fatalf("mode %s: %v", mode, err)
		}
		if got := op.ApprovalMode(); got != mode {
			t.Fatalf("approval mode = %q, want %q", got, mode)
		}
		if !op.AllowsWaiver(repo, "P6.egress") || op.WebResearchEnforcement != "off" {
			t.Fatalf("the approval key must not disturb the rest of the file: %+v", op)
		}
		if _, isRepo := op.Repos["approval"]; isRepo {
			t.Fatal("the approval key must not be read as a repository")
		}
	}
}

func TestApprovalModeRejectsUnknownValue(t *testing.T) {
	for _, body := range []string{"approval = \"webauthn\"\n", "approval = true\n", "approval = \"\"\n"} {
		writeOperatorConfig(t, body)
		op, err := LoadOperatorConfig()
		if err == nil || !strings.Contains(err.Error(), "approval") {
			t.Fatalf("%q: err = %v, want an error naming approval", body, err)
		}
		assertEmptyOperatorConfig(t, op)
	}
}

// A repository cannot choose how its own agent's operator actions are
// approved: an overlay's `approval` key is an unknown key (a warning), and
// the mode is a property of Operator config alone.
func TestApprovalModeCannotBeSetByOverlay(t *testing.T) {
	p := writeOverlay(t, "approval = \"prompt\"\n")
	ov, err := LoadOverlay(p)
	if err != nil {
		t.Fatalf("an unknown overlay key must not fail the load: %v", err)
	}
	warned := false
	for _, w := range ov.Warnings {
		warned = warned || strings.Contains(w, "approval")
	}
	if !warned {
		t.Fatalf("overlay approval key must be reported as unknown, warnings=%v", ov.Warnings)
	}
	base, err := LoadBase()
	if err != nil {
		t.Fatal(err)
	}
	op := &OperatorConfig{Approval: ApprovalPasskey}
	if _, _, err := Merge(base, ov, "dev", op, operatorRepo("trusted")); err != nil {
		t.Fatal(err)
	}
	if op.ApprovalMode() != ApprovalPasskey {
		t.Fatal("merging an overlay must not change the operator's approval mode")
	}
}
