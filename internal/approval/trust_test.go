package approval_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/CtrlCarlitos/agent-guardrails/internal/approval"
)

func TestWindowsOperatorTrustApprovalIsOperatorScopedAndDurable(t *testing.T) {
	setStateHome(t, t.TempDir())
	b := approval.New()

	r := request()
	r.Plane = "operator"
	r.Host = ""
	r.Scope = approval.RepoScope
	r.Action = "operator-trust-set"
	r.Parameters = map[string]string{
		"snapshot": `{"egress_allowlist":["api.example.com"],"web_hosts":["docs.example.com"],"waive":["P6.egress"],"secret_allow":["fixtures/**"],"audit_log":"/tmp/audit.jsonl"}`,
	}

	created, err := b.Create(r)
	if err != nil {
		t.Fatalf("valid operator-trust-set rejected: %v", err)
	}
	stored, err := approval.New().Request(created.ID)
	if err != nil || stored.Parameters["snapshot"] != r.Parameters["snapshot"] {
		t.Fatalf("snapshot lost across restart: %+v %v", stored, err)
	}
	summary := stored.Summary()
	for _, want := range []string{"api.example.com", "docs.example.com", "P6.egress", "fixtures/**"} {
		if !strings.Contains(summary, want) {
			t.Errorf("Summary() = %q, missing %q", summary, want)
		}
	}

	// Revocation ("null") is accepted and summarized clearly.
	revokeReq := r
	revokeReq.Parameters = map[string]string{"snapshot": "null"}
	revoked, err := b.Create(revokeReq)
	if err != nil {
		t.Fatalf("valid operator-trust-set revocation rejected: %v", err)
	}
	if !strings.Contains(strings.ToLower(revoked.Summary()), "revoke") {
		t.Errorf("revocation Summary() = %q, want revoke wording", revoked.Summary())
	}

	// Non-operator plane must fail closed.
	agentReq := r
	agentReq.Plane = "claude"
	if _, err := b.Create(agentReq); !errors.Is(err, approval.ErrMalformed) {
		t.Fatalf("agent plane created operator-trust-set: %v", err)
	}

	// Invalid snapshot (wildcard egress or neverWaivable) must fail closed.
	badReq := r
	badReq.Parameters = map[string]string{"snapshot": `{"egress_allowlist":["*"]}`}
	if _, err := b.Create(badReq); !errors.Is(err, approval.ErrMalformed) {
		t.Fatalf("wildcard snapshot accepted: %v", err)
	}
	badWaive := r
	badWaive.Parameters = map[string]string{"snapshot": `{"waive":["P3.unresolved"]}`}
	if _, err := b.Create(badWaive); !errors.Is(err, approval.ErrMalformed) {
		t.Fatalf("neverWaivable snapshot accepted: %v", err)
	}
}
