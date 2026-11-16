package approval_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/CtrlCarlitos/agent-guardrails/internal/approval"
)

func TestWindowsDeliveryApprovalIsOperatorScopedAndDurable(t *testing.T) {
	setStateHome(t, t.TempDir())
	r := request()
	r.Plane = "operator"
	r.Host = ""
	r.Scope = approval.RepoScope
	r.Action = "delivery-set"
	r.Parameters = map[string]string{"policy": `{"GitHub":"owner/repo","GitHubID":1,"Base":"main","Method":"squash","ProtectedPaths":["ci/**"]}`}
	b := approval.New()
	created, err := b.Create(r)
	if err != nil {
		t.Fatalf("valid delivery consent rejected: %v", err)
	}
	stored, err := approval.New().Request(created.ID)
	if err != nil || stored.Parameters["policy"] != r.Parameters["policy"] {
		t.Fatalf("policy lost across restart: %+v %v", stored, err)
	}
	if !strings.Contains(stored.Summary(), "owner/repo") || !strings.Contains(stored.Summary(), "ci/**") {
		t.Fatalf("consent hides authorized boundary: %s", stored.Summary())
	}
	r.Plane = "codex"
	if _, err := b.Create(r); !errors.Is(err, approval.ErrMalformed) {
		t.Fatal("agent self-authorized delivery", err)
	}
}
