package delivery

import (
	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
	"testing"
)

func TestProtectedCIPathsIncludeReplaceableParents(t *testing.T) {
	p := policy.DeliveryPolicy{ProtectedPaths: []string{"scripts/ci/**"}}
	for _, path := range []string{"scripts", "scripts/ci", "scripts/ci/check.sh"} {
		if !protected(p, path) {
			t.Errorf("CI control ancestor %q can be replaced", path)
		}
	}
	if protected(p, "scripts/application.go") {
		t.Fatal("unrelated application script was protected")
	}
}
