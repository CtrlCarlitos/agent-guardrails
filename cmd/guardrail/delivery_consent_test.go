package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/CtrlCarlitos/agent-guardrails/internal/delivery"
	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
	"github.com/CtrlCarlitos/agent-guardrails/internal/testenv"
)

func TestWindowsDeliveryConsentPersistsAndRevokes(t *testing.T) {
	savedAPI := deliveryAPI
	t.Cleanup(func() { deliveryAPI = savedAPI })
	deliveryAPI = func(ctx context.Context, path string, body any, out any) error {
		switch path {
		case "repos/owner/repo":
			if body != nil {
				return fmt.Errorf("unexpected API")
			}
			return json.Unmarshal([]byte(`{"id":1,"full_name":"owner/repo","default_branch":"main","allow_squash_merge":true}`), out)
		case "repos/owner/repo/rules/branches/main":
			return json.Unmarshal([]byte(`[{"type":"required_status_checks","ruleset_id":9,"parameters":{"strict_required_status_checks_policy":true,"required_status_checks":[{"context":"tests","integration_id":15368}]}}]`), out)
		case "repos/owner/repo/rulesets/9?includes_parents=true":
			return json.Unmarshal([]byte(`{"id":9,"enforcement":"active","target":"branch","bypass_actors":[],"current_user_can_bypass":"never"}`), out)
		}
		return fmt.Errorf("unexpected API path %s", path)
	}

	testenv.SetConfig(t, t.TempDir())
	testenv.SetState(t, t.TempDir())
	if err := os.MkdirAll(filepath.Dir(policy.OperatorConfigPath()), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(policy.OperatorConfigPath(), []byte("approval = 'prompt'\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	root, err := delivery.CommonRoot(context.Background(), cwd)
	if err != nil {
		t.Fatal(err)
	}
	var out, stderr bytes.Buffer
	args := []string{"enable", "--github", "owner/repo", "--protect", "ci/**"}
	if code := cmdDelivery(args, false, strings.NewReader("yes\n"), &out, &stderr); code != 2 {
		t.Fatalf("agent enabled delivery: %d", code)
	}
	if code := cmdDelivery(args, true, strings.NewReader("yes\n"), &out, &stderr); code != 0 {
		t.Fatalf("terminal consent failed: %d %s", code, stderr.String())
	}
	op, err := policy.LoadOperatorConfig()
	if err != nil {
		t.Fatal(err)
	}
	configured, ok := op.DeliveryFor(root)
	if !ok || configured.GitHub != "owner/repo" || len(configured.ProtectedPaths) != 1 {
		t.Fatalf("consent not persisted: %+v", configured)
	}
	if err := mutateCommandGrants(root, func(g []policy.CommandGrant) []policy.CommandGrant { return g }); err != nil {
		t.Fatal(err)
	}
	op, err = policy.LoadOperatorConfig()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := op.DeliveryFor(root); !ok {
		t.Fatal("ordinary grant rewrite erased standing delivery")
	}
	if code := cmdDelivery([]string{"revoke"}, true, strings.NewReader("yes\n"), &out, &stderr); code != 0 {
		t.Fatalf("revoke failed: %d %s", code, stderr.String())
	}
	if err := deliveryMutationAllowed(root, configured, "merge", 7, "1111111111111111111111111111111111111111"); err == nil {
		t.Fatal("revoked policy still authorized mutation")
	}
}
