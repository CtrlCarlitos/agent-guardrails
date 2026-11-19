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

// #616: enable must not accept a policy the repository makes unfishable, and
// must fail closed (with the surfaced reason) where branch rulesets cannot be
// read at all — there, `mergeable_state=clean` proves nothing.
func TestDeliveryEnableValidatesTheRepositoryContract(t *testing.T) {
	savedAPI := deliveryAPI
	t.Cleanup(func() { deliveryAPI = savedAPI })

	repo := func(squash, merge, rebase bool) string {
		return fmt.Sprintf(`{"id":1,"full_name":"owner/repo","default_branch":"main","allow_squash_merge":%t,"allow_merge_commit":%t,"allow_rebase_merge":%t}`, squash, merge, rebase)
	}
	probe := func(t *testing.T, repoDoc, rulesResult string, rulesErr error, args ...string) (int, string, string) {
		t.Helper()
		var out, stderr bytes.Buffer
		deliveryAPI = func(ctx context.Context, path string, body any, out any) error {
			switch {
			case path == "repos/owner/repo" && body == nil:
				return json.Unmarshal([]byte(repoDoc), out)
			case path == "repos/owner/repo/rules/branches/main":
				if rulesErr != nil {
					return rulesErr
				}
				return json.Unmarshal([]byte(rulesResult), out)
			case path == "repos/owner/repo/rulesets/9?includes_parents=true":
				return json.Unmarshal([]byte(`{"id":9,"enforcement":"active","target":"branch","bypass_actors":[],"current_user_can_bypass":"never"}`), out)
			}
			return fmt.Errorf("unexpected API path %s", path)
		}
		code := cmdDelivery(append([]string{"enable"}, args...), true, strings.NewReader("yes\n"), &out, &stderr)
		return code, out.String(), stderr.String()
	}

	sandbox := func(t *testing.T) string {
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
		return root
	}
	notEnabled := func(t *testing.T, root string) {
		t.Helper()
		op, err := policy.LoadOperatorConfig()
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := op.DeliveryFor(root); ok {
			t.Fatalf("rejected enable must not persist an authorization")
		}
	}

	squashOnly := repo(true, false, false)
	baseArgs := []string{"--github", "owner/repo", "--base", "main", "--method", "squash"}

	t.Run("multi-method repository is refused with the remedy", func(t *testing.T) {
		root := sandbox(t)
		code, _, errOut := probe(t, repo(true, true, true), "[]", nil, baseArgs...)
		if code != 1 || !strings.Contains(errOut, "allows merge methods [merge, rebase, squash]") || !strings.Contains(errOut, `restrict the repository to "squash"`) {
			t.Fatalf("code=%d err=%q; want the repository's methods named with the remedy", code, errOut)
		}
		notEnabled(t, root)
	})

	t.Run("plan-gated rulesets fail closed with the surfaced status", func(t *testing.T) {
		root := sandbox(t)
		gated := fmt.Errorf("GitHub API GET repos/owner/repo/rules/branches/main failed: exit status 1: gh: Upgrade to GitHub Pro or make this repository public to enable this feature. (HTTP 403)")
		code, _, errOut := probe(t, squashOnly, "", gated, baseArgs...)
		if code != 1 || !strings.Contains(errOut, "cannot read branch rulesets") || !strings.Contains(errOut, "403") || !strings.Contains(errOut, "Upgrade to GitHub Pro") {
			t.Fatalf("code=%d err=%q; want the surfaced reason and the rulesets guidance", code, errOut)
		}
		notEnabled(t, root)
	})

	t.Run("single-method mismatch names the method to authorize", func(t *testing.T) {
		root := sandbox(t)
		code, _, errOut := probe(t, repo(false, true, false), "[]", nil, baseArgs...)
		if code != 1 || !strings.Contains(errOut, "--method merge") {
			t.Fatalf("code=%d err=%q; want the --method remedy", code, errOut)
		}
		notEnabled(t, root)
	})

	t.Run("a conforming repository enables", func(t *testing.T) {
		root := sandbox(t)
		rules := `[{"type":"required_status_checks","ruleset_id":9,"parameters":{"strict_required_status_checks_policy":true,"required_status_checks":[{"context":"tests","integration_id":15368}]}}]`
		code, _, errOut := probe(t, squashOnly, rules, nil, baseArgs...)
		if code != 0 {
			t.Fatalf("conforming enable failed: %d %s", code, errOut)
		}
		op, err := policy.LoadOperatorConfig()
		if err != nil {
			t.Fatal(err)
		}
		if p, ok := op.DeliveryFor(root); !ok || p.Method != "squash" {
			t.Fatalf("authorization not persisted: %+v", p)
		}
	})
}
