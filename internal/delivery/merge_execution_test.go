package delivery

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
)

func TestMergePinsHeadAndRequiresAuditBeforeMutation(t *testing.T) {
	for _, auditOK := range []bool{false, true} {
		t.Run(fmt.Sprint(auditOK), func(t *testing.T) {
			f := mergeFixture()
			merged := false
			audited := false
			api := func(ctx context.Context, path string, body any, out any) error {
				if body == nil {
					return fixtureAPI(f)(ctx, path, nil, out)
				}
				if !audited {
					t.Fatal("mutation before successful authorization/audit")
				}
				raw, _ := json.Marshal(body)
				var payload map[string]any
				_ = json.Unmarshal(raw, &payload)
				if path != "repos/o/r/pulls/7/merge" || payload["sha"] != fixtureHead || payload["merge_method"] != "squash" {
					t.Fatalf("unbound merge: %s %s", path, raw)
				}
				merged = true
				f["repos/o/r/pulls/7"] = `{"number":7,"state":"closed","merged":true,"merge_commit_sha":"3333333333333333333333333333333333333333","head":{"sha":"` + fixtureHead + `","ref":"topic","repo":{"id":1}},"base":{"ref":"main","sha":"` + fixtureBase + `","repo":{"id":1}}}`
				return json.Unmarshal([]byte(`{"merged":true,"sha":"3333333333333333333333333333333333333333"}`), out)
			}
			_, err := Merge(context.Background(), api, policy.DeliveryPolicy{GitHubID: 1, GitHub: "o/r", Base: "main", Method: "squash"}, 7, fixtureHead, func() error {
				if !auditOK {
					return fmt.Errorf("audit unavailable")
				}
				audited = true
				return nil
			})
			if auditOK && (err != nil || !merged) {
				t.Fatalf("eligible merge failed: %v", err)
			}
			if !auditOK && (err == nil || merged) {
				t.Fatalf("failed audit allowed mutation: %v", err)
			}
		})
	}
}
