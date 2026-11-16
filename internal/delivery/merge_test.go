package delivery

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
)

const fixtureHead = "1111111111111111111111111111111111111111"
const fixtureBase = "2222222222222222222222222222222222222222"

func mergeFixture() map[string]string {
	return map[string]string{
		"repos/o/r":                                   `{"id":1,"full_name":"o/r","default_branch":"main","allow_squash_merge":true}`,
		"repos/o/r/pulls/7":                           `{"number":7,"state":"open","draft":false,"merged":false,"mergeable":true,"mergeable_state":"clean","changed_files":1,"head":{"sha":"` + fixtureHead + `","ref":"topic","repo":{"id":1}},"base":{"ref":"main","sha":"` + fixtureBase + `","repo":{"id":1}}}`,
		"repos/o/r/rules/branches/main":               `[{"type":"required_status_checks","ruleset_id":9,"parameters":{"strict_required_status_checks_policy":true,"required_status_checks":[{"context":"tests","integration_id":15368}]}}]`,
		"repos/o/r/rulesets/9?includes_parents=true":  `{"id":9,"enforcement":"active","target":"branch","bypass_actors":[],"current_user_can_bypass":"never"}`,
		"repos/o/r/pulls/7/files?per_page=100&page=1": `[{"filename":"app.go","status":"modified"}]`,
		"repos/o/r/commits/" + fixtureHead + "/check-runs?per_page=100&page=1": `{"total_count":1,"check_runs":[{"name":"tests","status":"completed","conclusion":"success","app":{"id":15368}}]}`,
	}
}

func fixtureAPI(fixtures map[string]string) API {
	return func(ctx context.Context, path string, body any, out any) error {
		if body != nil {
			return fmt.Errorf("preflight must not mutate")
		}
		raw, ok := fixtures[path]
		if !ok {
			return fmt.Errorf("unavailable API %s", path)
		}
		return json.Unmarshal([]byte(raw), out)
	}
}

func TestInspectMergeRequiresLiveBoundChecks(t *testing.T) {
	p := policy.DeliveryPolicy{GitHubID: 1, GitHub: "o/r", Base: "main", Method: "squash"}
	for _, test := range []struct{ name, path, value, reason string }{
		{"eligible", "", "", ""},
		{"no checks", "repos/o/r/rules/branches/main", `[]`, "required checks"},
		{"loose checks", "repos/o/r/rules/branches/main", `[{"type":"required_status_checks","ruleset_id":9,"parameters":{"strict_required_status_checks_policy":false,"required_status_checks":[{"context":"tests","integration_id":15368}]}}]`, "strict"},
		{"bypass", "repos/o/r/rulesets/9?includes_parents=true", `{"enforcement":"active","target":"branch","bypass_actors":[],"current_user_can_bypass":"always"}`, "bypass"},
		{"workflow", "repos/o/r/pulls/7/files?per_page=100&page=1", `[{"filename":".github/workflows/ci.yml"}]`, "protected"},
		{"rename from workflow", "repos/o/r/pulls/7/files?per_page=100&page=1", `[{"filename":"harmless.yml","previous_filename":".github/workflows/ci.yml","status":"renamed"}]`, "protected"},
		{"rename missing source", "repos/o/r/pulls/7/files?per_page=100&page=1", `[{"filename":"app.go","status":"renamed"}]`, "file list"},
		{"truncated files", "repos/o/r/pulls/7/files?per_page=100&page=1", `[]`, "file list"},
		{"skipped check", "repos/o/r/commits/" + fixtureHead + "/check-runs?per_page=100&page=1", `{"total_count":1,"check_runs":[{"name":"tests","status":"completed","conclusion":"skipped","app":{"id":15368}}]}`, "green"},
		{"offline", "repos/o/r/rules/branches/main", `!offline`, "API"},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := mergeFixture()
			if test.path != "" {
				f[test.path] = test.value
			}
			result, err := Inspect(context.Background(), fixtureAPI(f), p, 7, fixtureHead)
			if test.reason == "" {
				if err != nil || result.Head != fixtureHead {
					t.Fatalf("eligible exact head rejected: %#v %v", result, err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), test.reason) {
				t.Fatalf("want %q rejection, got %v", test.reason, err)
			}
		})
	}
}
