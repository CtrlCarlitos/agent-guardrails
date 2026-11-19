package delivery

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
)

// #616: a finish rejection must name which side to change and that nothing
// happened, not just "does not match".
func TestInspectMethodMismatchNamesBothSides(t *testing.T) {
	api := func(ctx context.Context, path string, body any, out any) error {
		switch path {
		case "repos/o/r":
			return json.Unmarshal([]byte(`{"id":1,"full_name":"o/r","default_branch":"main",
				"allow_squash_merge":true,"allow_merge_commit":true,"allow_rebase_merge":true}`), out)
		case "repos/o/r/pulls/7":
			return json.Unmarshal([]byte(`{"number":7,"state":"open","draft":false,"merged":false,
				"mergeable":true,"mergeable_state":"clean","changed_files":1,
				"head":{"ref":"t","sha":"1111111111111111111111111111111111111111","repo":{"id":1}},
				"base":{"ref":"main","sha":"2222222222222222222222222222222222222222","repo":{"id":1}}}`), out)
		}
		return fmt.Errorf("unexpected API path %s", path)
	}
	p := policy.DeliveryPolicy{GitHubID: 1, GitHub: "o/r", Base: "main", Method: "squash"}
	_, err := Inspect(context.Background(), api, p, 7, "1111111111111111111111111111111111111111")
	if err == nil {
		t.Fatal("multi-method repository must not inspect clean")
	}
	for _, want := range []string{"allows [merge, rebase, squash]", `authorizes exactly "squash"`, `restrict the repository to "squash"`, "nothing was changed"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q lacks %q", err.Error(), want)
		}
	}
}
