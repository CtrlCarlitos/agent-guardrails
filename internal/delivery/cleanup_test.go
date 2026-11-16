package delivery

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
)

func TestCleanupProofNeverUsesPatchID(t *testing.T) {
	for _, test := range []struct {
		name, headTree, squashTree, status string
		want                               bool
	}{
		{"ancestry", "", "", "ahead", true},
		{"exact squash", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "diverged", true},
		{"different squash", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "diverged", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			p := policy.DeliveryPolicy{GitHubID: 1, GitHub: "o/r", Base: "main", Method: "squash"}
			pr := PullRequest{Merged: true, MergeCommit: "3333333333333333333333333333333333333333"}
			pr.Head.SHA = fixtureHead
			api := func(ctx context.Context, path string, body any, out any) error {
				if body != nil {
					t.Fatal("proof mutated remote")
				}
				var raw string
				switch {
				case path == "repos/o/r/git/ref/heads/main":
					raw = `{"object":{"type":"commit","sha":"` + fixtureBase + `"}}`
				case strings.HasPrefix(path, "repos/o/r/compare/"+fixtureHead):
					raw = `{"status":"` + test.status + `"}`
				case strings.HasPrefix(path, "repos/o/r/compare/3333"):
					raw = `{"status":"ahead"}`
				case path == "repos/o/r/git/commits/"+fixtureHead:
					raw = `{"sha":"` + fixtureHead + `","tree":{"sha":"` + test.headTree + `"}}`
				case path == "repos/o/r/git/commits/"+pr.MergeCommit:
					raw = `{"sha":"` + pr.MergeCommit + `","tree":{"sha":"` + test.squashTree + `"},"parents":[{"sha":"` + fixtureBase + `"}]}`
				default:
					return fmt.Errorf("unavailable %s", path)
				}
				return json.Unmarshal([]byte(raw), out)
			}
			_, err := Redundancy(context.Background(), api, p, pr, fixtureHead)
			if (err == nil) != test.want {
				t.Fatalf("proof result %v, want success %v", err, test.want)
			}
			if _, err := Redundancy(context.Background(), api, p, pr, "4444444444444444444444444444444444444444"); err == nil {
				t.Fatal("extra local commit accepted")
			}
		})
	}
}
