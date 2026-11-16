package delivery

import (
	"context"
	"fmt"
	"net/url"

	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
)

// Redundancy proves either preserved commit history or the deliberately
// narrower preservation of the complete tracked tree in a recorded squash.
func Redundancy(ctx context.Context, api API, p policy.DeliveryPolicy, pr PullRequest, tip string) (string, error) {
	if !pr.Merged || tip != pr.Head.SHA || !ValidOID(tip) || !ValidOID(pr.MergeCommit) {
		return "", fmt.Errorf("branch tip does not match confirmed merged PR")
	}
	var ref struct {
		Object struct {
			SHA  string `json:"sha"`
			Type string `json:"type"`
		} `json:"object"`
	}
	if err := read(ctx, api, "repos/"+p.GitHub+"/git/ref/heads/"+url.PathEscape(p.Base), &ref); err != nil {
		return "", err
	}
	if ref.Object.Type != "commit" || !ValidOID(ref.Object.SHA) {
		return "", fmt.Errorf("default branch identity unavailable")
	}
	reachable := func(sha string) (bool, error) {
		var result struct {
			Status string `json:"status"`
		}
		err := read(ctx, api, "repos/"+p.GitHub+"/compare/"+sha+"..."+ref.Object.SHA, &result)
		return result.Status == "ahead" || result.Status == "identical", err
	}
	ok, err := reachable(tip)
	if err != nil {
		return "", err
	}
	if ok {
		return "ancestry", nil
	}
	if p.Method != "squash" {
		return "", fmt.Errorf("branch commits are not in default history")
	}
	ok, err = reachable(pr.MergeCommit)
	if err != nil {
		return "", err
	}
	if !ok {
		return "", fmt.Errorf("recorded merge is not reachable from default branch")
	}
	type commit struct {
		SHA  string `json:"sha"`
		Tree struct {
			SHA string `json:"sha"`
		} `json:"tree"`
		Parents []struct {
			SHA string `json:"sha"`
		} `json:"parents"`
	}
	var head, squash commit
	if err := read(ctx, api, "repos/"+p.GitHub+"/git/commits/"+tip, &head); err != nil {
		return "", err
	}
	if err := read(ctx, api, "repos/"+p.GitHub+"/git/commits/"+pr.MergeCommit, &squash); err != nil {
		return "", err
	}
	if head.SHA != tip || squash.SHA != pr.MergeCommit || len(squash.Parents) != 1 || !ValidOID(head.Tree.SHA) || head.Tree.SHA != squash.Tree.SHA {
		return "", fmt.Errorf("squash tree is not exactly identical; preserve branch history")
	}
	return "exact-squash-tree", nil
}
