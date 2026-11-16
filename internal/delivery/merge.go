package delivery

import (
	"context"
	"fmt"

	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
)

// Merge performs a head-pinned immediate request. GitHub still enforces the
// current branch requirements; no queued request outlives the inspected head.
func Merge(ctx context.Context, api API, p policy.DeliveryPolicy, n int, head string, before func() error) (PullRequest, error) {
	proof, err := Inspect(ctx, api, p, n, head)
	if err != nil {
		return PullRequest{}, err
	}
	if before == nil {
		return PullRequest{}, fmt.Errorf("delivery mutation requires authorization and audit")
	}
	if err := before(); err != nil {
		return PullRequest{}, err
	}
	var result struct {
		Merged  bool   `json:"merged"`
		SHA     string `json:"sha"`
		Message string `json:"message"`
	}
	if err := api(ctx, fmt.Sprintf("repos/%s/pulls/%d/merge", p.GitHub, n), map[string]string{"sha": proof.Head, "merge_method": p.Method}, &result); err != nil {
		return PullRequest{}, fmt.Errorf("merge request failed; preserve task resources and inspect PR state: %w", err)
	}
	if !result.Merged || !ValidOID(result.SHA) {
		return PullRequest{}, fmt.Errorf("merge not confirmed; preserve task resources")
	}
	_, pr, err := ReadPR(ctx, api, p, n)
	if err != nil {
		return PullRequest{}, fmt.Errorf("merge confirmation unavailable; preserve task resources: %w", err)
	}
	if !pr.Merged || pr.Head.SHA != head || pr.MergeCommit != result.SHA {
		return PullRequest{}, fmt.Errorf("merge confirmation mismatch; preserve task resources")
	}
	return pr, nil
}
