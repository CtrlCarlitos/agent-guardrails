// Package delivery implements the bounded executor authorized by operator policy.
// No model assertion, cached audit record or repository Overlay is authority.
package delivery

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
	"github.com/bmatcuk/doublestar/v4"
)

type API func(context.Context, string, any, any) error

type Repository struct {
	ID            int64  `json:"id"`
	FullName      string `json:"full_name"`
	DefaultBranch string `json:"default_branch"`
	Squash        bool   `json:"allow_squash_merge"`
	Merge         bool   `json:"allow_merge_commit"`
	Rebase        bool   `json:"allow_rebase_merge"`
}

type PullRequest struct {
	Number         int    `json:"number"`
	State          string `json:"state"`
	Draft          bool   `json:"draft"`
	Merged         bool   `json:"merged"`
	Mergeable      *bool  `json:"mergeable"`
	MergeableState string `json:"mergeable_state"`
	ChangedFiles   int    `json:"changed_files"`
	MergeCommit    string `json:"merge_commit_sha"`
	Head           struct {
		SHA  string `json:"sha"`
		Ref  string `json:"ref"`
		Repo struct {
			ID int64 `json:"id"`
		} `json:"repo"`
	} `json:"head"`
	Base struct {
		SHA  string `json:"sha"`
		Ref  string `json:"ref"`
		Repo struct {
			ID int64 `json:"id"`
		} `json:"repo"`
	} `json:"base"`
}

type Proof struct {
	Head, Base string
	PR         PullRequest
}

var oidPattern = regexp.MustCompile(`^[a-f0-9]{40}$`)

func ValidOID(value string) bool { return oidPattern.MatchString(value) }

func read(ctx context.Context, api API, path string, out any) error {
	if err := api(ctx, path, nil, out); err != nil {
		return fmt.Errorf("delivery API unavailable (%s): %w", path, err)
	}
	return nil
}

func ReadPR(ctx context.Context, api API, p policy.DeliveryPolicy, n int) (Repository, PullRequest, error) {
	var repo Repository
	var pr PullRequest
	if err := p.Validate(); err != nil {
		return repo, pr, err
	}
	if n < 1 {
		return repo, pr, fmt.Errorf("invalid PR number")
	}
	root := "repos/" + p.GitHub
	if err := read(ctx, api, root, &repo); err != nil {
		return repo, pr, err
	}
	if repo.ID != p.GitHubID || repo.FullName != p.GitHub || repo.DefaultBranch != p.Base {
		return repo, pr, fmt.Errorf("repository identity or default branch changed")
	}
	if err := read(ctx, api, fmt.Sprintf("%s/pulls/%d", root, n), &pr); err != nil {
		return repo, pr, err
	}
	if pr.Number != n || pr.Base.Ref != p.Base || pr.Base.Repo.ID != repo.ID || pr.Head.Repo.ID != repo.ID || !ValidOID(pr.Head.SHA) || !ValidOID(pr.Base.SHA) {
		return repo, pr, fmt.Errorf("PR repository, base or head identity is unproven")
	}
	return repo, pr, nil
}

// EnabledMethods lists the repository's enabled merge methods, in a stable
// order, for messages that must name both sides of a mismatch (#616).
func EnabledMethods(repo Repository) []string {
	var methods []string
	for _, m := range []struct {
		name string
		on   bool
	}{{"merge", repo.Merge}, {"rebase", repo.Rebase}, {"squash", repo.Squash}} {
		if m.on {
			methods = append(methods, m.name)
		}
	}
	return methods
}

// RulesAvailable reports whether the base branch's rulesets can be read.
// Delivery proves required checks through them; when the endpoint is
// plan-gated (#616) enable must refuse with the surfaced reason instead of
// accepting a policy whose `mergeable_state=clean` would prove nothing.
func RulesAvailable(ctx context.Context, api API, p policy.DeliveryPolicy) error {
	_, err := requiredChecks(ctx, api, p)
	return err
}

func Inspect(ctx context.Context, api API, p policy.DeliveryPolicy, n int, expected string) (Proof, error) {
	var proof Proof
	repo, pr, err := ReadPR(ctx, api, p, n)
	if err != nil {
		return proof, err
	}
	if !ValidOID(expected) || pr.Head.SHA != expected {
		return proof, fmt.Errorf("PR head changed")
	}
	if pr.Merged || pr.State != "open" || pr.Draft || pr.Mergeable == nil || !*pr.Mergeable || pr.MergeableState != "clean" {
		return proof, fmt.Errorf("PR is not green and mergeable")
	}
	methods := EnabledMethods(repo)
	if len(methods) != 1 || methods[0] != p.Method {
		remedy := fmt.Sprintf("restrict the repository to %q only", p.Method)
		if len(methods) == 1 {
			remedy = fmt.Sprintf("re-authorize delivery with --method %s", methods[0])
		}
		return proof, fmt.Errorf("repository merge method mismatch: the repository allows [%s]; delivery authorizes exactly %q; %s; nothing was changed, the PR is untouched", strings.Join(methods, ", "), p.Method, remedy)
	}
	checks, err := requiredChecks(ctx, api, p)
	if err != nil {
		return proof, err
	}
	if err := safeFiles(ctx, api, p, n, pr.ChangedFiles); err != nil {
		return proof, err
	}
	if err := greenChecks(ctx, api, p, expected, checks); err != nil {
		return proof, err
	}
	_, current, err := ReadPR(ctx, api, p, n)
	if err != nil {
		return proof, err
	}
	if current.Head.SHA != expected || current.Base.SHA != pr.Base.SHA {
		return proof, fmt.Errorf("PR head or base changed during verification")
	}
	return Proof{Head: expected, Base: pr.Base.SHA, PR: pr}, nil
}

type requiredCheck struct {
	Context string `json:"context"`
	App     int64  `json:"integration_id"`
}

func requiredChecks(ctx context.Context, api API, p policy.DeliveryPolicy) ([]requiredCheck, error) {
	var rules []struct {
		Type       string `json:"type"`
		ID         int64  `json:"ruleset_id"`
		Parameters struct {
			Strict  bool            `json:"strict_required_status_checks_policy"`
			Checks  []requiredCheck `json:"required_status_checks"`
			Methods []string        `json:"allowed_merge_methods"`
		} `json:"parameters"`
	}
	if err := read(ctx, api, "repos/"+p.GitHub+"/rules/branches/"+url.PathEscape(p.Base), &rules); err != nil {
		return nil, err
	}
	var checks []requiredCheck
	ids := map[int64]bool{}
	for _, r := range rules {
		if r.ID <= 0 {
			return nil, fmt.Errorf("unknown ruleset identity")
		}
		ids[r.ID] = true
		if r.Type == "merge_queue" {
			return nil, fmt.Errorf("merge queue requires a separate authorization design")
		}
		if r.Type == "pull_request" && len(r.Parameters.Methods) > 0 {
			allowed := false
			for _, m := range r.Parameters.Methods {
				allowed = allowed || m == p.Method
			}
			if !allowed {
				return nil, fmt.Errorf("branch merge method mismatch: the branch's ruleset allows %s; delivery authorizes %q; nothing was changed", strings.Join(r.Parameters.Methods, ", "), p.Method)
			}
		}
		if r.Type != "required_status_checks" {
			continue
		}
		if !r.Parameters.Strict {
			return nil, fmt.Errorf("required checks are not strict")
		}
		for _, c := range r.Parameters.Checks {
			if c.Context == "" || c.App <= 0 {
				return nil, fmt.Errorf("required checks lack trusted integration identity")
			}
			checks = append(checks, c)
		}
	}
	if len(checks) == 0 {
		return nil, fmt.Errorf("no active required checks")
	}
	if len(ids) > 32 {
		return nil, fmt.Errorf("ruleset verification budget exceeded")
	}
	for id := range ids {
		var detail struct {
			ID          int64              `json:"id"`
			Enforcement string             `json:"enforcement"`
			Target      string             `json:"target"`
			Bypass      string             `json:"current_user_can_bypass"`
			Actors      *[]json.RawMessage `json:"bypass_actors"`
		}
		if err := read(ctx, api, fmt.Sprintf("repos/%s/rulesets/%d?includes_parents=true", p.GitHub, id), &detail); err != nil {
			return nil, err
		}
		if detail.Bypass != "never" || detail.Actors == nil || len(*detail.Actors) != 0 {
			return nil, fmt.Errorf("ruleset bypass is possible or unproven")
		}
		if detail.ID != id || detail.Enforcement != "active" || detail.Target != "branch" {
			return nil, fmt.Errorf("active ruleset identity changed")
		}
	}
	return checks, nil
}

func protected(p policy.DeliveryPolicy, path string) bool {
	path = strings.ToLower(path)
	for _, g := range append([]string{".github", ".github/workflows", ".github/workflows/**", ".github/actions", ".github/actions/**", "**/codeowners", "codeowners", "guardrail.toml"}, p.ProtectedPaths...) {
		// Replacing an ancestor directory can redirect every protected child.
		literal := strings.ToLower(g)
		if wildcard := strings.IndexAny(literal, "*?[{"); wildcard >= 0 {
			literal = literal[:wildcard]
		}
		literal = strings.TrimSuffix(literal, "/")
		if path == literal || strings.HasPrefix(literal, path+"/") {
			return true
		}
		matched, err := doublestar.Match(strings.ToLower(g), path)
		if err != nil || matched {
			return true
		}
	}
	return false
}

func safeFiles(ctx context.Context, api API, p policy.DeliveryPolicy, n, count int) error {
	if count < 1 || count >= 3000 {
		return fmt.Errorf("PR file list exceeds verification budget or is empty")
	}
	seen := map[string]bool{}
	for page := 1; page <= 30; page++ {
		var files []struct {
			Name     string `json:"filename"`
			Previous string `json:"previous_filename"`
			Status   string `json:"status"`
		}
		if err := read(ctx, api, fmt.Sprintf("repos/%s/pulls/%d/files?per_page=100&page=%d", p.GitHub, n, page), &files); err != nil {
			return err
		}
		for _, f := range files {
			if f.Name == "" || seen[f.Name] {
				return fmt.Errorf("incomplete PR file list")
			}
			seen[f.Name] = true
			if f.Status == "renamed" && f.Previous == "" {
				return fmt.Errorf("incomplete PR file list: renamed path lacks source")
			}

			if protected(p, f.Name) || f.Previous != "" && protected(p, f.Previous) {
				return fmt.Errorf("PR touches protected check/control path %s", f.Name)
			}
			switch f.Status {
			case "added", "modified", "removed", "renamed", "copied", "changed", "unchanged":
			default:
				return fmt.Errorf("unknown PR file list status")
			}
			if strings.HasPrefix(f.Name, "/") || strings.Contains(f.Name, "\\") {
				return fmt.Errorf("unsupported PR file list path")
			}
		}
		if len(files) < 100 {
			if len(seen) != count {
				return fmt.Errorf("incomplete PR file list")
			}
			return nil
		}
	}
	return fmt.Errorf("PR file list verification budget exceeded")
}

func greenChecks(ctx context.Context, api API, p policy.DeliveryPolicy, head string, checks []requiredCheck) error {
	type key struct {
		Name string
		App  int64
	}
	found := map[key]bool{}
	total := -1
	observed := 0
	for page := 1; page <= 30; page++ {
		var result struct {
			Total int `json:"total_count"`
			Runs  []struct {
				Name       string `json:"name"`
				Status     string `json:"status"`
				Conclusion string `json:"conclusion"`
				App        struct {
					ID int64 `json:"id"`
				} `json:"app"`
			} `json:"check_runs"`
		}
		if err := read(ctx, api, fmt.Sprintf("repos/%s/commits/%s/check-runs?per_page=100&page=%d", p.GitHub, head, page), &result); err != nil {
			return err
		}
		if total < 0 {
			total = result.Total
		}
		if total < 1 || total >= 3000 || total != result.Total {
			return fmt.Errorf("check inventory is missing or changed")
		}
		for _, r := range result.Runs {
			observed++
			k := key{r.Name, r.App.ID}
			for _, c := range checks {
				if c.Context == r.Name && c.App == r.App.ID {
					if r.Status != "completed" || r.Conclusion != "success" {
						return fmt.Errorf("required check is not green: %s", r.Name)
					}
					found[k] = true
				}
			}
		}
		if len(result.Runs) < 100 {
			break
		}
	}
	if observed != total {
		return fmt.Errorf("incomplete check inventory")
	}
	for _, c := range checks {
		if !found[key{c.Context, c.App}] {
			return fmt.Errorf("required check is not green or is missing: %s", c.Context)
		}
	}
	return nil
}
