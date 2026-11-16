package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"time"

	"github.com/CtrlCarlitos/agent-guardrails/internal/approval"
	"github.com/CtrlCarlitos/agent-guardrails/internal/audit"
	"github.com/CtrlCarlitos/agent-guardrails/internal/delivery"
	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
	"github.com/gofrs/flock"
)

var deliveryAPI delivery.API = delivery.CLIAPI

func cmdDelivery(args []string, terminal bool, input io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "guardrail: delivery status|enable|revoke|finish")
		return 2
	}
	if (args[0] == "enable" || args[0] == "revoke") && !terminal {
		fmt.Fprintln(stderr, "guardrail: delivery authorization requires the operator's interactive terminal")
		return 2
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cwd, err := os.Getwd()
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	root, err := delivery.CommonRoot(ctx, cwd)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	op, err := policy.LoadOperatorConfig()
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	p, enabled := op.DeliveryFor(root)
	switch args[0] {
	case "status":
		if len(args) != 1 {
			return 2
		}
		if !enabled {
			fmt.Fprintf(stdout, "delivery disabled for %s\n", root)
			return 0
		}
		fmt.Fprintf(stdout, "delivery enabled for %s: %s base=%s method=%s; until revoked\n", root, p.GitHub, p.Base, p.Method)
		return 0
	case "enable", "revoke":
		return cmdDeliveryAuthorize(args, root, input, stdout, stderr)
	case "finish":
		if !enabled {
			fmt.Fprintln(stderr, "guardrail: delivery not enabled for this repository; operator must enable it once from their terminal")
			return 2
		}
		fs := flag.NewFlagSet("delivery finish", flag.ContinueOnError)
		fs.SetOutput(stderr)
		n := fs.Int("pr", 0, "task PR number")
		head := fs.String("head", "", "full exact tested head SHA")
		worktree := fs.String("worktree", "", "absolute task worktree to clean after confirmed merge")
		if err := fs.Parse(args[1:]); err != nil || fs.NArg() != 0 || *n < 1 || !delivery.ValidOID(*head) {
			fmt.Fprintln(stderr, "guardrail: finish requires --pr N --head SHA [--worktree ABSOLUTE_PATH]")
			return 2
		}
		before := func() error { return deliveryMutationAllowed(root, p, "merge", *n, *head) }
		_, pr, err := delivery.ReadPR(ctx, deliveryAPI, p, *n)
		if err == nil && !pr.Merged {
			pr, err = delivery.Merge(ctx, deliveryAPI, p, *n, *head, before)
		}
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		if !pr.Merged || pr.Head.SHA != *head {
			fmt.Fprintln(stderr, "guardrail: confirmed merge does not match task head")
			return 1
		}
		fmt.Fprintf(stdout, "PR #%d merged as %s\n", *n, pr.MergeCommit)
		if err := writeDeliveryAudit(root, "merge-confirmed", *n, *head); err != nil {
			fmt.Fprintln(stderr, "merge confirmed; audit unavailable; preserve cleanup resources:", err)
			return 1
		}
		if err := delivery.Cleanup(ctx, deliveryAPI, p, pr, root, *worktree, func() error { return deliveryMutationAllowed(root, p, "cleanup", *n, *head) }); err != nil {
			fmt.Fprintln(stderr, "merged / cleanup blocked:", err)
			return 1
		}
		if err := writeDeliveryAudit(root, "cleanup-confirmed", *n, *head); err != nil {
			fmt.Fprintln(stderr, "cleanup finished but completion audit failed:", err)
			return 1
		}
		fmt.Fprintln(stdout, "delivery complete: confirmed merge and task cleanup")
		return 0
	default:
		fmt.Fprintln(stderr, "guardrail: unknown delivery operation")
		return 2
	}
}

func deliveryMutationAllowed(root string, p policy.DeliveryPolicy, action string, n int, head string) error {
	op, err := policy.LoadOperatorConfig()
	if err != nil {
		return err
	}
	current, ok := op.DeliveryFor(root)
	if !ok || !reflect.DeepEqual(current, p) {
		return fmt.Errorf("delivery authorization was revoked or changed")
	}
	return writeDeliveryAudit(root, action+"-authorized", n, head)
}

func writeDeliveryAudit(root, action string, n int, head string) error {
	return audit.Write(audit.Record{TS: time.Now().UTC().Format(time.RFC3339Nano), Plane: "guardrail", Tool: "delivery", Event: "delivery", RepoRoot: root, Decision: "allow", RuleID: "repository-delivery-authorized", OperatorAction: action, Reason: fmt.Sprintf("standing repository delivery: PR %d head %s", n, head)}, audit.DefaultPath(""))
}

func cmdDeliveryAuthorize(args []string, root string, input io.Reader, stdout, stderr io.Writer) int {
	var chosen *policy.DeliveryPolicy
	if args[0] == "enable" {
		fs := flag.NewFlagSet("delivery enable", flag.ContinueOnError)
		fs.SetOutput(stderr)
		github := fs.String("github", "", "exact OWNER/REPO")
		base := fs.String("base", "main", "protected default branch")
		method := fs.String("method", "squash", "single authorized merge method")
		var paths deliveryPaths
		fs.Var(&paths, "protect", "additional protected CI path glob (repeatable)")
		if err := fs.Parse(args[1:]); err != nil || fs.NArg() != 0 {
			return 2
		}
		chosen = &policy.DeliveryPolicy{GitHubID: 1, GitHub: *github, Base: *base, Method: *method, ProtectedPaths: paths}
		if err := chosen.Validate(); err != nil {
			fmt.Fprintln(stderr, err)
			return 2
		}
		var identity delivery.Repository
		if err := deliveryAPI(context.Background(), "repos/"+chosen.GitHub, nil, &identity); err != nil {
			fmt.Fprintln(stderr, "cannot bind repository identity:", err)
			return 1
		}
		if identity.ID <= 0 || identity.FullName != chosen.GitHub || identity.DefaultBranch != chosen.Base {
			fmt.Fprintln(stderr, "repository identity/default branch mismatch")
			return 1
		}
		chosen.GitHubID = identity.ID
		if err := chosen.Validate(); err != nil {
			fmt.Fprintln(stderr, err)
			return 2
		}
	} else if len(args) != 1 {
		return 2
	}
	raw, _ := json.Marshal(chosen)
	fmt.Fprintf(stdout, "Repository: %s\nDelivery policy (until revoked): %s\nEligible exact-head merges and clean task resources only; existing account trust; no admin bypass.\n", root, raw)
	if promptApprovalMode() {
		fmt.Fprint(stdout, "Type yes to apply this repository delivery authorization: ")
		if !confirmGrant(input, stdout) {
			fmt.Fprintln(stderr, "guardrail: delivery authorization unchanged")
			return 1
		}
		if err := writeDeliveryAudit(root, "authorization-changed", 0, ""); err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		if err := setDeliveryPolicy(root, chosen); err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		fmt.Fprintln(stdout, "delivery authorization updated")
		return 0
	}
	if !operatorEnrolled() {
		fmt.Fprintln(stderr, "guardrail: enroll an operator authenticator before authorizing delivery")
		return 3
	}
	r, err := approval.SubmitOnDemand(approval.Request{Plane: "operator", SessionID: "terminal", RepoRoot: root, Scope: approval.RepoScope, Reason: "change standing repository delivery authorization", Action: "delivery-set", Parameters: map[string]string{"policy": string(raw)}, ExpiresAt: time.Now().Add(5 * time.Minute)})
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	fmt.Fprintln(stdout, r.ApprovalURL)
	return cmdApprovalsWait(r.ID, stdout, stderr)
}

type deliveryPaths []string

func (p *deliveryPaths) String() string     { return fmt.Sprint([]string(*p)) }
func (p *deliveryPaths) Set(v string) error { *p = append(*p, v); return nil }

func init() {
	approval.RegisterAction("delivery-set", func(r approval.Request) error {
		if r.Action != "delivery-set" || r.Plane != "operator" || r.Scope != approval.RepoScope || len(r.Parameters) != 1 {
			return fmt.Errorf("invalid delivery approval")
		}
		p, err := policy.DecodeDeliveryPolicy(r.Parameters["policy"])
		if err != nil {
			return err
		}
		done, err := startActionAudit(r)
		if err != nil || done {
			return err
		}
		if err := setDeliveryPolicy(r.RepoRoot, p); err != nil {
			return err
		}
		_ = completeActionAudit(r)
		return nil
	})
}

func setDeliveryPolicy(root string, p *policy.DeliveryPolicy) error {
	if p != nil {
		if err := p.Validate(); err != nil {
			return err
		}
	}
	dir, err := allowanceJournalDir()
	if err != nil {
		return err
	}
	if err := ensureAllowanceDir(dir); err != nil {
		return err
	}
	lock := flock.New(filepath.Join(dir, "operator.lock"), flock.SetPermissions(0o600))
	if err := lock.Lock(); err != nil {
		return err
	}
	defer lock.Unlock()
	if err := recoverAllowanceJournals(dir); err != nil {
		return err
	}
	op, err := policy.LoadOperatorConfig()
	if err != nil {
		return err
	}
	key := op.GrantKey(root)
	entry := op.Repos[key]
	entry.Delivery = p
	op.Repos[key] = entry
	raw, err := operatorConfigContent(op)
	if err != nil {
		return err
	}
	path := policy.OperatorConfigPath()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	if err := securePrivateDir(filepath.Dir(path)); err != nil {
		return err
	}
	return writeSyncedPrivateFile(path, raw, 0o600)
}
