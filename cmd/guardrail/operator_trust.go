package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/CtrlCarlitos/agent-guardrails/internal/approval"
	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
	"github.com/CtrlCarlitos/agent-guardrails/internal/safetext"
	"github.com/gofrs/flock"
)

var (
	submitOperatorTrustRequest = approval.SubmitOnDemand
	queryOperatorTrustStatus   = approval.QueryStatus
)

func init() {
	approval.RegisterAction("operator-trust-set", executeOperatorTrustApproval)
}

func cmdOperatorTrust(args []string, terminal bool, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) > 1 {
		fmt.Fprintln(stderr, "usage: guardrail operator trust [repo-path]")
		return 2
	}
	target := "."
	if len(args) == 1 && args[0] != "" {
		target = args[0]
	}
	repoRoot, err := resolveTrustRepoRoot(target, true)
	if err != nil {
		fmt.Fprintf(stderr, "guardrail: %s\n", safetext.SingleLine(err.Error()))
		return 1
	}
	overlayPath := filepath.Join(repoRoot, "guardrail.toml")
	if _, err := os.Stat(overlayPath); err != nil {
		if os.IsNotExist(err) {
			fmt.Fprintf(stderr, "guardrail: no guardrail.toml found in %s\n", safetext.SingleLine(repoRoot))
			return 1
		}
		fmt.Fprintf(stderr, "guardrail: cannot inspect %s: %s\n", safetext.SingleLine(overlayPath), safetext.SingleLine(err.Error()))
		return 1
	}
	ov, err := policy.LoadOverlay(overlayPath)
	if err != nil {
		fmt.Fprintf(stderr, "guardrail: %s\n", safetext.SingleLine(err.Error()))
		return 1
	}
	op, err := policy.LoadOperatorConfig()
	if err != nil {
		fmt.Fprintf(stderr, "guardrail: operator config unreadable (%s); cannot update trust\n", safetext.SingleLine(err.Error()))
		return 1
	}

	desired := policy.TrustSnapshotFromOverlay(ov)
	existing, hasExisting := op.TrustFor(repoRoot)
	diff := policy.DiffTrust(ov, op, repoRoot)

	printTrustReview(repoRoot, overlayPath, diff, stdout)

	if desired.IsEmpty() && !hasExisting {
		fmt.Fprintf(stdout, "guardrail: overlay in %s has no operator-gated loosening requests to trust\n", safetext.SingleLine(repoRoot))
		return 0
	}
	if hasExisting && !desired.IsEmpty() && existing.Equal(desired) {
		fmt.Fprintf(stdout, "guardrail: trust snapshot for %s is already up to date\n", safetext.SingleLine(repoRoot))
		return 0
	}

	var toStore *policy.TrustSnapshot
	reason := "trust repository Overlay loosening snapshot"
	if !desired.IsEmpty() {
		toStore = desired
	} else {
		reason = "clear repository Overlay trust snapshot (no loosening requests remain)"
	}

	encoded, err := policy.EncodeTrustSnapshot(toStore)
	if err != nil {
		fmt.Fprintf(stderr, "guardrail: cannot encode trust snapshot: %s\n", safetext.SingleLine(err.Error()))
		return 1
	}
	req := approval.Request{
		Plane:      "operator",
		SessionID:  "terminal",
		RepoRoot:   repoRoot,
		Scope:      approval.RepoScope,
		Reason:     reason,
		Action:     "operator-trust-set",
		Parameters: map[string]string{"snapshot": encoded},
		ExpiresAt:  time.Now().Add(5 * time.Minute),
	}
	return applyOperatorTrustDecision(req, repoRoot, toStore, terminal, stdin, stdout, stderr, "guardrail operator trust "+repoRoot)
}

func cmdOperatorUntrust(args []string, terminal bool, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) > 1 {
		fmt.Fprintln(stderr, "usage: guardrail operator untrust [repo-path]")
		return 2
	}
	target := "."
	if len(args) == 1 && args[0] != "" {
		target = args[0]
	}
	repoRoot, err := resolveTrustRepoRoot(target, false)
	if err != nil {
		fmt.Fprintf(stderr, "guardrail: %s\n", safetext.SingleLine(err.Error()))
		return 1
	}
	op, err := policy.LoadOperatorConfig()
	if err != nil {
		fmt.Fprintf(stderr, "guardrail: operator config unreadable (%s); cannot revoke trust\n", safetext.SingleLine(err.Error()))
		return 1
	}
	existing, hasExisting := op.TrustFor(repoRoot)
	if !hasExisting {
		fmt.Fprintf(stdout, "guardrail: no trust snapshot exists for %s\n", safetext.SingleLine(repoRoot))
		return 0
	}

	fmt.Fprintf(stdout, "Repository: %s\n", safetext.SingleLine(repoRoot))
	fmt.Fprintf(stdout, "Revoking trust snapshot: %s\n", safetext.SingleLine(existing.Summary()))

	req := approval.Request{
		Plane:      "operator",
		SessionID:  "terminal",
		RepoRoot:   repoRoot,
		Scope:      approval.RepoScope,
		Reason:     "revoke repository Overlay trust snapshot",
		Action:     "operator-trust-set",
		Parameters: map[string]string{"snapshot": "null"},
		ExpiresAt:  time.Now().Add(5 * time.Minute),
	}
	return applyOperatorTrustDecision(req, repoRoot, nil, terminal, stdin, stdout, stderr, "guardrail operator untrust "+repoRoot)
}

func applyOperatorTrustDecision(req approval.Request, repoRoot string, expected *policy.TrustSnapshot, terminal bool, stdin io.Reader, stdout, stderr io.Writer, commandLabel string) int {
	if promptApprovalMode() {
		prevInput := operatorInput
		operatorInput = stdin
		defer func() { operatorInput = prevInput }()

		transport, outcome := promptApproval(req.Summary(), terminal, stdout)
		switch outcome {
		case approvalUnreachable:
			fmt.Fprintln(stderr, "guardrail: operator commands require an interactive local terminal")
			return 2
		case approvalDeclined:
			fmt.Fprintln(stderr, "guardrail: repository trust unchanged")
			return 1
		}
		if _, err := approval.ApplyLocal(req, transport); err != nil {
			fmt.Fprintf(stderr, "guardrail: trust update failed: %s\n", safetext.SingleLine(err.Error()))
			return 1
		}
		if !trustSnapshotConverged(repoRoot, expected) {
			fmt.Fprintln(stderr, "guardrail: approved trust snapshot did not converge")
			return 1
		}
		printTrustUpdatedMessage(repoRoot, expected, stdout)
		return 0
	}

	if !requireOperatorEnrolled(commandLabel, stderr) {
		return exitNotEnrolled
	}
	r, err := submitOperatorTrustRequest(req)
	if err != nil {
		fmt.Fprintf(stderr, "guardrail: trust approval failed: %s\n", safetext.SingleLine(err.Error()))
		return 1
	}
	fmt.Fprintf(stdout, "repository trust update: approval required; open %s\n", r.ApprovalURL)
	deadline := time.Now().Add(5 * time.Minute)
	if !r.ExpiresAt.IsZero() && r.ExpiresAt.Before(deadline) {
		deadline = r.ExpiresAt
	}
	for time.Now().Before(deadline) {
		status, err := queryOperatorTrustStatus(approval.DefaultSocketPath(), r.ID)
		if err != nil {
			fmt.Fprintln(stderr, "guardrail: trust approval daemon unavailable")
			return 1
		}
		switch status.Status {
		case "completed":
			if !trustSnapshotConverged(repoRoot, expected) {
				fmt.Fprintln(stderr, "guardrail: approved trust snapshot did not converge")
				return 1
			}
			printTrustUpdatedMessage(repoRoot, expected, stdout)
			return 0
		case "denied", "expired", "failed":
			fmt.Fprintf(stderr, "guardrail: trust approval %s\n", status.Status)
			return 1
		}
		time.Sleep(500 * time.Millisecond)
	}
	fmt.Fprintln(stderr, "guardrail: trust approval timed out; inspect pending requests before retrying")
	return 1
}

func trustSnapshotConverged(repoRoot string, expected *policy.TrustSnapshot) bool {
	op, err := policy.LoadOperatorConfig()
	if err != nil {
		return false
	}
	got, ok := op.TrustFor(repoRoot)
	if expected == nil {
		return !ok
	}
	return ok && got.Equal(expected)
}

func printTrustUpdatedMessage(repoRoot string, expected *policy.TrustSnapshot, stdout io.Writer) {
	if expected == nil {
		fmt.Fprintf(stdout, "guardrail: trust snapshot revoked for %s\n", safetext.SingleLine(repoRoot))
		return
	}
	fmt.Fprintf(stdout, "guardrail: trusted Overlay snapshot for %s (%s)\n", safetext.SingleLine(repoRoot), safetext.SingleLine(expected.Summary()))
}

func resolveTrustRepoRoot(target string, requireExists bool) (string, error) {
	abs, err := filepath.Abs(target)
	if err != nil {
		return "", fmt.Errorf("resolve repository path %q: %w", target, err)
	}
	abs = filepath.Clean(abs)
	info, statErr := os.Stat(abs)
	if statErr != nil {
		if requireExists {
			return "", fmt.Errorf("repository path %s is unavailable: %w", abs, statErr)
		}
		return abs, nil
	}
	if !info.IsDir() {
		return "", fmt.Errorf("repository path %s is not a directory", abs)
	}
	if root, ok := policy.FindRepoRoot(abs); ok {
		return filepath.Clean(root), nil
	}
	return abs, nil
}

func printTrustReview(repoRoot, overlayPath string, diff policy.TrustDiff, stdout io.Writer) {
	fmt.Fprintf(stdout, "Repository: %s\n", safetext.SingleLine(repoRoot))
	fmt.Fprintf(stdout, "Overlay: %s\n", safetext.SingleLine(overlayPath))
	if len(diff.Authorized) > 0 {
		fmt.Fprintln(stdout, "  already authorized:")
		for _, item := range diff.Authorized {
			fmt.Fprintf(stdout, "    - %s: %s\n", item.Kind, safetext.SingleLine(item.Value))
		}
	}
	if len(diff.Pending) > 0 {
		fmt.Fprintln(stdout, "  new (will be authorized):")
		for _, item := range diff.Pending {
			fmt.Fprintf(stdout, "    + %s: %s\n", item.Kind, safetext.SingleLine(item.Value))
		}
	}
	if len(diff.Removed) > 0 {
		fmt.Fprintln(stdout, "  removed from overlay (will be dropped from snapshot):")
		for _, item := range diff.Removed {
			fmt.Fprintf(stdout, "    - %s: %s\n", item.Kind, safetext.SingleLine(item.Value))
		}
	}
	if len(diff.Rejected) > 0 {
		fmt.Fprintln(stdout, "  never authorizable (will remain dropped):")
		for _, item := range diff.Rejected {
			fmt.Fprintf(stdout, "    ! %s: %s\n", item.Kind, safetext.SingleLine(item.Value))
		}
	}
}

// printDoctorTrustDiff prints the Overlay-vs-trust-snapshot summary in
// `guardrail doctor` whenever a repo has a trust snapshot or untrusted Overlay
// loosening requests (#131).
func printDoctorTrustDiff(repoRoot string, diff policy.TrustDiff, stdout io.Writer) {
	if !diff.HasSnapshot && len(diff.Pending) == 0 && len(diff.Removed) == 0 {
		return
	}
	status := "trusted"
	switch {
	case !diff.HasSnapshot && len(diff.Pending) > 0:
		status = fmt.Sprintf("untrusted (%d pending)", len(diff.Pending))
	case len(diff.Pending) > 0 || len(diff.Removed) > 0:
		var parts []string
		if len(diff.Pending) > 0 {
			parts = append(parts, fmt.Sprintf("%d new", len(diff.Pending)))
		}
		if len(diff.Removed) > 0 {
			parts = append(parts, fmt.Sprintf("%d removed", len(diff.Removed)))
		}
		status = "drift (" + strings.Join(parts, ", ") + ")"
	}
	fmt.Fprintf(stdout, "overlay trust: %s\n", status)
	for _, item := range diff.Authorized {
		fmt.Fprintf(stdout, "  authorized: %s %s\n", item.Kind, safetext.SingleLine(item.Value))
	}
	for _, item := range diff.Pending {
		fmt.Fprintf(stdout, "  new (not trusted): %s %s\n", item.Kind, safetext.SingleLine(item.Value))
	}
	for _, item := range diff.Removed {
		fmt.Fprintf(stdout, "  removed from overlay (still in snapshot): %s %s\n", item.Kind, safetext.SingleLine(item.Value))
	}
	if len(diff.Pending) > 0 || len(diff.Removed) > 0 {
		target := filepath.Clean(repoRoot)
		if target == "" {
			target = "."
		}
		fmt.Fprintf(stdout, "  run: guardrail operator trust %s\n", safetext.SingleLine(target))
	}
}

func executeOperatorTrustApproval(r approval.Request) error {
	if r.Action != "operator-trust-set" || r.Plane != "operator" || r.Scope != approval.RepoScope || !filepath.IsAbs(r.RepoRoot) || len(r.Parameters) != 1 {
		return fmt.Errorf("invalid operator trust approval")
	}
	snap, err := policy.DecodeTrustSnapshot(r.Parameters["snapshot"])
	if err != nil {
		return err
	}
	done, err := startActionAudit(r)
	if err != nil || done {
		return err
	}
	if err := setRepoTrustSnapshot(r.RepoRoot, snap); err != nil {
		return err
	}
	_ = completeActionAudit(r)
	return nil
}

func setRepoTrustSnapshot(repoRoot string, snap *policy.TrustSnapshot) error {
	if snap != nil {
		if err := snap.Validate(); err != nil {
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
	key := op.GrantKey(repoRoot)
	entry := op.Repos[key]
	entry.Trust = snap
	if repoGrantEmpty(entry) {
		delete(op.Repos, key)
	} else {
		op.Repos[key] = entry
	}
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

func repoGrantEmpty(g policy.RepoGrant) bool {
	return g.Delivery == nil &&
		g.Trust == nil &&
		len(g.Waive) == 0 &&
		!g.SecretAllow &&
		!g.AuditLog &&
		len(g.EgressAllowlist) == 0 &&
		len(g.WebHosts) == 0 &&
		len(g.Commands) == 0
}
