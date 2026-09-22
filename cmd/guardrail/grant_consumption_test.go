package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/CtrlCarlitos/agent-guardrails/internal/audit"
	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
	"github.com/CtrlCarlitos/agent-guardrails/internal/testenv"
)

// grantedRepo builds a real repository, isolates the operator config and audit
// roots, and issues a grant through the ceremony -- the same path an operator
// takes -- so the consumption tests exercise what was actually recorded rather
// than a hand-built config.
func grantedRepo(t *testing.T, ruleID, command string, uses int) (repo, auditPath string) {
	t.Helper()
	repo = t.TempDir()
	gitInitSync(t, repo)
	testenv.SetConfig(t, t.TempDir())
	state := t.TempDir()
	testenv.SetState(t, state)
	t.Setenv("GUARDRAIL_CONFIG", "")

	args := []string{"grant", "--repo", repo, "--rule", ruleID, "--command", command}
	if uses > 0 {
		args = append(args, "--uses", fmt.Sprint(uses))
	}
	var out, errb bytes.Buffer
	if code := cmdApprovalsInput(args, true, strings.NewReader("yes\n"), &out, &errb); code != 0 {
		t.Fatalf("issuing the grant -> %d, stderr=%q", code, errb.String())
	}
	return repo, audit.DefaultPath("")
}

// hookCall drives one real pre-tool-use call and reports the verdict guardrail
// recorded for it.
//
// The exit code is deliberately not the probe: on the Claude plane an Ask is a
// successful hook invocation carrying a permission decision, so a test that
// asserted on the exit status would read every ask as an allow and pass while
// the gate was wide open. The audit record is what the rest of the system
// believes happened, so it is what these tests assert on.
func hookCall(t *testing.T, repo, command string) audit.Record {
	t.Helper()
	payload := map[string]any{
		"session_id":      "grant-session",
		"cwd":             repo,
		"hook_event_name": "PreToolUse",
		"tool_name":       "Bash",
		"tool_input":      map[string]any{"command": command},
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	if code := run([]string{"hook", "claude"}, bytes.NewReader(raw), &out, &errb); code > 2 {
		t.Fatalf("hook failed: code=%d out=%s err=%s", code, out.String(), errb.String())
	}
	records := auditRecordsFor(t, audit.DefaultPath(""))
	for i := len(records) - 1; i >= 0; i-- {
		// Skip the issuance record, which names the same command text.
		if records[i].Command == command && records[i].OperatorAction == "" {
			return records[i]
		}
	}
	t.Fatalf("no audit record for %q", command)
	return audit.Record{}
}

func remainingUses(t *testing.T, repo, command string) int {
	t.Helper()
	op, err := policy.LoadOperatorConfig()
	if err != nil {
		t.Fatal(err)
	}
	for _, g := range op.Repos[filepath.Clean(repo)].Commands {
		if g.Command == command {
			return g.RemainingUses()
		}
	}
	t.Fatalf("no grant recorded for %q", command)
	return -1
}

func auditRecordsFor(t *testing.T, path string) []audit.Record {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading audit log %s: %v", path, err)
	}
	var records []audit.Record
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		if line == "" {
			continue
		}
		var rec audit.Record
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("parsing audit line %q: %v", line, err)
		}
		records = append(records, rec)
	}
	return records
}

// The property the whole design rests on: one use means one. A window alone
// would authorize an unbounded number of executions of the granted command,
// which is a materially different authorization from the one the operator was
// shown.
func TestASingleUseGrantAuthorizesExactlyOneCall(t *testing.T) {
	const command = "git push origin main"
	repo, _ := grantedRepo(t, "P2.git-push-protected", command, 0)
	if got := remainingUses(t, repo, command); got != 1 {
		t.Fatalf("issued with %d uses, want 1", got)
	}

	first := hookCall(t, repo, command)
	if first.Decision != "allow" || first.RuleID != "ask-allowed-by-operator-grant" {
		t.Fatalf("the granted call -> %s/%s, want an allow attributed to the grant", first.Decision, first.RuleID)
	}
	if got := remainingUses(t, repo, command); got != 0 {
		t.Fatalf("after one call %d uses remain, want 0", got)
	}
	// The second call must be refused: the grant is spent, not merely
	// unexpired.
	second := hookCall(t, repo, command)
	if second.Decision == "allow" {
		t.Errorf("a spent single-use grant authorized a second call -> %s/%s", second.Decision, second.RuleID)
	}
	if second.RuleID != first.OriginRuleID {
		t.Errorf("after the grant was spent the rule is %q, want the original ask %q back", second.RuleID, first.OriginRuleID)
	}
}

// The case a pattern language would have got wrong.
//
// "git push origin HEAD:main" raises the same ask, under the same rule, in the
// same repository, and pushes to the same branch as the granted command. Only
// the text differs. A grant that covered it would be authorizing something the
// operator did not read, which is the whole reason there are no wildcards
// here -- and it must not quietly spend the grant issued for the other one
// either, or a near-miss becomes a way to disarm an authorization.
func TestAnEquivalentButDifferentCommandNeitherMatchesNorSpendsTheGrant(t *testing.T) {
	const granted = "git push origin main"
	repo, _ := grantedRepo(t, "P2.git-push-protected", granted, 0)
	got := hookCall(t, repo, "git push origin HEAD:main")
	if got.Decision == "allow" {
		t.Errorf("an ungranted command -> %s/%s, want the ask preserved", got.Decision, got.RuleID)
	}
	if got.RuleID != "P2.git-push-protected" {
		t.Errorf("the near-miss raised %q; the fixture no longer exercises the same rule", got.RuleID)
	}
	if got := remainingUses(t, repo, granted); got != 1 {
		t.Errorf("a near-miss left %d uses, want the grant untouched at 1", got)
	}
}

// Both ends are recorded. The audit has to answer "what did this grant
// actually authorize", not only "a grant existed" -- otherwise a grant becomes
// a way to make an action quieter in the record instead of louder.
func TestIssuanceAndConsumptionAreBothAudited(t *testing.T) {
	const command = "git push origin main"
	repo, auditPath := grantedRepo(t, "P2.git-push-protected", command, 0)

	issued := auditRecordsFor(t, auditPath)
	var foundIssue bool
	for _, rec := range issued {
		if rec.OperatorAction == "grant-issued" && rec.Command == command && rec.RuleID == "P2.git-push-protected" {
			foundIssue = true
		}
	}
	if !foundIssue {
		t.Errorf("no grant-issued record naming the command; records=%+v", issued)
	}

	if got := hookCall(t, repo, command); got.Decision != "allow" {
		t.Fatalf("the granted call -> %s/%s, want allow", got.Decision, got.RuleID)
	}
	var foundUse bool
	for _, rec := range auditRecordsFor(t, auditPath) {
		if rec.RuleID == "ask-allowed-by-operator-grant" {
			foundUse = true
			if rec.OriginRuleID != "P2.git-push-protected" {
				t.Errorf("consumption recorded origin %q, want the ask the grant covered", rec.OriginRuleID)
			}
			if rec.Decision != "allow" {
				t.Errorf("consumption recorded decision %q, want allow", rec.Decision)
			}
		}
	}
	if !foundUse {
		t.Error("the consuming allow is not distinguishable from an ordinary allow in the record")
	}
}

// A revoked grant stops working immediately rather than at the end of its
// window; that is the difference between having a move and waiting one out.
func TestRevokingStopsTheGrantBeforeItExpires(t *testing.T) {
	const command = "git push origin main"
	repo, _ := grantedRepo(t, "P2.git-push-protected", command, 3)
	var out, errb bytes.Buffer
	if code := cmdApprovalsInput([]string{"revoke", "--repo", repo,
		"--rule", "P2.git-push-protected", "--command", command}, true,
		strings.NewReader(""), &out, &errb); code != 0 {
		t.Fatalf("revoke -> %d, stderr=%q", code, errb.String())
	}
	if got := hookCall(t, repo, command); got.Decision == "allow" {
		t.Errorf("a revoked grant still authorized the call -> %s/%s", got.Decision, got.RuleID)
	}
}
