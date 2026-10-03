package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/CtrlCarlitos/agent-guardrails/internal/audit"
	"github.com/CtrlCarlitos/agent-guardrails/internal/testenv"
)

func writeExplainLog(t *testing.T, records ...audit.Record) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	for _, rec := range records {
		if err := audit.Write(rec, path); err != nil {
			t.Fatal(err)
		}
	}
	return path
}

func runExplain(t *testing.T, cwd string, args ...string) (int, string, string) {
	t.Helper()
	var out, errb strings.Builder
	code := cmdExplain(args, cwd, &out, &errb)
	return code, out.String(), errb.String()
}

func TestExplainDefaultsToNewestNonAllowRecordForThisRepo(t *testing.T) {
	repo := t.TempDir()
	other := t.TempDir()
	path := writeExplainLog(t,
		audit.Record{TS: "2026-09-26T10:00:00Z", SessionID: "s1", Plane: "claude", Tool: "Bash", NativeTool: "Bash", Event: "pre", Command: "curl https://example.test", Decision: "deny", RuleID: "P6.egress", Reason: "network access to a non-allowlisted host: example.test", RepoRoot: repo},
		audit.Record{TS: "2026-09-26T10:01:00Z", SessionID: "s1", Plane: "claude", Tool: "Bash", NativeTool: "Bash", Event: "pre", Command: "rm -rf build", Decision: "deny", RuleID: "P1.rm-rf", Reason: "recursive force delete", RepoRoot: repo},
		audit.Record{TS: "2026-09-26T10:02:00Z", SessionID: "s1", Plane: "claude", Tool: "Bash", NativeTool: "Bash", Event: "pre", Command: "ls", Decision: "allow", RepoRoot: repo},
		audit.Record{TS: "2026-09-26T10:03:00Z", SessionID: "s2", Plane: "opencode", Tool: "Bash", NativeTool: "bash", Event: "pre", Command: "npm install x", Decision: "ask", RuleID: "P6.package-install", Reason: "new JS dependency", RepoRoot: other},
		audit.Record{TS: "2026-09-26T10:04:00Z", SessionID: "selftest-123", Plane: "claude", Tool: "Bash", NativeTool: "Bash", Event: "pre", Command: "rm -rf /", Decision: "deny", RuleID: "P1.rm-rf", Reason: "selftest probe", RepoRoot: repo},
		audit.Record{TS: "2026-09-26T10:05:00Z", Plane: "operator", Tool: "guardrail", Event: "operator-action", Decision: "completed", OperatorAction: "night-on"},
	)

	code, out, errOut := runExplain(t, repo, "--path", path)
	if code != 0 {
		t.Fatalf("exit = %d, stderr %q", code, errOut)
	}
	for _, want := range []string{
		"2026-09-26T10:01:00Z",
		"rm -rf build",
		"deny",
		"P1.rm-rf",
		"recursive force delete",
		// The next step is the adapter's own continuation for this rule.
		"Destructive operation: do not retry it.",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("explain output missing %q:\n%s", want, out)
		}
	}
	for _, unwanted := range []string{"npm install x", "selftest probe", "curl https://example.test"} {
		if strings.Contains(out, unwanted) {
			t.Errorf("explain output shows %q, which is another repo, a selftest probe, or not the newest:\n%s", unwanted, out)
		}
	}

	// `last` is the spelled-out default.
	if code, lastOut, _ := runExplain(t, repo, "last", "--path", path); code != 0 || lastOut != out {
		t.Errorf("explain last (exit %d) differs from explain:\n%s\nvs\n%s", code, lastOut, out)
	}
}

func TestExplainAllCoversEveryRepositoryAndLastNIsNewestFirst(t *testing.T) {
	repo := t.TempDir()
	other := t.TempDir()
	path := writeExplainLog(t,
		audit.Record{TS: "2026-09-26T10:00:00Z", Plane: "claude", Tool: "Bash", Event: "pre", Command: "git push --force", Decision: "deny", RuleID: "P1.git-push-force", Reason: "force push", RepoRoot: repo},
		audit.Record{TS: "2026-09-26T10:01:00Z", Plane: "opencode", Tool: "Bash", Event: "pre", Command: "npm install x", Decision: "ask", RuleID: "P6.package-install", Reason: "new JS dependency", RepoRoot: other},
	)
	code, out, errOut := runExplain(t, repo, "--all", "--last", "2", "--path", path)
	if code != 0 {
		t.Fatalf("exit = %d, stderr %q", code, errOut)
	}
	first, second := strings.Index(out, "npm install x"), strings.Index(out, "git push --force")
	if first < 0 || second < 0 || first > second {
		t.Fatalf("--all --last 2 should list both records newest first:\n%s", out)
	}
}

func TestExplainAskNamesTheExactOperatorGrant(t *testing.T) {
	repo := t.TempDir()
	path := writeExplainLog(t,
		audit.Record{TS: "2026-09-26T10:00:00Z", SessionID: "s1", Plane: "claude", Tool: "Bash", NativeTool: "Bash", Event: "pre", Command: "npm install left-pad", Decision: "ask", RuleID: "P6.package-install", Reason: "new JS dependency", RepoRoot: repo},
	)
	code, out, errOut := runExplain(t, repo, "--path", path)
	if code != 0 {
		t.Fatalf("exit = %d, stderr %q", code, errOut)
	}
	for _, want := range []string{
		"conversational approval",
		"guardrail approvals grant --repo " + shellQuote(repo) + " --rule P6.package-install --command " + shellQuote("npm install left-pad"),
	} {
		if !strings.Contains(out, want) {
			t.Errorf("explain output missing %q:\n%s", want, out)
		}
	}
}

func TestExplainNeverOffersAGrantForAnUngrantableAsk(t *testing.T) {
	repo := t.TempDir()
	path := writeExplainLog(t,
		audit.Record{TS: "2026-09-26T10:00:00Z", Plane: "claude", Tool: "mcp__x__y", Event: "pre", Decision: "ask", RuleID: "capability-external", Reason: "outward reach", RepoRoot: repo},
	)
	code, out, _ := runExplain(t, repo, "--path", path)
	if code != 0 {
		t.Fatalf("exit = %d", code)
	}
	if strings.Contains(out, "approvals grant") {
		t.Errorf("capability-external can never be granted, but explain offers a grant:\n%s", out)
	}
	if !strings.Contains(out, "can never be granted") {
		t.Errorf("explain should say the ask can never be granted:\n%s", out)
	}
}

func TestWindowsAndPOSIXExplainCodexNeverPromisesConversationalApproval(t *testing.T) {
	repo := t.TempDir()
	for _, rec := range []audit.Record{
		{Plane: "codex", Tool: "Bash", Event: "pre", Command: "unparseable", Decision: "ask", RuleID: "tokenize-failed", RepoRoot: repo},
		{Plane: "codex", Tool: "Edit", Event: "pre", Decision: "ask", RuleID: "P5.ci-infra-lockfile", RequestID: strings.Repeat("a", 64), RepoRoot: repo},
	} {
		path := writeExplainLog(t, rec)
		code, out, _ := runExplain(t, repo, "--path", path)
		if code != 0 {
			t.Fatalf("exit %d", code)
		}
		if strings.Contains(out, "conversational approval.") || strings.Contains(out, "once they approve") {
			t.Fatalf("unsupported approval: %s", out)
		}
		if rec.RequestID != "" && !strings.Contains(out, "guardrail approvals grant --record "+rec.RequestID) {
			t.Fatalf("missing exact request: %s", out)
		}
		if rec.RuleID == "tokenize-failed" && strings.Contains(out, "single-use grant") {
			t.Fatalf("backstop grant offered: %s", out)
		}
	}
}

func TestWindowsAndPOSIXExplainCodexPostFindingCannotOfferApproval(t *testing.T) {
	repo := t.TempDir()
	path := writeExplainLog(t, audit.Record{Plane: "codex", Tool: "Edit", Event: "post", Decision: "ask", RuleID: "P5.ci-infra-lockfile", RepoRoot: repo})
	code, out, _ := runExplain(t, repo, "--path", path)
	if code != 0 {
		t.Fatalf("exit %d", code)
	}
	if !strings.Contains(out, "tool already ran") || strings.Contains(out, "approvals grant") || strings.Contains(out, "retry the exact call once they approve") {
		t.Fatalf("post finding advertised approval: %s", out)
	}
}

func TestExplainRedactedCommandIsNotOfferedAsAGrant(t *testing.T) {
	repo := t.TempDir()
	path := writeExplainLog(t,
		audit.Record{TS: "2026-09-26T10:00:00Z", Plane: "claude", Tool: "Bash", Event: "pre", Command: "npm install --token=abcdef0123456789abcdef x", Decision: "ask", RuleID: "P6.package-install", Reason: "new JS dependency", RepoRoot: repo},
	)
	code, out, _ := runExplain(t, repo, "--path", path)
	if code != 0 {
		t.Fatalf("exit = %d", code)
	}
	if strings.Contains(out, "approvals grant --repo") {
		t.Errorf("the audit log redacted this command, so a grant built from it could never match; explain must not print one:\n%s", out)
	}
	if !strings.Contains(out, "redacted") {
		t.Errorf("explain should say why no grant command is printed:\n%s", out)
	}
}

func TestExplainFailClosedDenyWithoutRuleIDIsExplainedHonestly(t *testing.T) {
	repo := t.TempDir()
	path := writeExplainLog(t,
		audit.Record{TS: "2026-09-26T10:00:00Z", Plane: "claude", AuditKind: "hook-fail-closed", Decision: "deny", Reason: "guardrail: unparseable hook payload (unexpected EOF); failing closed"},
	)
	code, out, errOut := runExplain(t, repo, "--path", path)
	if code != 0 {
		t.Fatalf("exit = %d, stderr %q", code, errOut)
	}
	for _, want := range []string{"unparseable hook payload", "no rule ID", "failed closed", "guardrail doctor"} {
		if !strings.Contains(out, want) {
			t.Errorf("explain output missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "rule ID ()") {
		t.Errorf("explain must not render an empty rule ID as if it were one:\n%s", out)
	}
}

func TestExplainBrokeredOperatorActionBySelector(t *testing.T) {
	repo := t.TempDir()
	path := writeExplainLog(t,
		audit.Record{TS: "2026-09-26T10:00:00Z", SessionID: "s9", Plane: "claude", Tool: "Bash", Event: "pre", Command: "guardrail egress grant --scope repo --host example.test", Decision: "complete", RuleID: "operator-action", Reason: "operator action requires broker approval", OperatorAction: "web-host-grant", RequestID: "req-abc", RepoRoot: repo},
		audit.Record{TS: "2026-09-26T10:00:01Z", Plane: "claude", Tool: "guardrail", Event: "operator-action", Decision: "requested", OperatorAction: "web-host-grant", RequestID: "req-abc"},
		audit.Record{TS: "2026-09-26T10:05:00Z", SessionID: "s9", Plane: "claude", Tool: "Bash", Event: "pre", Command: "rm -rf x", Decision: "deny", RuleID: "P1.rm-rf", Reason: "recursive force delete", RepoRoot: repo},
	)
	code, out, errOut := runExplain(t, t.TempDir(), "req-abc", "--path", path)
	if code != 0 {
		t.Fatalf("exit = %d, stderr %q", code, errOut)
	}
	for _, want := range []string{"web-host-grant", "req-abc", "guardrail approvals approve req-abc", "requested"} {
		if !strings.Contains(out, want) {
			t.Errorf("explain req-abc missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "rm -rf x") {
		t.Errorf("a request-id selector must show only that request:\n%s", out)
	}

	// A session id selects that session's newest non-allow record, from any directory.
	code, out, _ = runExplain(t, t.TempDir(), "s9", "--path", path)
	if code != 0 || !strings.Contains(out, "rm -rf x") {
		t.Errorf("explain s9 (exit %d) should show the session's newest record:\n%s", code, out)
	}

	// A timestamp selects the record written at that instant.
	code, out, _ = runExplain(t, t.TempDir(), "2026-09-26T10:00:00Z", "--path", path)
	if code != 0 || !strings.Contains(out, "req-abc") || strings.Contains(out, "rm -rf x") {
		t.Errorf("explain <ts> (exit %d) should show the record at that instant:\n%s", code, out)
	}
}

func TestExplainWithNothingToExplainExitsOne(t *testing.T) {
	repo := t.TempDir()
	path := writeExplainLog(t,
		audit.Record{TS: "2026-09-26T10:00:00Z", Plane: "claude", Tool: "Bash", Event: "pre", Command: "ls", Decision: "allow", RepoRoot: repo},
	)
	code, out, errOut := runExplain(t, repo, "--path", path)
	if code != 1 {
		t.Fatalf("exit = %d, want 1 (a state, not a crash); stdout %q", code, out)
	}
	if !strings.Contains(errOut, "--all") {
		t.Errorf("the empty answer should point at --all: %q", errOut)
	}

	missing := filepath.Join(t.TempDir(), "absent.jsonl")
	if code, _, errOut := runExplain(t, repo, "--path", missing); code != 1 || !strings.Contains(errOut, "no audit log") {
		t.Errorf("missing log: exit %d stderr %q", code, errOut)
	}
}

func TestExplainRejectsBadArguments(t *testing.T) {
	for _, args := range [][]string{
		{"--last"},
		{"--last", "0"},
		{"--last", "x"},
		{"--path"},
		{"--nope"},
		{"a", "b"},
	} {
		if code, _, _ := runExplain(t, t.TempDir(), args...); code != 2 {
			t.Errorf("explain %v: exit = %d, want 2", args, code)
		}
	}
}

// The hook records the repository it evaluated for, which is what lets
// explain default to "this repo" (#106).
func TestHookAuditRecordCarriesTheRepoRoot(t *testing.T) {
	testenv.SetState(t, t.TempDir())
	testenv.SetConfig(t, t.TempDir())
	t.Setenv("GUARDRAIL_CONFIG", "")
	cwd := t.TempDir()
	payload, _ := json.Marshal(map[string]any{
		"session_id": "rr1", "cwd": cwd, "hook_event_name": "PreToolUse",
		"tool_name": "Bash", "tool_input": map[string]any{"command": "rm -rf /"},
	})
	var out, errb strings.Builder
	if code := run([]string{"hook", "claude"}, strings.NewReader(string(payload)), &out, &errb); code != 2 {
		t.Fatalf("hook exit = %d, want deny; stderr %q", code, errb.String())
	}
	rec := lastAuditRecord(t)
	if rec.RepoRoot == "" || !sameRepoRoot(rec.RepoRoot, cwd) {
		t.Fatalf("audit repo_root = %q, want %q", rec.RepoRoot, cwd)
	}
}

// A hook that fails closed before evaluating anything still leaves a record,
// so the deny the agent saw can be found and explained (#106).
func TestHookFailClosedDenyIsAudited(t *testing.T) {
	testenv.SetState(t, t.TempDir())
	testenv.SetConfig(t, t.TempDir())
	var out, errb strings.Builder
	if code := run([]string{"hook", "claude"}, strings.NewReader("{"), &out, &errb); code != 2 {
		t.Fatalf("hook exit = %d, want fail-closed 2", code)
	}
	rec := lastAuditRecord(t)
	if rec.Decision != "deny" || rec.RuleID != "" || rec.AuditKind != "hook-fail-closed" || rec.Plane != "claude" ||
		!strings.Contains(rec.Reason, "unparseable hook payload") {
		t.Fatalf("fail-closed audit record = %+v", rec)
	}
}

func lastAuditRecord(t *testing.T) audit.Record {
	t.Helper()
	raw, err := os.ReadFile(audit.DefaultPath(""))
	if err != nil {
		t.Fatalf("read audit log: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	var rec audit.Record
	if err := json.Unmarshal([]byte(lines[len(lines)-1]), &rec); err != nil {
		t.Fatal(err)
	}
	return rec
}
