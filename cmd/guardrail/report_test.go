package main

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/CtrlCarlitos/agent-guardrails/internal/audit"
)

func runReport(t *testing.T, cwd string, args ...string) (int, string, string) {
	t.Helper()
	var out, errb strings.Builder
	code := cmdReport(args, cwd, &out, &errb)
	return code, out.String(), errb.String()
}

// #124: the newest ask/deny for this repository becomes a ready-to-paste
// issue: a title naming the rule, and a body with the version, the record's
// verdict, rule and reason, and the questions only the reporter can answer.
func TestReportPrintsAReadyToPasteIssueForTheNewestRecord(t *testing.T) {
	repo := t.TempDir()
	path := writeExplainLog(t,
		audit.Record{TS: "2026-11-15T10:00:00Z", SessionID: "s1", Plane: "claude", Tool: "Bash", NativeTool: "Bash", Event: "pre", Command: "curl https://example.test", Decision: "deny", RuleID: "P6.egress", Reason: "network access to a non-allowlisted host: example.test", RepoRoot: repo},
		audit.Record{TS: "2026-11-15T10:01:00Z", SessionID: "s1", Plane: "claude", Tool: "Read", NativeTool: "Read", Event: "pre", Paths: []string{".env.example"}, Decision: "deny", RuleID: "P4.secret-path", Reason: "access to a credential/secret path: .env.example", RepoRoot: repo},
		audit.Record{TS: "2026-11-15T10:02:00Z", SessionID: "s1", Plane: "claude", Tool: "Bash", Event: "pre", Command: "ls", Decision: "allow", RepoRoot: repo},
	)
	code, out, errOut := runReport(t, repo, "--path", path)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	first := strings.SplitN(out, "\n", 2)[0]
	if !strings.HasPrefix(first, "Title: [bug] P4.secret-path: ") {
		t.Fatalf("first line %q is not the issue title for the newest ask/deny", first)
	}
	for _, want := range []string{
		"guardrail version", version,
		"2026-11-15T10:01:00Z", "claude", "deny", "P4.secret-path",
		"access to a credential/secret path: .env.example",
		".env.example",
		"What were you trying to do?",
		"Why does this verdict look wrong?",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("report lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "curl https://example.test") {
		t.Errorf("report includes an older record:\n%s", out)
	}
	if !strings.Contains(errOut, "github.com/CtrlCarlitos/agent-guardrails/issues/new") || !strings.Contains(errOut, "review") {
		t.Errorf("stderr does not tell the reporter to review and where to paste:\n%s", errOut)
	}
}

// --last N reports the Nth newest record and --id selects one by timestamp
// or request ID, so a record other than the newest can be filed.
func TestReportSelectsARecordOtherThanTheNewest(t *testing.T) {
	repo := t.TempDir()
	path := writeExplainLog(t,
		audit.Record{TS: "2026-11-15T10:00:00Z", Plane: "claude", Tool: "Bash", Event: "pre", Command: "git push --force", Decision: "deny", RuleID: "P1.git-push-force", Reason: "force push", RepoRoot: repo},
		audit.Record{TS: "2026-11-15T10:01:00Z", Plane: "opencode", Tool: "Bash", Event: "pre", Command: "npm install x", Decision: "ask", RuleID: "P6.package-install", Reason: "new JS dependency", RepoRoot: repo},
		audit.Record{TS: "2026-11-15T10:02:00Z", Plane: "claude", Tool: "Bash", Event: "pre", Command: "rm -rf /", Decision: "deny", RuleID: "P1.rm-rf", Reason: "recursive force delete", RepoRoot: repo, RequestID: "req-abc"},
	)
	for _, c := range []struct {
		args []string
		rule string
	}{
		{[]string{"--last", "2"}, "P6.package-install"},
		{[]string{"--last", "3"}, "P1.git-push-force"},
		{[]string{"--id", "2026-11-15T10:00:00Z"}, "P1.git-push-force"},
		{[]string{"--id", "req-abc"}, "P1.rm-rf"},
	} {
		code, out, errOut := runReport(t, repo, append(c.args, "--path", path)...)
		if code != 0 {
			t.Fatalf("%v: exit %d: %s", c.args, code, errOut)
		}
		if !strings.HasPrefix(out, "Title: [bug] "+c.rule+": ") {
			t.Errorf("%v: title %q, want rule %s", c.args, strings.SplitN(out, "\n", 2)[0], c.rule)
		}
	}
	if code, _, errOut := runReport(t, repo, "--last", "4", "--path", path); code != 1 || !strings.Contains(errOut, "only 3") {
		t.Errorf("--last beyond the records: exit %d stderr %q, want 1 naming how many exist", code, errOut)
	}
	for _, bad := range [][]string{{"--last", "0"}, {"--last"}, {"--id"}, {"--bogus"}, {"--id", "x", "--last", "2"}} {
		if code, _, _ := runReport(t, repo, append(bad, "--path", path)...); code != 2 {
			t.Errorf("%v: exit %d, want 2", bad, code)
		}
	}
}

// The redaction guarantee: whatever the log holds, a report never prints a
// secret the audit redaction recognises, in any field, and never the
// reporter's home directory. A log written by an older binary, or a reason
// that quotes the command, must not carry a token into a public issue.
func TestReportRedactsEverySecretAndTheHomeDirectory(t *testing.T) {
	repo := t.TempDir()
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		t.Skip("no home directory")
	}
	token := "ghp_" + strings.Repeat("A1b2C3d4", 5)
	aws := "AKIA" + "ABCDEFGHIJKLMNOP"
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	// Written raw, as a log from before Command redaction or from another
	// writer would hold it: audit.Write would already redact Command.
	raw := `{"ts":"2026-11-15T10:00:00Z","plane":"claude","tool":"Bash","event":"pre","command":"curl -H 'Authorization: Bearer ` + token + `' https://x.test","paths":["` + filepath.ToSlash(filepath.Join(home, "proj", aws)) + `"],"decision":"deny","rule_id":"P6.egress","reason":"blocked GITHUB_TOKEN=` + token + ` for ` + filepath.ToSlash(filepath.Join(home, "proj")) + `","repo_root":"` + filepath.ToSlash(repo) + `"}` + "\n"
	if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	code, out, errOut := runReport(t, repo, "--all", "--path", path)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	for _, secret := range []string{token, aws, filepath.ToSlash(home), home} {
		if strings.Contains(out, secret) {
			t.Errorf("report leaks %q:\n%s", secret, out)
		}
	}
	if !strings.Contains(out, "«redacted»") || !strings.Contains(out, "~/proj") {
		t.Errorf("report does not show the redaction and home masking it applied:\n%s", out)
	}
}

// A command that itself contains a Markdown fence cannot close the report's
// code block and inject Markdown into the issue.
func TestReportFencesCommandsThatContainBackticks(t *testing.T) {
	repo := t.TempDir()
	path := writeExplainLog(t, audit.Record{TS: "2026-11-15T10:00:00Z", Plane: "claude", Tool: "Bash", Event: "pre", Command: "echo '```' && rm -rf /", Decision: "deny", RuleID: "P1.rm-rf", Reason: "recursive force delete", RepoRoot: repo})
	code, out, _ := runReport(t, repo, "--path", path)
	if code != 0 {
		t.Fatal(code)
	}
	if !strings.Contains(out, "````") {
		t.Errorf("command fence is not longer than the backtick run inside it:\n%s", out)
	}
}

// v1 is print-only: the command never reaches the network or another
// process, so filing stays the reporter's own reviewed act (#124).
func TestReportImportsNoNetworkOrProcessPackages(t *testing.T) {
	f, err := parser.ParseFile(token.NewFileSet(), "report.go", nil, parser.ImportsOnly)
	if err != nil {
		t.Fatal(err)
	}
	for _, imp := range f.Imports {
		p, _ := strconv.Unquote(imp.Path.Value)
		if p == "os/exec" || p == "net" || strings.HasPrefix(p, "net/") {
			t.Errorf("report.go imports %s; v1 must print only", p)
		}
	}
}

func TestReportWithNothingToReportExitsOne(t *testing.T) {
	repo := t.TempDir()
	path := writeExplainLog(t, audit.Record{TS: "2026-11-15T10:00:00Z", Plane: "claude", Tool: "Bash", Event: "pre", Command: "ls", Decision: "allow", RepoRoot: repo})
	if code, out, _ := runReport(t, repo, "--path", path); code != 1 || out != "" {
		t.Errorf("exit %d stdout %q, want 1 and nothing to paste", code, out)
	}
}
