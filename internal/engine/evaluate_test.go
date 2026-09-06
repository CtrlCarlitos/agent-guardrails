package engine

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
)

func fullPol() *policy.Policy {
	p := pathPol()
	p.Slots.SafeRoots = []string{"/repo/tmp"}
	p.Rules = []policy.Rule{
		{ID: "proj.tf", Pattern: "terraform apply*", Decision: policy.Ask, Reason: "infra"},
	}
	return p
}

func TestEvaluate(t *testing.T) {
	cases := []struct {
		tc   ToolCall
		want policy.Decision
		id   string
	}{
		{ToolCall{Tool: "Bash", Command: "ls -la", CWD: "/repo", RepoRoot: "/repo"}, policy.Allow, ""},
		{ToolCall{Tool: "Bash", Command: "rm -rf /", CWD: "/repo", RepoRoot: "/repo"}, policy.Deny, "P1.rm-rf"},
		{ToolCall{Tool: "Read", Paths: []string{"/h/.ssh/id_rsa"}}, policy.Deny, "P4.secret-path"},
		{ToolCall{Tool: "Bash", Command: "chmod -R 777 /repo", CWD: "/repo", RepoRoot: "/repo"}, policy.Ask, "P1.chmod"},
		{ToolCall{Tool: "Bash", Command: "terraform apply -auto-approve", CWD: "/repo", RepoRoot: "/repo"}, policy.Ask, "proj.tf"},
		{ToolCall{Tool: "Bash", Command: `echo "oops`, CWD: "/repo", RepoRoot: "/repo"}, policy.Ask, "tokenize-failed"},
	}
	for _, c := range cases {
		v := Evaluate(c.tc, fullPol())
		if v.Decision != c.want || (c.id != "" && v.RuleID != c.id) {
			t.Errorf("Evaluate(%q) = %+v, want %s/%s", c.tc.Command+c.tc.Tool, v, c.want, c.id)
		}
	}
}

func TestEvaluateWaived(t *testing.T) {
	p := fullPol()
	p.Waived["P1.rm-rf"] = true
	v := Evaluate(ToolCall{Tool: "Bash", Command: "rm -rf /etc", CWD: "/repo", RepoRoot: "/repo"}, p)
	if v.Decision != policy.Allow {
		t.Fatalf("waived rule still fired: %+v", v)
	}
}

func TestEvaluateSecretGlobWaiverStillAllows(t *testing.T) {
	p := fullPol()
	p.Waived["P4.secret-path"] = true
	tc := ToolCall{Tool: "Read", Paths: []string{"/repo/.env"}, CWD: "/repo", RepoRoot: "/repo"}
	if v := Evaluate(tc, p); v.Decision != policy.Allow {
		t.Fatalf("waived secret glob -> %+v, want allow", v)
	}
}

func TestEvaluateSecretDirIgnoresP4Waiver(t *testing.T) {
	p := fullPol()
	p.Waived["P4.secret-path"] = true
	tc := ToolCall{Tool: "Read", Paths: []string{"/home/u/.ssh/id_rsa"}, CWD: "/repo", RepoRoot: "/repo"}
	if v := Evaluate(tc, p); v.Decision != policy.Deny || v.RuleID != "P4.secret-path" {
		t.Fatalf("direct secret-dir path with P4 waiver -> %+v, want deny/P4.secret-path", v)
	}
}

func TestEvaluateResolvedSecretDirIgnoresP4Waiver(t *testing.T) {
	secretDir := filepath.Join(t.TempDir(), ".ssh")
	if err := os.Mkdir(secretDir, 0o700); err != nil {
		t.Fatal(err)
	}
	secret := filepath.Join(secretDir, "id_rsa")
	if err := os.WriteFile(secret, []byte("k"), 0o600); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(t.TempDir(), "innocent")
	if err := os.Symlink(secret, alias); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	p := fullPol()
	p.Waived["P4.secret-path"] = true
	tc := ToolCall{Tool: "Read", Paths: []string{alias}, CWD: "/repo", RepoRoot: "/repo"}
	if v := Evaluate(tc, p); v.Decision != policy.Deny || v.RuleID != "P4.secret-path" {
		t.Fatalf("resolved secret-dir path with P4 waiver -> %+v, want deny/P4.secret-path", v)
	}
}

func TestEvaluateWaivedLexicalDenyKeepsResolvedAsk(t *testing.T) {
	repo := t.TempDir()
	cert := filepath.Join(repo, "cert.pem")
	if err := os.WriteFile(cert, []byte("cert"), 0o600); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(repo, ".env")
	if err := os.Symlink(cert, alias); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	p := fullPol()
	p.Waived["P4.secret-path"] = true
	tc := ToolCall{Tool: "Read", Paths: []string{alias}, CWD: repo, RepoRoot: repo}
	if v := Evaluate(tc, p); v.Decision != policy.Ask || v.RuleID != "P4.secret-path-ambiguous" {
		t.Fatalf("waived lexical deny plus unwaived resolved ask -> %+v, want ask/P4.secret-path-ambiguous", v)
	}
}

func TestEvaluateStrongestUnwaivedSecretTierOnSameForm(t *testing.T) {
	tc := ToolCall{Tool: "Read", Paths: []string{"/repo/foo-private-key.pem"}, CWD: "/repo", RepoRoot: "/repo"}
	for _, test := range []struct {
		name   string
		waived bool
		want   policy.Decision
		ruleID string
	}{
		{name: "deny wins without waiver", want: policy.Deny, ruleID: "P4.secret-path"},
		{name: "ask survives deny waiver", waived: true, want: policy.Ask, ruleID: "P4.secret-path-ambiguous"},
	} {
		t.Run(test.name, func(t *testing.T) {
			p := fullPol()
			p.Waived["P4.secret-path"] = test.waived
			if v := Evaluate(tc, p); v.Decision != test.want || v.RuleID != test.ruleID {
				t.Fatalf("Evaluate() = %+v, want %s/%s", v, test.want, test.ruleID)
			}
		})
	}
}

func TestEvaluateWaivedOverlayRuleStillAllows(t *testing.T) {
	p := fullPol()
	p.Waived["proj.tf"] = true
	tc := ToolCall{Tool: "Bash", Command: "terraform apply -auto-approve", CWD: "/repo", RepoRoot: "/repo"}
	if v := Evaluate(tc, p); v.Decision != policy.Allow {
		t.Fatalf("waived Overlay rule -> %+v, want allow", v)
	}
}
