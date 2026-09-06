package engine

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
	"github.com/CtrlCarlitos/agent-guardrails/internal/session"
)

func TestIsPrivateDataAccess(t *testing.T) {
	pol := pathPol()
	if !IsPrivateDataAccess(ToolCall{Tool: "Read", Paths: []string{"/h/.ssh/id_rsa"}}, pol) {
		t.Error("want true for a secret path")
	}
	if IsPrivateDataAccess(ToolCall{Tool: "Read", Paths: []string{"src/main.go"}}, pol) {
		t.Error("want false for a non-secret path")
	}
	if !IsPrivateDataAccess(ToolCall{Tool: "Bash", Command: "cat ~/.aws/credentials"}, pol) {
		t.Error("want true for a bash reader of a secret path")
	}
	if !IsPrivateDataAccess(ToolCall{Tool: "Bash", Command: "/bin/cat ~/.aws/credentials"}, pol) {
		t.Error("want true for an absolute bash reader of a secret path")
	}
	if IsPrivateDataAccess(ToolCall{Tool: "Read", Paths: []string{"/repo/.env.example"}}, pol) {
		t.Error("want false for an allowlisted secret-adjacent path")
	}
	for _, command := range []string{`> /repo/.env`, `< /repo/.env`, `<> /repo/.env`} {
		if !IsPrivateDataAccess(ToolCall{Tool: "Bash", Command: command}, pol) {
			t.Errorf("%q should count as private-data access", command)
		}
	}
	for _, command := range []string{"cat <<'/repo/.env'\nbody\n/repo/.env", `cat <<< /repo/.env`} {
		if IsPrivateDataAccess(ToolCall{Tool: "Bash", Command: command}, pol) {
			t.Errorf("%q should not count here-data as a path", command)
		}
	}
}

func TestIsPrivateDataAccessUsesStatementCwd(t *testing.T) {
	repo := t.TempDir()
	if err := os.Mkdir(filepath.Join(repo, ".aws"), 0o700); err != nil {
		t.Fatal(err)
	}
	tc := ToolCall{Tool: "Bash", Command: `cd .aws; cat credentials`, CWD: repo, RepoRoot: repo}
	if !IsPrivateDataAccess(tc, pathPol()) {
		t.Fatal("relative read after cd should count as private-data access")
	}
}

func TestIsNetworkAttempt(t *testing.T) {
	if !IsNetworkAttempt(ToolCall{Tool: "Bash", Command: "curl https://example.com"}) {
		t.Error("want true for curl")
	}
	if !IsNetworkAttempt(ToolCall{Tool: "Bash", Command: "/usr/bin/curl https://example.com"}) {
		t.Error("want true for absolute curl")
	}
	if IsNetworkAttempt(ToolCall{Tool: "Bash", Command: "ls -la"}) {
		t.Error("want false for ls")
	}
	if IsNetworkAttempt(ToolCall{Tool: "Read", Paths: []string{"x"}}) {
		t.Error("want false for a non-bash tool call")
	}
}

func TestTrifectaVerdictEscalatesSecondLeg(t *testing.T) {
	v := TrifectaVerdict(policy.Verdict{Decision: policy.Allow}, true, false, &session.State{SawNetworkCall: true})
	if v == nil || v.Decision != policy.Ask || v.RuleID != "P7.trifecta" {
		t.Fatalf("private read after a network call -> %+v, want ask/P7.trifecta", v)
	}
	v = TrifectaVerdict(policy.Verdict{Decision: policy.Allow}, false, true, &session.State{SawPrivateRead: true})
	if v == nil || v.RuleID != "P7.trifecta" {
		t.Fatalf("network call after a private read -> %+v, want ask/P7.trifecta", v)
	}
}

func TestTrifectaVerdictNoEscalationWithoutBothLegs(t *testing.T) {
	if v := TrifectaVerdict(policy.Verdict{Decision: policy.Allow}, true, false, &session.State{}); v != nil {
		t.Fatalf("private read with no prior signal -> %+v, want nil", v)
	}
	if v := TrifectaVerdict(policy.Verdict{Decision: policy.Allow}, false, false, &session.State{SawPrivateRead: true, SawNetworkCall: true}); v != nil {
		t.Fatalf("neither leg this call -> %+v, want nil", v)
	}
}

func TestTrifectaVerdictNeverOverridesNonAllow(t *testing.T) {
	existing := policy.Verdict{Decision: policy.Ask, RuleID: "P1.chmod", Reason: "other reason"}
	if v := TrifectaVerdict(existing, true, true, &session.State{SawPrivateRead: true, SawNetworkCall: true}); v != nil {
		t.Fatalf("should not override an existing non-allow verdict, got %+v", v)
	}
}
