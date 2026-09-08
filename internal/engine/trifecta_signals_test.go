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

func TestApplyTrifectaEscalatesSecondLegAndRecordsSignals(t *testing.T) {
	pol := pathPol()
	privateState := &session.State{SawNetworkCall: true}
	v := ApplyTrifecta(
		policy.Verdict{Decision: policy.Allow},
		ToolCall{Tool: "Read", Paths: []string{"/h/.ssh/id_rsa"}},
		privateState,
		pol,
	)
	if v == nil || v.Decision != policy.Ask || v.RuleID != "P7.trifecta" {
		t.Fatalf("private read after a network call -> %+v, want ask/P7.trifecta", v)
	}
	if !privateState.SawPrivateRead || !privateState.SawNetworkCall {
		t.Fatalf("private signal was not recorded: %+v", privateState)
	}

	networkState := &session.State{SawPrivateRead: true}
	v = ApplyTrifecta(
		policy.Verdict{Decision: policy.Allow},
		ToolCall{Tool: "Bash", Command: "curl https://example.com"},
		networkState,
		pol,
	)
	if v == nil || v.RuleID != "P7.trifecta" {
		t.Fatalf("network call after a private read -> %+v, want ask/P7.trifecta", v)
	}
	if !networkState.SawPrivateRead || !networkState.SawNetworkCall {
		t.Fatalf("network signal was not recorded: %+v", networkState)
	}
}

func TestApplyTrifectaNoEscalationWithoutBothLegs(t *testing.T) {
	pol := pathPol()
	state := &session.State{}
	if v := ApplyTrifecta(policy.Verdict{Decision: policy.Allow}, ToolCall{Tool: "Read", Paths: []string{"/h/.ssh/id_rsa"}}, state, pol); v != nil {
		t.Fatalf("private read with no prior signal -> %+v, want nil", v)
	}
	if !state.SawPrivateRead || state.SawNetworkCall {
		t.Fatalf("first private signal was not recorded: %+v", state)
	}
	if v := ApplyTrifecta(policy.Verdict{Decision: policy.Allow}, ToolCall{Tool: "Bash", Command: "ls"}, &session.State{SawPrivateRead: true, SawNetworkCall: true}, pol); v != nil {
		t.Fatalf("neither leg this call -> %+v, want nil", v)
	}
}

func TestApplyTrifectaNeverOverridesNonAllow(t *testing.T) {
	existing := policy.Verdict{Decision: policy.Ask, RuleID: "P1.chmod", Reason: "other reason"}
	state := &session.State{SawNetworkCall: true}
	if v := ApplyTrifecta(existing, ToolCall{Tool: "Read", Paths: []string{"/h/.ssh/id_rsa"}}, state, pathPol()); v != nil {
		t.Fatalf("should not override an existing non-allow verdict, got %+v", v)
	}
	if !state.SawPrivateRead || !state.SawNetworkCall {
		t.Fatalf("signal under existing Ask was not recorded: %+v", state)
	}
}

func TestApplyTrifectaEscalatesUnavailableTrackingSignals(t *testing.T) {
	const wantReason = "session tracking is unavailable; approval is required because P7 cannot retain this private-data or network signal"
	for _, test := range []struct {
		name string
		tc   ToolCall
	}{
		{"private data", ToolCall{Tool: "Read", Paths: []string{"/h/.ssh/id_rsa"}}},
		{"network", ToolCall{Tool: "Bash", Command: "curl https://example.com"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			v := ApplyTrifecta(policy.Verdict{Decision: policy.Allow}, test.tc, nil, pathPol())
			if v == nil || v.Decision != policy.Ask || v.RuleID != "P7.tracking-unavailable" || v.Reason != wantReason {
				t.Fatalf("unavailable tracking -> %+v, want ask/P7.tracking-unavailable", v)
			}
		})
	}
}

func TestApplyTrifectaUnavailableTrackingPreservesUnderlyingVerdict(t *testing.T) {
	private := ToolCall{Tool: "Read", Paths: []string{"/h/.ssh/id_rsa"}}
	for _, existing := range []policy.Verdict{
		{Decision: policy.Ask, RuleID: "P1.chmod", Reason: "existing ask"},
		{Decision: policy.Deny, RuleID: "P4.secret-path", Reason: "existing deny"},
	} {
		if v := ApplyTrifecta(existing, private, nil, pathPol()); v != nil {
			t.Errorf("existing %s -> %+v, want no override", existing.Decision, v)
		}
	}
	if v := ApplyTrifecta(policy.Verdict{Decision: policy.Allow}, ToolCall{Tool: "Bash", Command: "ls"}, nil, pathPol()); v != nil {
		t.Fatalf("routine call with unavailable tracking -> %+v, want nil", v)
	}
}

func TestApplyTrifectaWaiverDisablesPolicyOperation(t *testing.T) {
	pol := pathPol()
	pol.Waived = map[string]bool{"P7.trifecta": true}
	state := &session.State{SawNetworkCall: true}
	private := ToolCall{Tool: "Read", Paths: []string{"/h/.ssh/id_rsa"}}
	if v := ApplyTrifecta(policy.Verdict{Decision: policy.Allow}, private, state, pol); v != nil {
		t.Fatalf("waived available tracking -> %+v, want nil", v)
	}
	if state.SawPrivateRead || !state.SawNetworkCall {
		t.Fatalf("waived policy operation mutated state: %+v", state)
	}
	if v := ApplyTrifecta(policy.Verdict{Decision: policy.Allow}, private, nil, pol); v != nil {
		t.Fatalf("waived unavailable tracking -> %+v, want nil", v)
	}
}
