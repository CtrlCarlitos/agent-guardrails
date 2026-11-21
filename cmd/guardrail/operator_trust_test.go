package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/CtrlCarlitos/agent-guardrails/internal/approval"
	"github.com/CtrlCarlitos/agent-guardrails/internal/engine"
	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
	"github.com/CtrlCarlitos/agent-guardrails/internal/testenv"
)

func initTrustTestRepo(t *testing.T, overlayTOML string) string {
	t.Helper()
	repo := t.TempDir()
	// Create a real git repository so policy.FindRepoRoot and doctor resolve it.
	if out, err := exec.Command("git", "init", repo).CombinedOutput(); err != nil {
		t.Fatalf("git init %s: %v (%s)", repo, err, out)
	}
	if err := os.WriteFile(filepath.Join(repo, "guardrail.toml"), []byte(overlayTOML), 0o644); err != nil {
		t.Fatal(err)
	}
	return repo
}

func TestWindowsAndPOSIXOperatorTrustPromptModeLifecycle(t *testing.T) {
	testenv.SetHome(t, t.TempDir())
	testenv.SetConfig(t, t.TempDir())
	testenv.SetState(t, t.TempDir())
	t.Setenv("GUARDRAIL_CONFIG", "")
	stubOperatorEnrolled(t, false)
	useNoCredentialPosture(t)
	useInstalledPlanes(t)

	repo := initTrustTestRepo(t, `
waive = ["P6.egress", "tokenize-failed"]
audit_log = "repo-audit.jsonl"

[slots]
egress_allowlist = ["api.example.com", "*"]
web_hosts = ["docs.example.com"]
secret_allow = ["fixtures/**"]
`)

	// Seed prompt mode plus a pre-existing manual waiver to verify preservation.
	opPath := policy.OperatorConfigPath()
	if err := os.MkdirAll(filepath.Dir(opPath), 0o700); err != nil {
		t.Fatal(err)
	}
	seed := "approval = \"prompt\"\n\n[" + tomlQuote(repo) + "]\nwaive = [\"P2.manual\"]\n"
	if err := os.WriteFile(opPath, []byte(seed), 0o600); err != nil {
		t.Fatal(err)
	}

	// Non-terminal invocation fails closed with exit 2.
	var stdout, stderr bytes.Buffer
	if code := cmdOperatorInput([]string{"trust", repo}, false, strings.NewReader("y\n"), &stdout, &stderr); code != 2 {
		t.Fatalf("trust without terminal exit = %d, want 2 (stderr=%q)", code, stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	if code := cmdOperatorInput([]string{"untrust", repo}, false, strings.NewReader("y\n"), &stdout, &stderr); code != 2 {
		t.Fatalf("untrust without terminal exit = %d, want 2 (stderr=%q)", code, stderr.String())
	}

	// Declining prompt leaves waivers.toml unchanged.
	stdout.Reset()
	stderr.Reset()
	if code := cmdOperatorInput([]string{"trust", repo}, true, strings.NewReader("n\n"), &stdout, &stderr); code != 1 {
		t.Fatalf("declined trust exit = %d, want 1 (stdout=%q stderr=%q)", code, stdout.String(), stderr.String())
	}
	// Review list must be shown BEFORE prompting, including rejected items.
	for _, want := range []string{"api.example.com", "docs.example.com", "P6.egress", "fixtures/**", "repo-audit.jsonl", "tokenize-failed"} {
		if !strings.Contains(stdout.String(), want) {
			t.Errorf("trust review output missing %q:\n%s", want, stdout.String())
		}
	}
	op, err := policy.LoadOperatorConfig()
	if err != nil {
		t.Fatal(err)
	}
	if op.HasTrustSnapshot(repo) {
		t.Fatal("declined trust still wrote snapshot")
	}

	// Approving prompt writes the snapshot and preserves manual grants.
	stdout.Reset()
	stderr.Reset()
	if code := cmdOperatorInput([]string{"trust", repo}, true, strings.NewReader("y\n"), &stdout, &stderr); code != 0 {
		t.Fatalf("approved trust exit = %d, stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	op, err = policy.LoadOperatorConfig()
	if err != nil {
		t.Fatal(err)
	}
	if !op.HasTrustSnapshot(repo) {
		t.Fatal("approved trust did not persist snapshot")
	}
	if !op.AllowsWaiver(repo, "P2.manual") {
		t.Fatal("approved trust clobbered pre-existing manual waiver")
	}
	ov, err := policy.LoadOverlay(filepath.Join(repo, "guardrail.toml"))
	if err != nil {
		t.Fatal(err)
	}
	base := &policy.Policy{Slots: policy.Slots{AuditLog: "/base/audit.jsonl"}, Waived: map[string]bool{}}
	merged, _, err := policy.Merge(base, ov, "1.0.0", op, repo)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(merged.Slots.EgressAllowlist, "api.example.com") ||
		!slices.Contains(merged.Slots.WebHosts, "docs.example.com") ||
		!merged.Waived["P6.egress"] ||
		!slices.Contains(merged.Slots.SecretAllow, "fixtures/**") ||
		merged.Slots.AuditLog != "repo-audit.jsonl" {
		t.Fatalf("merged policy did not honor trusted snapshot: %+v", merged)
	}
	if merged.Waived["tokenize-failed"] || slices.Contains(merged.Slots.EgressAllowlist, "*") {
		t.Fatalf("non-authorizable entries leaked into merged policy: %+v", merged)
	}

	// Re-running trust when unchanged is a clean no-op without prompting.
	stdout.Reset()
	stderr.Reset()
	if code := cmdOperatorInput([]string{"trust", repo}, true, strings.NewReader(""), &stdout, &stderr); code != 0 {
		t.Fatalf("idempotent trust exit = %d, stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	if !strings.Contains(strings.ToLower(stdout.String()), "up to date") {
		t.Errorf("idempotent trust output = %q, want 'up to date'", stdout.String())
	}

	// Simulate a PR editing guardrail.toml: adds newdomain.example.com, removes api.example.com.
	updatedOverlay := `
waive = ["P6.egress"]
audit_log = "repo-audit.jsonl"

[slots]
egress_allowlist = ["newdomain.example.com"]
web_hosts = ["docs.example.com"]
secret_allow = ["fixtures/**"]
`
	if err := os.WriteFile(filepath.Join(repo, "guardrail.toml"), []byte(updatedOverlay), 0o644); err != nil {
		t.Fatal(err)
	}

	// Doctor shows the trust diff (authorized, new, removed).
	t.Chdir(repo)
	stdout.Reset()
	stderr.Reset()
	if code := cmdDoctor(nil, &stdout, &stderr); code != 0 {
		t.Fatalf("doctor exit = %d, stderr=%q", code, stderr.String())
	}
	docOut := stdout.String()
	for _, want := range []string{"overlay trust:", "newdomain.example.com", "api.example.com", "guardrail operator trust"} {
		if !strings.Contains(docOut, want) {
			t.Errorf("doctor output missing %q:\n%s", want, docOut)
		}
	}

	// Re-trusting authorizes newdomain.example.com and drops api.example.com.
	stdout.Reset()
	stderr.Reset()
	if code := cmdOperatorInput([]string{"trust", repo}, true, strings.NewReader("y\n"), &stdout, &stderr); code != 0 {
		t.Fatalf("re-trust exit = %d, stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	op, err = policy.LoadOperatorConfig()
	if err != nil {
		t.Fatal(err)
	}
	if !op.AllowsEgress(repo, "newdomain.example.com") || op.AllowsEgress(repo, "api.example.com") {
		t.Fatalf("re-trust did not replace snapshot: new=%v old=%v", op.AllowsEgress(repo, "newdomain.example.com"), op.AllowsEgress(repo, "api.example.com"))
	}

	// Untrust revokes snapshot while keeping manual waiver intact.
	stdout.Reset()
	stderr.Reset()
	if code := cmdOperatorInput([]string{"untrust", repo}, true, strings.NewReader("y\n"), &stdout, &stderr); code != 0 {
		t.Fatalf("untrust exit = %d, stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	op, err = policy.LoadOperatorConfig()
	if err != nil {
		t.Fatal(err)
	}
	if op.HasTrustSnapshot(repo) {
		t.Fatal("untrust did not remove trust snapshot")
	}
	if op.AllowsEgress(repo, "newdomain.example.com") {
		t.Fatal("egress remained authorized after untrust")
	}
	if !op.AllowsWaiver(repo, "P2.manual") {
		t.Fatal("untrust clobbered pre-existing manual waiver")
	}

	// Second untrust is a clean no-op.
	stdout.Reset()
	stderr.Reset()
	if code := cmdOperatorInput([]string{"untrust", repo}, true, strings.NewReader(""), &stdout, &stderr); code != 0 {
		t.Fatalf("idempotent untrust exit = %d, stderr=%q", code, stderr.String())
	}
}

func TestWindowsAndPOSIXOperatorTrustPasskeyMode(t *testing.T) {
	testenv.SetHome(t, t.TempDir())
	testenv.SetConfig(t, t.TempDir())
	testenv.SetState(t, t.TempDir())
	t.Setenv("GUARDRAIL_CONFIG", "")
	useApprovalMode(t, policy.ApprovalPasskey)

	repo := initTrustTestRepo(t, `
[slots]
egress_allowlist = ["passkey.example.com"]
`)

	// Unenrolled operator exits exitNotEnrolled (3).
	stubOperatorEnrolled(t, false)
	var stdout, stderr bytes.Buffer
	if code := cmdOperatorInput([]string{"trust", repo}, true, strings.NewReader(""), &stdout, &stderr); code != exitNotEnrolled {
		t.Fatalf("unenrolled passkey trust exit = %d, want %d (stderr=%q)", code, exitNotEnrolled, stderr.String())
	}

	// Enrolled operator submits operator-trust-set to the broker and converges on completion.
	stubOperatorEnrolled(t, true)
	origSubmit := submitOperatorTrustRequest
	origQuery := queryOperatorTrustStatus
	t.Cleanup(func() {
		submitOperatorTrustRequest = origSubmit
		queryOperatorTrustStatus = origQuery
	})

	var submitted approval.Request
	submitOperatorTrustRequest = func(req approval.Request) (approval.Request, error) {
		submitted = req
		req.ID = "trust-req-1"
		req.ApprovalURL = "http://localhost:9999/approve/trust-req-1"
		req.ExpiresAt = time.Now().Add(time.Minute)
		return req, nil
	}
	queryOperatorTrustStatus = func(_ string, id string) (approval.Request, error) {
		if id != "trust-req-1" {
			t.Fatalf("queried unexpected id %q", id)
		}
		if err := executeOperatorTrustApproval(submitted); err != nil {
			t.Fatalf("executeOperatorTrustApproval: %v", err)
		}
		return approval.Request{ID: id, Status: "completed"}, nil
	}

	stdout.Reset()
	stderr.Reset()
	if code := cmdOperatorInput([]string{"trust", repo}, true, strings.NewReader(""), &stdout, &stderr); code != 0 {
		t.Fatalf("enrolled passkey trust exit = %d, stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	if submitted.Action != "operator-trust-set" || submitted.Scope != approval.RepoScope {
		t.Fatalf("submitted unexpected request: %+v", submitted)
	}
	if !strings.Contains(stdout.String(), "http://localhost:9999/approve/trust-req-1") {
		t.Errorf("passkey trust did not print approval URL:\n%s", stdout.String())
	}
	op, err := policy.LoadOperatorConfig()
	if err != nil {
		t.Fatal(err)
	}
	if !op.AllowsEgress(repo, "passkey.example.com") {
		t.Fatal("passkey-approved trust snapshot did not converge")
	}
}

func TestWindowsAndPOSIXOperatorTrustDeniedForAgents(t *testing.T) {
	base, err := policy.LoadBase()
	if err != nil {
		t.Fatal(err)
	}
	repo := t.TempDir()
	for _, cmd := range []string{
		"guardrail operator trust " + repo,
		"guardrail operator untrust " + repo,
		"guardrail operator trust",
	} {
		v := engine.Evaluate(engine.ToolCall{Tool: "Bash", Command: cmd, CWD: repo, RepoRoot: repo}, base)
		if v.Decision != policy.Deny || v.RuleID != "P5.self-config" {
			t.Errorf("%q -> %s/%s, want deny/P5.self-config", cmd, v.Decision, v.RuleID)
		}
	}
}

func tomlQuote(s string) string {
	return `"` + strings.ReplaceAll(strings.ReplaceAll(s, `\`, `\\`), `"`, `\"`) + `"`
}
