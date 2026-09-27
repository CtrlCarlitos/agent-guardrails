package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/CtrlCarlitos/agent-guardrails/internal/approval"
	"github.com/CtrlCarlitos/agent-guardrails/internal/audit"
	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
)

// ADR-0033 (#413): approvals default to a prompt. These tests run the
// production resolution (a real waivers.toml in the sandbox config root);
// the rest of the package runs under passkey through TestMain, which is how
// "passkey mode keeps today's behaviour" stays pinned by every older test.

func useApprovalMode(t *testing.T, mode string) {
	t.Helper()
	path := policy.OperatorConfigPath()
	if path == "" {
		t.Fatal("operator config path unresolved")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("approval = \""+mode+"\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

// promptSandbox is driftSandbox plus a working directory the hook payload
// and the CLI run share, in prompt mode, with nobody enrolled.
func promptSandbox(t *testing.T) string {
	t.Helper()
	driftSandbox(t)
	useApprovalMode(t, policy.ApprovalPrompt)
	stubOperatorEnrolled(t, false)
	refuseSubmits(t)
	origInvocation := operatorInvocation
	t.Cleanup(func() { operatorInvocation = origInvocation })
	operatorInvocation = nil
	dir := t.TempDir()
	t.Chdir(dir)
	return dir
}

// useOperatorInput is what the operator types at the terminal prompt.
func useOperatorInput(t *testing.T, typed string) {
	t.Helper()
	orig := operatorInput
	operatorInput = strings.NewReader(typed)
	t.Cleanup(func() { operatorInput = orig })
}

func claudeHook(t *testing.T, session, cwd, command string) (int, map[string]any, string) {
	t.Helper()
	raw, err := json.Marshal(map[string]any{
		"session_id": session, "hook_event_name": "PreToolUse", "cwd": cwd,
		"tool_name": "Bash", "tool_input": map[string]any{"command": command},
	})
	if err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	code := run([]string{"hook", "claude"}, bytes.NewReader(raw), &out, &errb)
	var decoded map[string]any
	_ = json.Unmarshal(out.Bytes(), &decoded)
	return code, decoded, errb.String()
}

func claudeDecision(payload map[string]any) (string, string) {
	specific, _ := payload["hookSpecificOutput"].(map[string]any)
	decision, _ := specific["permissionDecision"].(string)
	reason, _ := specific["permissionDecisionReason"].(string)
	return decision, reason
}

// runCLI runs a guardrail command the way the host runs an approved one:
// stdin is not a terminal.
func runCLI(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	code := run(args, strings.NewReader(""), &out, &errb)
	return code, out.String(), errb.String()
}

func operatorActionRecords(t *testing.T) []audit.Record {
	t.Helper()
	raw, err := os.ReadFile(audit.DefaultPath(""))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	var records []audit.Record
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		var rec audit.Record
		if json.Unmarshal([]byte(line), &rec) == nil && rec.Event == "operator-action" {
			records = append(records, rec)
		}
	}
	return records
}

func TestWindowsAndPOSIXApprovalModeProductionDefaultIsPrompt(t *testing.T) {
	if productionApprovalDefault != policy.ApprovalPrompt {
		t.Fatalf("an Operator config without `approval` must mean %q in production, got %q", policy.ApprovalPrompt, productionApprovalDefault)
	}
	if got := approvalModeOf(nil, errors.New("unparseable")); got != policy.ApprovalPasskey {
		t.Fatalf("an unreadable Operator config resolves to %q, want the stronger %q", got, policy.ApprovalPasskey)
	}
	if got := approvalModeOf(&policy.OperatorConfig{Approval: policy.ApprovalPrompt}, nil); got != policy.ApprovalPrompt {
		t.Fatalf("explicit prompt resolves to %q", got)
	}
	if got := approvalModeOf(&policy.OperatorConfig{Approval: policy.ApprovalPasskey}, nil); got != policy.ApprovalPasskey {
		t.Fatalf("explicit passkey resolves to %q", got)
	}
}

// Every rewrite of waivers.toml (grant consumption runs in the hook) must keep
// the operator's choice; dropping it would silently downgrade passkey users.
func TestWindowsAndPOSIXOperatorConfigRewritesPreserveApprovalKey(t *testing.T) {
	driftSandbox(t)
	useApprovalMode(t, policy.ApprovalPasskey)
	repo := t.TempDir()
	steps := map[string]func() error{
		"web-research": func() error { return setWebResearchEnforcement("off") },
		"global host":  func() error { return applyGlobalWebHost("docs.example.com", true) },
		"command grant": func() error {
			return mutateCommandGrants(repo, func(existing []policy.CommandGrant) []policy.CommandGrant {
				return append(existing, policy.CommandGrant{RuleID: "P2.git-push-protected", Command: "git push origin main", Uses: 1, ExpiresAt: time.Now().Add(time.Hour)})
			})
		},
	}
	for name, step := range steps {
		if err := step(); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		op, err := policy.LoadOperatorConfig()
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if op.Approval != policy.ApprovalPasskey {
			t.Fatalf("%s rewrote waivers.toml and dropped approval = passkey", name)
		}
	}
}

func TestWindowsAndPOSIXHookPromptModeAsksAndRecordsATicket(t *testing.T) {
	dir := promptSandbox(t)
	code, payload, errb := claudeHook(t, "s1", dir, "guardrail plane enable claude")
	decision, reason := claudeDecision(payload)
	if code != 0 || decision != "ask" {
		t.Fatalf("code=%d decision=%q stderr=%q; want the native ask", code, decision, errb)
	}
	for _, want := range []string{"register guardrail on the claude plane", "guardrail plane enable claude"} {
		if !strings.Contains(reason, want) {
			t.Fatalf("ask reason %q does not name %q", reason, want)
		}
	}
	if !approval.PeekTicket("guardrail plane enable claude", dir, time.Now()) {
		t.Fatal("the ask must record a ticket for the approved run")
	}
}

func TestWindowsAndPOSIXHookPasskeyModeKeepsTheSelfConfigDeny(t *testing.T) {
	dir := promptSandbox(t)
	useApprovalMode(t, policy.ApprovalPasskey)
	code, _, errb := claudeHook(t, "s1", dir, "guardrail plane enable claude")
	if code != 2 || !strings.Contains(errb, "P5.self-config") {
		t.Fatalf("code=%d stderr=%q; passkey mode must keep today's P5 deny", code, errb)
	}
	if approval.PeekTicket("guardrail plane enable claude", dir, time.Now()) {
		t.Fatal("passkey mode must never record a ticket")
	}
}

func TestWindowsAndPOSIXHookPromptModeCodexDeniesAndNamesTheTerminalCommand(t *testing.T) {
	dir := promptSandbox(t)
	raw, _ := json.Marshal(map[string]any{
		"hook_event_name": "PreToolUse", "session_id": "s1", "cwd": dir,
		"tool_name": "Bash", "tool_input": map[string]any{"command": "guardrail recover claude-settings"},
	})
	var out, errb bytes.Buffer
	code := run([]string{"hook", "codex"}, bytes.NewReader(raw), &out, &errb)
	if code != 2 || !strings.Contains(errb.String(), "guardrail recover claude-settings") || !strings.Contains(errb.String(), "terminal") {
		t.Fatalf("code=%d stderr=%q; want a deny naming the command to run in a terminal", code, errb.String())
	}
	if approval.PeekTicket("guardrail recover claude-settings", dir, time.Now()) {
		t.Fatal("a plane that cannot ask must not record a ticket")
	}
}

func TestWindowsAndPOSIXHookPromptModeAntigravityForceAsks(t *testing.T) {
	dir := promptSandbox(t)
	raw, _ := json.Marshal(map[string]any{"conversationId": "c1", "toolCall": map[string]any{"name": "run_command", "args": map[string]any{"CommandLine": "guardrail night off", "Cwd": dir}}})
	var out, errb bytes.Buffer
	code := run([]string{"hook", "antigravity", "pre"}, bytes.NewReader(raw), &out, &errb)
	var got map[string]any
	_ = json.Unmarshal(out.Bytes(), &got)
	if code != 0 || got["decision"] != "force_ask" {
		t.Fatalf("code=%d stdout=%q; want force_ask", code, out.String())
	}
	if !approval.PeekTicket("guardrail night off", dir, time.Now()) {
		t.Fatal("the force_ask must record a ticket")
	}
}

func TestWindowsAndPOSIXHookPromptModeOpencodeNeedsHostEvidence(t *testing.T) {
	dir := promptSandbox(t)
	hook := func(hostApproved bool) (int, map[string]any) {
		payload := map[string]any{"session_id": "s1", "event": "pre", "tool": "bash", "cwd": dir,
			"command": "guardrail web-research off", "arguments": map[string]any{"command": "guardrail web-research off"}}
		if hostApproved {
			payload["host_approved"] = true
			payload["call_id"] = "call-1"
		}
		raw, _ := json.Marshal(payload)
		var out, errb bytes.Buffer
		code := run([]string{"hook", "opencode"}, bytes.NewReader(raw), &out, &errb)
		var got map[string]any
		_ = json.Unmarshal(out.Bytes(), &got)
		return code, got
	}
	if _, got := hook(false); got["decision"] != "ask" || approval.PeekTicket("guardrail web-research off", dir, time.Now()) {
		t.Fatalf("without host evidence: decision=%v; want ask and no ticket", got["decision"])
	}
	if _, got := hook(false); got["decision"] != "ask" {
		t.Fatalf("an exact retry must not self-approve an operator action: %v", got)
	}
	if code, got := hook(true); code != 0 || got["decision"] != "allow" || !approval.PeekTicket("guardrail web-research off", dir, time.Now()) {
		t.Fatalf("with host evidence: code=%d decision=%v; want allow and a ticket", code, got["decision"])
	}
}

func TestWindowsAndPOSIXHookPromptModeTicketIsVoidedByTheSessionsNextCall(t *testing.T) {
	dir := promptSandbox(t)
	claudeHook(t, "s1", dir, "guardrail plane disable claude")
	claudeHook(t, "s2", dir, "ls")
	if !approval.PeekTicket("guardrail plane disable claude", dir, time.Now()) {
		t.Fatal("another session's call must not void the ticket")
	}
	claudeHook(t, "s1", dir, "ls")
	if approval.PeekTicket("guardrail plane disable claude", dir, time.Now()) {
		t.Fatal("the same session's next call must void the ticket")
	}
}

// The design problem: after the host's ask, the command runs without a TTY.
func TestWindowsAndPOSIXPromptModeHostApprovedRunAppliesOnceWithTheTicket(t *testing.T) {
	dir := promptSandbox(t)
	enableForDrift(t, "claude")
	useInstalledPlanes(t, "claude")

	// Without a ask first, a TTY-less disable is refused (exit 3, as today).
	if code, _, errb := runCLI(t, "plane", "disable", "claude"); code != exitOperatorActionPending || !planeIntegrationRegistered("claude") {
		t.Fatalf("no ticket, no TTY: exit=%d stderr=%q; want 3 and nothing changed", code, errb)
	}
	claudeHook(t, "s1", dir, "guardrail plane disable claude")
	code, out, errb := runCLI(t, "plane", "disable", "claude")
	if code != 0 || planeIntegrationRegistered("claude") {
		t.Fatalf("host-approved run: exit=%d stdout=%q stderr=%q; want the plane disabled", code, out, errb)
	}
	records := operatorActionRecords(t)
	if len(records) == 0 || records[len(records)-1].Transport != "host-ask" || records[len(records)-1].OperatorAction != "plane-disable" {
		t.Fatalf("audit = %+v; want a plane-disable completed via host-ask", records)
	}
	// Replay: the ticket is spent.
	enableForDrift(t, "claude")
	if code, _, _ := runCLI(t, "plane", "disable", "claude"); code != exitOperatorActionPending || !planeIntegrationRegistered("claude") {
		t.Fatalf("replayed run: exit=%d; want 3 and the plane still registered", code)
	}
}

func TestWindowsAndPOSIXPromptModeTicketDoesNotTravelToAnotherDirectory(t *testing.T) {
	dir := promptSandbox(t)
	enableForDrift(t, "claude")
	useInstalledPlanes(t, "claude")
	claudeHook(t, "s1", dir, "guardrail plane disable claude")
	t.Chdir(t.TempDir())
	if code, _, _ := runCLI(t, "plane", "disable", "claude"); code != exitOperatorActionPending || !planeIntegrationRegistered("claude") {
		t.Fatalf("exit=%d; a ticket bound to another directory must not approve this run", code)
	}
}

func TestWindowsAndPOSIXPromptModeTerminalAsksYesNo(t *testing.T) {
	promptSandbox(t)
	enableForDrift(t, "claude")
	useInstalledPlanes(t, "claude")
	for _, answer := range []string{"", "n\n", "no\n", "maybe\n"} {
		useOperatorInput(t, answer)
		var out, errb bytes.Buffer
		code := cmdPlane([]string{"disable", "claude"}, true, &out, &errb)
		if code != exitOperatorActionPending || !planeIntegrationRegistered("claude") {
			t.Fatalf("answer %q: exit=%d; want 3 and nothing changed (default No)", answer, code)
		}
		if !strings.Contains(out.String(), "Approve remove guardrail from planes: claude? [y/N] ") {
			t.Fatalf("answer %q: prompt missing from stdout %q", answer, out.String())
		}
	}
	useOperatorInput(t, "y\n")
	var out, errb bytes.Buffer
	if code := cmdPlane([]string{"disable", "claude"}, true, &out, &errb); code != 0 || planeIntegrationRegistered("claude") {
		t.Fatalf("answer y: exit=%d stdout=%q stderr=%q; want the plane disabled", code, out.String(), errb.String())
	}
	records := operatorActionRecords(t)
	if len(records) == 0 || records[len(records)-1].Transport != "terminal-prompt" {
		t.Fatalf("audit = %+v; want the terminal-prompt transport", records)
	}
}

func TestWindowsAndPOSIXPromptModeTerminalSetupAsksFirst(t *testing.T) {
	promptSandbox(t)
	useInstalledPlanes(t, "claude")
	stubSetupGates(t, false, 0, 0)
	useOperatorInput(t, "n\n")
	code, out, _ := runSetup(t, "--planes", "claude")
	if code != exitOperatorActionPending || planeIntegrationRegistered("claude") {
		t.Fatalf("declined setup: exit=%d; want 3 and nothing registered\n%s", code, out)
	}
	if !strings.Contains(out, "Approve register guardrail on planes: claude? [y/N] ") {
		t.Fatalf("setup did not ask on the terminal:\n%s", out)
	}
	useOperatorInput(t, "Y\n")
	if code, out, errb := runSetup(t, "--planes", "claude"); code != 0 || !planeIntegrationRegistered("claude") {
		t.Fatalf("approved setup: exit=%d stdout=%q stderr=%q", code, out, errb)
	}
}

// ADR-0030 still arms a fresh machine unattended: no terminal, no ticket and
// nobody enrolled is the bootstrap, and it can only tighten.
func TestWindowsAndPOSIXPromptModeUnattendedFirstInstallStillBootstraps(t *testing.T) {
	promptSandbox(t)
	useInstalledPlanes(t, "claude")
	stubSetupGates(t, false, 0, 0)
	var out, errb bytes.Buffer
	if code := cmdSetup([]string{"--planes", "claude"}, false, &out, &errb); code != 0 || !planeIntegrationRegistered("claude") {
		t.Fatalf("exit=%d stdout=%q stderr=%q; want the bootstrap", code, out.String(), errb.String())
	}
	if !strings.Contains(out.String(), "setup: planes armed without an approval because nobody was asked.") || strings.Contains(out.String(), "guardrail operator enroll") {
		t.Fatalf("prompt-mode bootstrap must not send the operator to enroll a passkey:\n%s", out.String())
	}
	out.Reset()
	errb.Reset()
	if code := cmdSetup([]string{"--planes", "claude", "--state", "disabled"}, false, &out, &errb); code != exitOperatorActionPending || !planeIntegrationRegistered("claude") {
		t.Fatalf("unattended disable: exit=%d; want 3 and nothing loosened", code)
	}
}

func TestWindowsAndPOSIXPromptModeRecoverEgressAndNightUseTheTicket(t *testing.T) {
	dir := promptSandbox(t)
	if err := os.MkdirAll(filepath.Join(dir, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	enableForDrift(t, "claude")

	claudeHook(t, "s1", dir, "guardrail recover claude-settings")
	if code, out, errb := runCLI(t, "recover", "claude-settings"); code != 0 || !strings.Contains(out, "claude-settings recovered") {
		t.Fatalf("recover: exit=%d stdout=%q stderr=%q", code, out, errb)
	}

	claudeHook(t, "s1", dir, "guardrail egress grant --scope global --host docs.example.com")
	if code, out, errb := runCLI(t, "egress", "grant", "--scope", "global", "--host", "docs.example.com"); code != 0 {
		t.Fatalf("egress: exit=%d stdout=%q stderr=%q", code, out, errb)
	}
	if op, err := policy.LoadOperatorConfig(); err != nil || !op.AllowsGlobalWebHost("docs.example.com") {
		t.Fatalf("egress grant not applied: %v", err)
	}

	claudeHook(t, "s1", dir, "guardrail night on --until 07:30")
	if code, out, errb := runCLI(t, "night", "on", "--until", "07:30"); code != 0 || !strings.Contains(out, "NIGHT MODE") {
		t.Fatalf("night on: exit=%d stdout=%q stderr=%q", code, out, errb)
	}
	if code, _, _ := runCLI(t, "night", "off"); code != 2 {
		t.Fatalf("night off without a ticket: exit=%d, want today's 2", code)
	}
	for _, rec := range operatorActionRecords(t) {
		if rec.Decision == "completed" && rec.Transport != "host-ask" {
			t.Fatalf("completed record %+v not attributed to host-ask", rec)
		}
	}
}

func TestWindowsAndPOSIXPromptModeNextStepsAskForThePromptNotAPasskey(t *testing.T) {
	promptSandbox(t)
	useInstalledPlanes(t, "claude")
	steps, err := nextSteps()
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(steps, "\n")
	if !strings.Contains(joined, "claude: not registered; enabling. Run `guardrail plane enable claude` from an interactive terminal and answer its prompt.") {
		t.Fatalf("next steps = %q", joined)
	}
	if strings.Contains(joined, "operator enroll") || strings.Contains(joined, "passkey") {
		t.Fatalf("prompt mode must not ask for a passkey: %q", joined)
	}
}

func TestWindowsAndPOSIXDoctorShowsApprovalMode(t *testing.T) {
	for _, mode := range []string{policy.ApprovalPrompt, policy.ApprovalPasskey} {
		promptSandbox(t)
		useApprovalMode(t, mode)
		var out, errb bytes.Buffer
		cmdDoctor(nil, &out, &errb)
		if !strings.Contains(out.String(), "approval mode: "+mode) {
			t.Fatalf("doctor output lacks %q:\n%s", "approval mode: "+mode, out.String())
		}
	}
}
