package main

import (
	"fmt"
	"io"
	"time"

	"github.com/CtrlCarlitos/agent-guardrails/internal/actiongrant"
	"github.com/CtrlCarlitos/agent-guardrails/internal/approval"
	"github.com/CtrlCarlitos/agent-guardrails/internal/audit"
	"github.com/CtrlCarlitos/agent-guardrails/internal/engine"
	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
)

const exactActionGrant = "exact-action-grant"

func exactActionVerdict(tc engine.ToolCall, v policy.Verdict) (policy.Verdict, bool, error) {
	action, eligible := engine.ExactGrantAction(tc, v)
	if !eligible {
		return v, false, nil
	}
	store, err := actiongrant.Default()
	if err != nil {
		return v, false, err
	}
	req, spent, err := store.Consume(action, time.Now())
	if err != nil {
		return v, false, err
	}
	if spent {
		return policy.Verdict{Decision: policy.Allow, RuleID: engine.GrantRuleID, OriginRuleID: v.RuleID, RequestID: req.ID, Reason: "allowed once by an operator-issued grant for this exact action"}, true, nil
	}
	req, err = store.Create(action, time.Now())
	if err != nil {
		return v, false, err
	}
	v.RequestID = req.ID
	return v, false, nil
}

func init() { approval.RegisterAction(exactActionGrant, executeExactActionGrant) }

func executeExactActionGrant(r approval.Request) error {
	s, err := actiongrant.Default()
	if err != nil {
		return err
	}
	id, digest := r.Parameters["record"], r.Parameters["digest"]
	pending, err := s.Read(id, time.Now())
	if err != nil {
		return err
	}
	if pending.Digest != digest || pending.Action.Repo != r.RepoRoot {
		return fmt.Errorf("action request no longer matches")
	}
	if r.Transport != "webauthn" || r.CredentialFingerprint == "" {
		return fmt.Errorf("action grant requires an authenticated broker completion")
	}
	return s.AuthorizeWithAudit(id, digest, r.Transport, time.Now(), func(record actiongrant.Request) error {
		return writeActionGrantAudit("grant-issued", record, r.Transport, r.CredentialFingerprint)
	})
}

func writeActionGrantAudit(event string, r actiongrant.Request, transport, fingerprint string) error {
	return audit.Write(audit.Record{TS: time.Now().UTC().Format(time.RFC3339Nano), Plane: "operator", Tool: "guardrail approvals", Event: "operator", RepoRoot: r.Action.Repo, Decision: "allow", RuleID: r.Action.Rule, OperatorAction: event, RequestID: r.ID, Transport: transport, CredentialFingerprint: fingerprint, Reason: "exact-action authorization (digest " + r.Digest + ")"}, audit.DefaultPath(""))
}

func cmdRecordGrant(args []string, terminal bool, input io.Reader, stdout, stderr io.Writer) int {
	if !terminal {
		fmt.Fprintln(stderr, "guardrail: approvals grant --record requires an interactive local terminal")
		return 2
	}
	if len(args) != 2 || args[0] != "--record" {
		fmt.Fprintln(stderr, "guardrail: use approvals grant --record <id>; record approvals authorize one retry for 15 minutes")
		return 2
	}
	s, err := actiongrant.Default()
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	r, err := s.Read(args[1], time.Now())
	if err != nil || r.Status != "pending" {
		fmt.Fprintf(stderr, "guardrail: action request is not pending: %v\n", err)
		return 1
	}
	fmt.Fprintln(stdout, r.Summary())
	if promptApprovalMode() {
		fmt.Fprint(stdout, "Type yes to authorize this exact action: ")
		if !confirmGrant(input, stdout) {
			fmt.Fprintln(stderr, "guardrail: not authorized; nothing was recorded")
			return 1
		}
		if err := s.AuthorizeWithAudit(r.ID, r.Digest, transportTerminalPrompt, time.Now(), func(record actiongrant.Request) error {
			return writeActionGrantAudit("grant-issued", record, transportTerminalPrompt, "")
		}); err != nil {
			fmt.Fprintf(stderr, "guardrail: authorization failed (%v)\n", err)
			return 1
		}
		fmt.Fprintln(stdout, "authorized for one identical retry")
		return 0
	}
	if !operatorEnrolled() {
		fmt.Fprintln(stderr, "guardrail: no operator authenticator is enrolled; enroll from your terminal before approving")
		return 3
	}
	req := approval.Request{Plane: "operator", SessionID: "terminal", RepoRoot: r.Action.Repo, Scope: approval.OnceScope, Reason: "authorize exact action " + r.Digest, Action: exactActionGrant, Parameters: map[string]string{"record": r.ID, "digest": r.Digest}, ExpiresAt: r.Expires}
	created, err := approval.SubmitOnDemand(req)
	if err != nil {
		fmt.Fprintf(stderr, "guardrail: approval could not start: %v\n", err)
		return 3
	}
	fmt.Fprintf(stdout, "approval pending: %s\n%s\n", created.ID, created.ApprovalURL)
	return cmdApprovalsWait(created.ID, stdout, stderr)
}

func cmdRecordRevoke(args []string, terminal bool, stdout, stderr io.Writer) int {
	if !terminal || len(args) != 2 || args[0] != "--record" {
		fmt.Fprintln(stderr, "guardrail: approvals revoke --record <id> requires an interactive local terminal")
		return 2
	}
	s, err := actiongrant.Default()
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	r, err := s.Read(args[1], time.Now())
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	if err := s.Revoke(r.ID, time.Now()); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	if err := writeActionGrantAudit("grant-revoked", r, transportTerminalPrompt, ""); err != nil {
		fmt.Fprintf(stderr, "guardrail: action revoked, but audit failed: %v\n", err)
		return 1
	}
	fmt.Fprintln(stdout, "revoked")
	return 0
}
