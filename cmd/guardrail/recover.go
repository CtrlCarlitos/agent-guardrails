package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/CtrlCarlitos/agent-guardrails/internal/approval"
)

func init() {
	approval.RegisterAction("recover", executeRecoverApproval)
}

var recoverRepairs = map[string]string{
	"claude-settings":   "claude",
	"opencode-config":   "opencode",
	"antigravity-hooks": "antigravity",
}

// executeRecoverApproval applies a predefined protected-machinery repair:
// timestamped backup first; an unparseable file is reset and the Guardrail
// integration re-registered; a parseable file is repaired in place with
// user configuration preserved. No agent-supplied content is ever executed.
func executeRecoverApproval(r approval.Request) error {
	plane, known := recoverRepairs[r.Parameters["repair"]]
	if r.Action != "recover" || !known {
		return fmt.Errorf("invalid approved recover action")
	}
	alreadyCompleted, err := startActionAudit(r)
	if err != nil {
		return err
	}
	if alreadyCompleted {
		return nil
	}
	path, err := planeConfigPath(plane)
	if err != nil {
		return err
	}
	if err := backupForRecovery(path); err != nil {
		return err
	}
	if !jsonFileParses(path) {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(path, []byte("{}\n"), 0o600); err != nil {
			return err
		}
	}
	if err := enablePlaneIntegration(plane); err != nil {
		return err
	}
	_ = completeActionAudit(r)
	return nil
}

func jsonFileParses(path string) bool {
	raw, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	var doc map[string]any
	return json.Unmarshal(raw, &doc) == nil && doc != nil
}

func backupForRecovery(path string) error {
	raw, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	backup := fmt.Sprintf("%s.guardrail-recover-%s", path, time.Now().UTC().Format("20060102-150405"))
	return os.WriteFile(backup, raw, 0o600)
}

func cmdRecover(args []string, terminal bool, stdout, stderr io.Writer) int {
	if len(args) != 1 || recoverRepairs[args[0]] == "" {
		fmt.Fprintln(stderr, "guardrail: recover needs one known repair (claude-settings, opencode-config, antigravity-hooks)")
		return 2
	}
	if !terminal {
		fmt.Fprintln(stderr, "guardrail: recover requires an interactive local terminal")
		return 2
	}
	repair := args[0]

	cwd, _ := os.Getwd()
	created, err := submitPlaneRequest(approval.Request{
		Plane:      "operator",
		SessionID:  "terminal",
		RepoRoot:   cwd,
		Scope:      approval.GlobalScope,
		Reason:     "operator terminal recovery",
		Action:     "recover",
		Parameters: map[string]string{"repair": repair},
	})
	if err != nil {
		fmt.Fprintf(stderr, "guardrail: %s: approval request failed: %v\n", repair, err)
		return 1
	}
	fmt.Fprintf(stdout, "%s: approval required; open %s\n", repair, created.ApprovalURL)

	deadline := time.Now().Add(5 * time.Minute)
	if created.ExpiresAt.After(time.Now()) && created.ExpiresAt.Before(deadline) {
		deadline = created.ExpiresAt
	}
	for time.Now().Before(deadline) {
		time.Sleep(500 * time.Millisecond)
		status, err := queryPlaneStatus(approval.DefaultSocketPath(), created.ID)
		if err != nil {
			fmt.Fprintf(stderr, "guardrail: %s: approval daemon unavailable\n", repair)
			return 1
		}
		switch status.Status {
		case "approved", "completed":
			fmt.Fprintf(stdout, "%s recovered\n", repair)
			return 0
		case "denied", "expired":
			fmt.Fprintf(stderr, "guardrail: %s: recover %s\n", repair, status.Status)
			return 1
		}
	}
	fmt.Fprintf(stderr, "guardrail: %s: recover approval expired\n", repair)
	return 1
}
