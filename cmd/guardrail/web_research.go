package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/CtrlCarlitos/agent-guardrails/internal/approval"
	"github.com/CtrlCarlitos/agent-guardrails/internal/audit"
	"github.com/CtrlCarlitos/agent-guardrails/internal/genconfig"
	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
	"github.com/gofrs/flock"
)

var submitWebResearchRequest = approval.SubmitOnDemand
var queryWebResearchStatus = approval.QueryStatus

// Fresh-install defaults are not authenticated operator actions. Keep their
// audit event and writer distinct from the approval action journal.
var writeWebResearchDefaultAudit = audit.Write

func init() { approval.RegisterAction("web-research-set", executeWebResearchApproval) }

func webResearchPosture(off bool) string {
	if off {
		return "web-research enforcement: off; native research outbound data and destinations are not enforced (other protections unchanged)"
	}
	return "web-research enforcement: on (strict)"
}

func cmdWebResearch(args []string, terminal bool, stdout, stderr io.Writer) int {
	if len(args) != 1 || (args[0] != "status" && args[0] != "on" && args[0] != "off") {
		fmt.Fprintln(stderr, "usage: guardrail web-research on|off|status (on means strict enforcement)")
		return 2
	}
	mode := args[0]
	if mode != "status" && !terminal {
		fmt.Fprintln(stderr, "guardrail: web-research changes require an interactive local terminal")
		return 2
	}
	op, err := policy.LoadOperatorConfig()
	if err != nil {
		fmt.Fprintln(stderr, "guardrail: operator config unreadable; web-research enforcement remains strict")
		return 1
	}
	if mode == "status" {
		fmt.Fprintln(stdout, webResearchPosture(op.WebResearchEnforcement == "off"))
		return 0
	}
	if !requireOperatorEnrolled("guardrail web-research "+mode, stderr) {
		return exitNotEnrolled
	}
	cwd, err := os.Getwd()
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	r, err := submitWebResearchRequest(approval.Request{
		Plane: "operator", SessionID: "terminal", RepoRoot: cwd, Scope: approval.GlobalScope,
		Action: "web-research-set", Reason: "operator-selected native web-research enforcement",
		Parameters: map[string]string{"enforcement": mode},
	})
	if err != nil {
		fmt.Fprintf(stderr, "guardrail: web-research approval failed: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "web-research enforcement %s: approval required; open %s\n", mode, r.ApprovalURL)
	deadline := time.Now().Add(5 * time.Minute)
	if !r.ExpiresAt.IsZero() && r.ExpiresAt.Before(deadline) {
		deadline = r.ExpiresAt
	}
	for time.Now().Before(deadline) {
		status, err := queryWebResearchStatus(approval.DefaultSocketPath(), r.ID)
		if err != nil {
			fmt.Fprintln(stderr, "guardrail: web-research approval daemon unavailable")
			return 1
		}
		switch status.Status {
		case "completed":
			current, err := policy.LoadOperatorConfig()
			if err != nil || current.WebResearchEnforcement != mode {
				fmt.Fprintln(stderr, "guardrail: approved web-research setting did not converge")
				return 1
			}
			fmt.Fprintln(stdout, webResearchPosture(mode == "off"))
			return 0
		case "denied", "expired", "failed":
			fmt.Fprintf(stderr, "guardrail: web-research approval %s\n", status.Status)
			return 1
		}
		time.Sleep(500 * time.Millisecond)
	}
	fmt.Fprintln(stderr, "guardrail: web-research approval timed out; inspect pending requests before retrying")
	return 1
}

func executeWebResearchApproval(r approval.Request) error {
	mode := r.Parameters["enforcement"]
	if r.Action != "web-research-set" || r.Plane != "operator" || r.Scope != approval.GlobalScope || len(r.Parameters) != 1 || (mode != "on" && mode != "off") {
		return fmt.Errorf("invalid approved web-research action")
	}
	done, err := startActionAudit(r)
	if err != nil || done {
		return err
	}
	if err := setWebResearchEnforcement(mode); err != nil {
		return err
	}
	// The approved mutation is durable. As with plane changes, completion
	// audit recovery must not relabel an applied change as a denied request.
	_ = completeActionAudit(r)
	return nil
}

func setWebResearchEnforcement(mode string) error {
	if mode != "on" && mode != "off" {
		return fmt.Errorf("invalid web-research enforcement")
	}
	return mutateWebResearchConfig(func(op *policy.OperatorConfig) bool {
		op.WebResearchEnforcement = mode
		return true
	})
}

func mutateWebResearchConfig(mutate func(*policy.OperatorConfig) bool) error {
	dir, err := allowanceJournalDir()
	if err != nil {
		return err
	}
	if err := ensureAllowanceDir(dir); err != nil {
		return err
	}
	lock := flock.New(filepath.Join(dir, "operator.lock"), flock.SetPermissions(0o600))
	if err := lock.Lock(); err != nil {
		return err
	}
	defer lock.Unlock()
	if err := recoverAllowanceJournals(dir); err != nil {
		return err
	}
	op, err := policy.LoadOperatorConfig()
	if err != nil {
		return err
	}
	if !mutate(op) {
		return nil
	}
	raw, err := operatorConfigContent(op)
	if err != nil {
		return err
	}
	path := policy.OperatorConfigPath()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	if err := securePrivateDir(filepath.Dir(path)); err != nil {
		return err
	}
	return writeSyncedPrivateFile(path, raw, 0o600)
}

// Absence of waivers.toml alone is NOT first-install evidence. Older installs
// often have no grants. Any existing config/state or legacy integration keeps
// strict mode. Only setup can claim an entirely new Operator config directory.
func initializeWebResearchDefault(stdout io.Writer) error {
	dir, err := policy.OperatorConfigDir()
	if err != nil {
		return err
	}
	if _, err := os.Lstat(dir); !os.IsNotExist(err) {
		return nil
	}
	manifestDir, err := genconfig.ManifestDir()
	if err != nil {
		return err
	}
	if _, err := os.Lstat(filepath.Dir(manifestDir)); !os.IsNotExist(err) {
		return nil
	}
	for _, plane := range supportedPlanes {
		path, err := planeConfigPath(plane)
		if err != nil {
			return err
		}
		raw, err := os.ReadFile(path)
		if err != nil && !os.IsNotExist(err) {
			return nil
		}
		if err == nil {
			var config map[string]any
			if json.Unmarshal(raw, &config) != nil || config == nil {
				return nil
			}
		}
		if strings.Contains(strings.ToLower(string(raw)), "guardrail") {
			return nil
		}
	}
	if err := os.MkdirAll(filepath.Dir(dir), 0o700); err != nil {
		return err
	}
	if err := os.Mkdir(dir, 0o700); err != nil {
		if os.IsExist(err) {
			return nil
		}
		return err
	}
	if err := securePrivateDir(dir); err != nil {
		return err
	}
	// A failed initialization leaves the directory as conservative upgrade
	// evidence. It never retries the relaxed default over an existing install.
	if err := writeWebResearchDefaultAudit(audit.Record{Plane: "operator", Tool: "guardrail", Event: "installation-default", Decision: "requested", Transport: "bootstrap", Reason: "fresh installation default: web-research enforcement off"}, audit.DefaultPath("")); err != nil {
		fmt.Fprintln(stdout, "setup: cannot audit fresh web-research default; keeping strict enforcement")
		return nil
	}
	initialized := false
	if err := mutateWebResearchConfig(func(op *policy.OperatorConfig) bool {
		// Recheck under the shared operator-config lock: an explicit choice
		// or another authorization recorded concurrently takes precedence.
		if _, err := os.Lstat(policy.OperatorConfigPath()); !os.IsNotExist(err) {
			return false
		}
		op.WebResearchEnforcement = "off"
		initialized = true
		return true
	}); err != nil {
		return err
	}
	if !initialized {
		return nil
	}
	fmt.Fprintln(stdout, "setup: fresh installation default; "+webResearchPosture(true))
	return writeWebResearchDefaultAudit(audit.Record{Plane: "operator", Tool: "guardrail", Event: "installation-default", Decision: "completed", Transport: "bootstrap", Reason: "fresh installation default: web-research enforcement off"}, audit.DefaultPath(""))
}
