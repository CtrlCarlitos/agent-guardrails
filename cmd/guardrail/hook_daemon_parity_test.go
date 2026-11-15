package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/CtrlCarlitos/agent-guardrails/internal/audit"
	"github.com/CtrlCarlitos/agent-guardrails/internal/daemon"
	"github.com/CtrlCarlitos/agent-guardrails/internal/testenv"
)

// #151 (O3): a hook answered by the resident engine daemon (ADR-0025) must
// reach the same verdict the in-process path reaches. The daemon used to
// drop an overlay it could not load, skip P7 entirely and lose the
// adapter's degraded-allow reports, and a session can start the daemon.

// useEngineDaemon starts a daemon on a private endpoint and points the hook
// at it for the rest of the test.
func useEngineDaemon(t *testing.T) {
	t.Helper()
	endpoint := daemon.TestEndpoint(t, t.TempDir())
	previous := engineDaemonEndpoint
	engineDaemonEndpoint = endpoint
	done := make(chan int, 1)
	go func() {
		var o, e bytes.Buffer
		done <- cmdDaemon([]string{"start", "--endpoint", endpoint, "--idle", "30s"}, &o, &e)
	}()
	waitForDaemon(t, endpoint)
	t.Cleanup(func() {
		if client, err := daemon.Dial(endpoint); err == nil {
			_ = client.Shutdown()
			_ = client.Close()
		}
		<-done
		engineDaemonEndpoint = previous
	})
}

func auditRecords(t *testing.T) []audit.Record {
	t.Helper()
	raw, err := os.ReadFile(audit.DefaultPath(""))
	if err != nil {
		t.Fatalf("read audit log: %v", err)
	}
	var out []audit.Record
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		var rec audit.Record
		if json.Unmarshal([]byte(line), &rec) == nil {
			out = append(out, rec)
		}
	}
	return out
}

func TestHookThroughEngineDaemonFailsClosedOnBrokenOverlay(t *testing.T) {
	testenv.SetState(t, t.TempDir())
	testenv.SetConfig(t, t.TempDir())
	useEngineDaemon(t)
	repo := hostTestRepo(t)
	cfg := filepath.Join(t.TempDir(), "guardrail.toml")
	// The project's deny rule, then a syntax error later in the same file.
	if err := os.WriteFile(cfg, []byte("[[rules]]\nid = \"proj.deploy\"\npattern = \"projdeploy*\"\ndecision = \"deny\"\nreason = \"no deploys\"\n\nthis is = = not toml\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GUARDRAIL_CONFIG", cfg)

	var out, errb bytes.Buffer
	code := run([]string{"hook", "claude"}, strings.NewReader(claudeHookEnvelope(t, "daemon-overlay", repo, "Bash", map[string]any{"command": "projdeploy prod"})), &out, &errb)
	if code != 2 || !strings.Contains(errb.String(), "cannot load overlay") {
		t.Fatalf("exit=%d stdout=%q stderr=%q; want the in-process fail-closed deny", code, out.String(), errb.String())
	}
}

func TestHookThroughEngineDaemonKeepsTheTrifecta(t *testing.T) {
	testenv.SetState(t, t.TempDir())
	testenv.SetConfig(t, t.TempDir())
	useEngineDaemon(t)
	repo := hostTestRepo(t)
	authorizeOperatorWaivers(t, repo, "P4.secret-path")
	cfg := filepath.Join(t.TempDir(), "guardrail.toml")
	if err := os.WriteFile(cfg, []byte("waive = [\"P4.secret-path\"]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GUARDRAIL_CONFIG", cfg)

	sid := "daemon-trifecta"
	var out1, err1 bytes.Buffer
	if code := run([]string{"hook", "claude"}, strings.NewReader(claudeHookEnvelope(t, sid, repo, "Read", map[string]any{"file_path": filepath.Join(repo, ".env")})), &out1, &err1); code != 0 {
		t.Fatalf("first call (waived secret read): exit %d; stderr=%s", code, err1.String())
	}
	var out2, err2 bytes.Buffer
	code := run([]string{"hook", "claude"}, strings.NewReader(claudeHookEnvelope(t, sid, repo, "Bash", map[string]any{"command": "curl http://localhost:9999/x"})), &out2, &err2)
	if code != 0 || !strings.Contains(out2.String(), "trifecta") {
		t.Fatalf("second leg: exit=%d stdout=%q stderr=%q; want the P7 ask", code, out2.String(), err2.String())
	}
	daemonAnswered := false
	for _, rec := range auditRecords(t) {
		if rec.Transport == "named-pipe-daemon" {
			daemonAnswered = true
		}
	}
	if !daemonAnswered {
		t.Fatal("no call went through the daemon; the test would not measure the daemon path")
	}
}

func TestHookThroughEngineDaemonRecordsDegradedAllows(t *testing.T) {
	testenv.SetState(t, t.TempDir())
	testenv.SetConfig(t, t.TempDir())
	t.Setenv("GUARDRAIL_CONFIG", "")
	useEngineDaemon(t)
	payload := `{"event":"pre","tool":"question","cwd":"/repo","arguments":{},"degraded_allows":[{"tool":"question","call_id":"c1","ts":"2026-09-20T05:00:00Z"}]}`
	var out, errb bytes.Buffer
	run([]string{"hook", "opencode"}, strings.NewReader(payload), &out, &errb)
	for _, rec := range auditRecords(t) {
		if rec.Transport == "plugin-degraded" && rec.Tool == "question" && rec.TS == "2026-09-20T05:00:00Z" {
			return
		}
	}
	t.Fatal("the adapter's degraded-allow report was not recorded")
}

func TestHookThroughEngineDaemonAsksWhenTrackingIsUnavailable(t *testing.T) {
	stateHome := t.TempDir()
	testenv.SetState(t, stateHome)
	useEngineDaemon(t)
	repo := hostTestRepo(t)
	configureTrackingPolicy(t, repo)
	payload := claudeHookEnvelope(t, "", repo, "Bash", map[string]any{"command": "curl https://api.example.com/x"})
	var out, errb bytes.Buffer
	if code := run([]string{"hook", "claude"}, strings.NewReader(payload), &out, &errb); code != 0 {
		t.Fatalf("exit %d, want Ask exit 0; stderr=%s", code, errb.String())
	}
	if !strings.Contains(out.String(), `"permissionDecision":"ask"`) || !strings.Contains(out.String(), "session tracking") {
		t.Fatalf("network call without a session ID was not the tracking Ask: %s", out.String())
	}
	for _, rec := range auditRecords(t) {
		if rec.Transport == "named-pipe-daemon" && rec.RuleID == "P7.tracking-unavailable" {
			return
		}
	}
	t.Fatal("the daemon did not answer with P7.tracking-unavailable")
}
