package main

import (
	"bytes"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/CtrlCarlitos/agent-guardrails/internal/audit"
	"github.com/CtrlCarlitos/agent-guardrails/internal/daemon"
	"github.com/CtrlCarlitos/agent-guardrails/internal/engine"
	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
)

func TestCmdDaemonStatusNotRunning(t *testing.T) {
	var stdout, stderr bytes.Buffer
	endpoint := daemon.TestEndpoint(t, t.TempDir()) + "-missing"
	code := cmdDaemon([]string{"status", "--endpoint", endpoint}, &stdout, &stderr)
	if code == 0 {
		t.Fatalf("status on non-running pipe returned 0, want non-zero")
	}
	if !strings.Contains(stderr.String(), "not running") && !strings.Contains(stdout.String(), "not running") {
		t.Errorf("expected 'not running' in output, got stdout=%q, stderr=%q", stdout.String(), stderr.String())
	}
}

func TestCmdDaemonLifecycleRoundTrip(t *testing.T) {
	endpoint := daemon.TestEndpoint(t, t.TempDir())
	var out, errb bytes.Buffer

	// Start daemon in background goroutine
	done := make(chan int, 1)
	go func() {
		var sOut, sErr bytes.Buffer
		done <- cmdDaemon([]string{"start", "--endpoint", endpoint, "--idle", "5s"}, &sOut, &sErr)
	}()

	time.Sleep(150 * time.Millisecond)

	// Check status
	out.Reset()
	errb.Reset()
	code := cmdDaemon([]string{"status", "--endpoint", endpoint}, &out, &errb)
	if code != 0 {
		t.Fatalf("status returned %d: %s", code, errb.String())
	}
	if !strings.Contains(out.String(), "running") {
		t.Fatalf("status output = %q, want 'running'", out.String())
	}

	// Stop daemon
	out.Reset()
	errb.Reset()
	code = cmdDaemon([]string{"stop", "--endpoint", endpoint}, &out, &errb)
	if code != 0 {
		t.Fatalf("stop returned %d: %s", code, errb.String())
	}

	select {
	case exitCode := <-done:
		if exitCode != 0 {
			t.Errorf("daemon start exited with %d", exitCode)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("daemon did not exit after stop command")
	}
}

func TestCmdDaemonEvaluationWritesNamedPipeTransportAuditRecord(t *testing.T) {
	tempDir := t.TempDir()
	endpoint := daemon.TestEndpoint(t, tempDir)
	t.Setenv("LOCALAPPDATA", tempDir)
	t.Setenv("XDG_STATE_HOME", tempDir)

	done := make(chan int, 1)
	go func() {
		var sOut, sErr bytes.Buffer
		done <- cmdDaemon([]string{"start", "--endpoint", endpoint, "--idle", "5s"}, &sOut, &sErr)
	}()

	time.Sleep(150 * time.Millisecond)

	client, err := daemon.Dial(endpoint)
	if err != nil {
		t.Fatalf("Dial failed: %v", err)
	}

	tc := engine.ToolCall{
		Plane:      "opencode",
		Event:      "pre",
		Tool:       "todowrite",
		NativeTool: "todowrite",
		SessionID:  "session-test",
		CWD:        tempDir,
		RepoRoot:   tempDir,
	}
	v, err := client.Evaluate(tc)
	if err != nil {
		t.Fatalf("Evaluate failed: %v", err)
	}
	if v.Decision != policy.Allow {
		t.Fatalf("Evaluate returned %v, want allow", v.Decision)
	}

	_ = client.Shutdown()
	_ = client.Close()
	<-done

	auditFile := audit.DefaultPath("")
	raw, err := os.ReadFile(auditFile)
	if err != nil {
		t.Fatalf("read audit file: %v", err)
	}
	if !strings.Contains(string(raw), `"transport":"named-pipe-daemon"`) {
		t.Fatalf("audit record missing transport:named-pipe-daemon:\n%s", string(raw))
	}
}
