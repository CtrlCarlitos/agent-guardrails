//go:build !windows

package adversarial

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/CtrlCarlitos/agent-guardrails/internal/approval"
)

func TestApprovalDaemonBinaryCompletesAdversarialNightRequest(t *testing.T) {
	bin := buildAdversarialBinary(t)
	stateHome := t.TempDir()
	configHome := t.TempDir()
	t.Setenv("XDG_STATE_HOME", stateHome)
	t.Setenv("XDG_CONFIG_HOME", configHome)
	daemon := exec.Command(bin, "approvals", "daemon")
	daemon.Env = append(os.Environ(), "XDG_STATE_HOME="+stateHome, "XDG_CONFIG_HOME="+configHome)
	if err := daemon.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = daemon.Process.Signal(syscall.SIGTERM)
		_ = daemon.Wait()
	})

	socket := approval.DefaultSocketPath()
	deadline := time.Now().Add(time.Second)
	for {
		info, err := os.Stat(filepath.Dir(socket))
		if err == nil {
			if info.Mode().Perm() != 0o700 {
				t.Fatalf("socket directory mode = %o, want 0700", info.Mode().Perm())
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("daemon did not create socket directory: %v", err)
		}
		time.Sleep(10 * time.Millisecond)
	}

	repo := t.TempDir()
	if err := os.Mkdir(filepath.Join(repo, ".git"), 0o700); err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(map[string]any{
		"session_id":      "adversarial-night-request",
		"cwd":             repo,
		"hook_event_name": "PreToolUse",
		"tool_name":       "Bash",
		"tool_input":      map[string]string{"command": "guardrail night off"},
	})
	if err != nil {
		t.Fatal(err)
	}
	hook := exec.Command(bin, "hook", "claude")
	hook.Stdin = bytes.NewReader(payload)
	hook.Env = append(os.Environ(), "XDG_STATE_HOME="+stateHome, "XDG_CONFIG_HOME="+configHome)
	var stdout, stderr bytes.Buffer
	hook.Stdout, hook.Stderr = &stdout, &stderr
	if err := hook.Run(); err != nil {
		t.Fatalf("night request hook failed: %v (stderr=%s)", err, stderr.String())
	}
	if !strings.Contains(stdout.String(), `"operator_action":"night-off"`) || !strings.Contains(stdout.String(), `"permissionDecision":"deny"`) {
		t.Fatalf("night request output = %s, want completion verdict", stdout.String())
	}
}
