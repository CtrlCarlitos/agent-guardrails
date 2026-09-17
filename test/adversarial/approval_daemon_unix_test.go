//go:build !windows

package adversarial

import (
	"bytes"
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/CtrlCarlitos/agent-guardrails/internal/approval"
	"github.com/CtrlCarlitos/agent-guardrails/internal/operatorauth"
)

func enrollDaemonTestCredential(t *testing.T, stateHome string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(stateHome, "guardrail"), 0o700); err != nil {
		t.Fatal(err)
	}
	store := operatorauth.NewStore(filepath.Join(stateHome, "guardrail"))
	if err := store.Replace([]operatorauth.Credential{{ID: "AQI", PublicKey: "AQI", Algorithm: -7}}); err != nil {
		t.Fatal(err)
	}
}

func TestApprovalDaemonBinaryCompletesAdversarialNightRequest(t *testing.T) {
	bin := buildAdversarialBinary(t)
	stateHome := t.TempDir()
	configHome := t.TempDir()
	t.Setenv("XDG_STATE_HOME", stateHome)
	t.Setenv("XDG_CONFIG_HOME", configHome)
	enrollDaemonTestCredential(t, stateHome)
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

func TestSubmitOnDemandReexecsProductionDaemon(t *testing.T) {
	bin := buildAdversarialBinary(t)
	stateHome := t.TempDir()
	configHome := t.TempDir()
	t.Setenv("XDG_STATE_HOME", stateHome)
	t.Setenv("XDG_CONFIG_HOME", configHome)
	enrollDaemonTestCredential(t, stateHome)
	socket := approval.DefaultSocketPath()

	repo := t.TempDir()
	if err := os.Mkdir(filepath.Join(repo, ".git"), 0o700); err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(map[string]any{
		"session_id":      "reexec-production-daemon",
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
	hook.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	var stdout, stderr bytes.Buffer
	hook.Stdout, hook.Stderr = &stdout, &stderr
	if err := hook.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = syscall.Kill(-hook.Process.Pid, syscall.SIGTERM)
		deadline := time.Now().Add(time.Second)
		for {
			conn, err := net.DialTimeout("unix", socket, 10*time.Millisecond)
			if err != nil {
				return
			}
			_ = conn.Close()
			if time.Now().After(deadline) {
				t.Error("re-execed daemon remained reachable after cleanup")
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
	})

	deadline := time.Now().Add(time.Second)
	for {
		if _, err := os.Stat(socket); err == nil {
			break
		} else if !os.IsNotExist(err) {
			t.Fatalf("inspect re-execed daemon socket: %v", err)
		}
		if time.Now().After(deadline) {
			t.Fatal("SubmitOnDemand did not re-exec a daemon socket")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err := hook.Wait(); err != nil {
		t.Fatalf("night request hook failed: %v (stderr=%s)", err, stderr.String())
	}
	if !strings.Contains(stdout.String(), `"operator_action":"night-off"`) {
		t.Fatalf("night request output = %s, want completion verdict", stdout.String())
	}

	request, err := approval.Submit(socket, approval.Request{
		Plane: "claude", SessionID: "reexec-daemon-client", RepoRoot: repo,
		Scope: approval.Allow, Reason: "production daemon request", Action: "night-off",
	})
	if err != nil {
		t.Fatalf("re-execed daemon did not handle submission: %v", err)
	}
	if request.ID == "" || request.Status != "pending" || request.ExpiresAt.IsZero() {
		t.Fatalf("re-execed daemon reply = %+v, want pending request status", request)
	}
}

func TestAdversarialSocketApprovalCannotPersistEgressGrant(t *testing.T) {
	stateHome := t.TempDir()
	configHome := t.TempDir()
	t.Setenv("XDG_STATE_HOME", stateHome)
	t.Setenv("XDG_CONFIG_HOME", configHome)
	enrollDaemonTestCredential(t, stateHome)
	store := operatorauth.NewStore(filepath.Join(stateHome, "guardrail"))
	daemon, err := approval.StartDaemon(approval.DefaultSocketPath(), approval.New(), &store, func(string) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	defer daemon.Close()
	repo := t.TempDir()
	request, err := approval.Submit(approval.DefaultSocketPath(), approval.Request{Plane: "claude", SessionID: "socket-egress", RepoRoot: repo, Scope: approval.RepoScope, Reason: "canonical operator action", Action: "web-host-grant", Parameters: map[string]string{"scope": "repo", "hosts": "socket.example.test"}})
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.Dial("unix", approval.DefaultSocketPath())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := json.NewEncoder(conn).Encode(map[string]string{"operation": "approve", "id": request.ID}); err != nil {
		t.Fatal(err)
	}
	var reply map[string]any
	if err := json.NewDecoder(conn).Decode(&reply); err != nil {
		t.Fatal(err)
	}
	if reply["error"] == "" {
		t.Fatalf("raw socket approval accepted: %#v", reply)
	}
	if _, err := os.Stat(filepath.Join(repo, "guardrail.toml")); !os.IsNotExist(err) {
		t.Fatalf("socket approval persisted an overlay grant: %v", err)
	}
}
