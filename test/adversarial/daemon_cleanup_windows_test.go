//go:build windows

package adversarial

import (
	"os/exec"
	"testing"
	"time"

	"github.com/CtrlCarlitos/agent-guardrails/internal/testenv"
)

// A daemon started by a test must not outlive it. The subtest starts the real
// binary's daemon in an isolated state root through adversarialChildEnv; once
// the subtest ends, nothing may answer on that endpoint and the process must be
// gone, or it keeps its image (and the build directory) open (#367).
func TestWindowsChildDaemonIsStoppedWhenTheTestEnds(t *testing.T) {
	bin := buildAdversarialBinary(t)
	roots := testenv.Roots{Home: t.TempDir(), Config: t.TempDir(), State: t.TempDir()}

	var daemon *exec.Cmd
	t.Run("a test that spawns a daemon", func(t *testing.T) {
		daemon = exec.Command(bin, "approvals", "daemon")
		daemon.Env = adversarialChildEnv(t, roots)
		if err := daemon.Start(); err != nil {
			t.Fatal(err)
		}
		deadline := time.Now().Add(10 * time.Second)
		for pipeServer(roots.State) == 0 {
			if time.Now().After(deadline) {
				_ = daemon.Process.Kill()
				t.Fatal("the daemon never began serving its pipe")
			}
			time.Sleep(50 * time.Millisecond)
		}
	})

	// The subtest has ended and its cleanup has run.
	if pid := pipeServer(roots.State); pid != 0 {
		_ = daemon.Process.Kill()
		t.Fatalf("process %d still serves the pipe after the test that started it ended", pid)
	}
	exited := make(chan error, 1)
	go func() { exited <- daemon.Wait() }()
	select {
	case <-exited:
	case <-time.After(10 * time.Second):
		_ = daemon.Process.Kill()
		t.Fatal("the daemon process is still running after its test ended")
	}
}
