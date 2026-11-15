package approval_test

import (
	"context"
	"strings"
	"testing"
	"time"
)

// #519: TestBrowserLoopbackFailurePath's agent-browser session outlived any
// run that died before t.Cleanup (a -timeout panic, an interrupt, a killed
// suite). The orphaned daemon then read as a guardrail-owned session with a
// version-mismatch warning after every agent-browser upgrade. Every command
// the test runs must bound the daemon's idle life, and the session name must
// say it belongs to the e2e test, not to a guardrail runtime component.
func TestBrowserE2ESessionIsNamedForTheTestAndEndsItselfWhenOrphaned(t *testing.T) {
	if got, want := browserE2ESession("df0adfba698e0123456789abcdef"), "guardrail-e2e-df0adfba698e"; got != want {
		t.Fatalf("session = %q, want %q", got, want)
	}
	if browserE2EIdleTimeout <= agentBrowserStepTimeout {
		t.Fatalf("idle timeout %s must exceed the %s step bound, or a live run's daemon could exit mid-test",
			browserE2EIdleTimeout, agentBrowserStepTimeout)
	}
	if browserE2EIdleTimeout > 5*time.Minute {
		t.Fatalf("idle timeout %s leaves an orphaned daemon alive long enough to meet an agent-browser upgrade", browserE2EIdleTimeout)
	}
	cmd := agentBrowserCommand(context.Background(), "agent-browser", "guardrail-e2e-x", "open", "about:blank")
	want := "AGENT_BROWSER_IDLE_TIMEOUT_MS=120000"
	found := false
	for _, kv := range cmd.Env {
		if kv == want {
			found = true
		}
		if strings.HasPrefix(kv, "AGENT_BROWSER_IDLE_TIMEOUT_MS=") && kv != want {
			t.Fatalf("conflicting idle timeout in env: %s", kv)
		}
	}
	if !found {
		t.Fatalf("command env lacks %s", want)
	}
	if got := strings.Join(cmd.Args[1:], " "); got != "--session guardrail-e2e-x open about:blank" {
		t.Fatalf("args = %q", got)
	}
}
