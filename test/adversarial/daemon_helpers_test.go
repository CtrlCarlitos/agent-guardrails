package adversarial

import (
	"testing"

	"github.com/CtrlCarlitos/agent-guardrails/internal/testenv"
)

// A test that runs the real binary in an isolated state root can make it spawn
// the approval daemon: SubmitOnDemand starts a detached `approvals daemon` when
// a verdict needs an operator approval and nothing is listening. On Windows the
// daemon's pipe is named from the state root, so each such test gets a daemon
// of its own, and nothing stopped it.
//
// The daemon does exit by itself after ten idle minutes, but TestMain removes
// the build directory when the run ends, and Windows cannot delete an image that
// is running. RemoveAll failed, its error was discarded, and every run left a
// ~20 MB directory in %TEMP% for good: 133 of them, 2.7 GB, on one machine
// (#367). The daemon also kept the test worktree's directory open for those ten
// minutes, so removing a finished worktree failed with "resource busy".
//
// adversarialChildEnv is where a test builds a child's environment, so it is
// also where the daemon is stopped: no test can start one and forget it.

// adversarialChildEnv is testenv.ChildProcessEnv for a child of the real
// binary, plus the cleanup that stops any approval daemon that child spawns.
func adversarialChildEnv(t *testing.T, roots testenv.Roots, overrides ...string) []string {
	t.Helper()
	t.Cleanup(func() { stopApprovalDaemon(t, roots.State) })
	return testenv.ChildProcessEnv(roots, overrides...)
}
